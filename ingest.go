package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog/log"
	metrics "github.com/slok/go-http-metrics/metrics/prometheus"
	"github.com/slok/go-http-metrics/middleware"
)

// OTLP signals the write gateway can accept, by their OTLP/HTTP path segment.
const (
	signalMetrics = "metrics"
	signalLogs    = "logs"
	signalTraces  = "traces"
)

var ingestSignals = []string{signalMetrics, signalLogs, signalTraces}

const defaultIngestMaxBodyBytes = 5 << 20

// The write listener is the one most likely to face untrusted networks, so unlike the
// read listeners it does not run with net/http's unbounded zero-value timeouts.
const (
	ingestReadHeaderTimeout = 10 * time.Second
	ingestReadTimeout       = 30 * time.Second
	ingestWriteTimeout      = 30 * time.Second
	ingestIdleTimeout       = 120 * time.Second
)

// writerIDPattern keeps writer ids usable as a label value and a path-like tenant
// suffix: lowercase alphanumerics and inner hyphens, at most 63 characters.
var writerIDPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

var (
	errNoIngestRole        = errors.New("no ingest role")
	errAmbiguousIngestRole = errors.New("ambiguous ingest roles")
)

// signalURL returns the configured upstream URL for signal, or "" when it is not routed.
func (c IngestConfig) signalURL(signal string) string {
	switch signal {
	case signalMetrics:
		return c.Metrics.URL
	case signalLogs:
		return c.Logs.URL
	case signalTraces:
		return c.Traces.URL
	}
	return ""
}

// validateIngestConfig reports the first problem with the ingest section, or nil when
// it is disabled or valid.
func validateIngestConfig(c *Config) error {
	in := c.Ingest
	if !in.Enabled {
		return nil
	}

	if in.Port <= 0 || in.Port > 65535 {
		return fmt.Errorf("ingest.port %d is not a valid port", in.Port)
	}
	others := []struct {
		name string
		port int
	}{
		{"web.proxy_port", c.Web.ProxyPort},
		{"web.metrics_port", c.Web.MetricsPort},
		{"auth.client_cert.mtls_port", c.Auth.ClientCert.MTLSPort},
	}
	for _, o := range others {
		if o.port != 0 && o.port == in.Port {
			return fmt.Errorf("ingest.port %d collides with %s", in.Port, o.name)
		}
	}

	if in.ServerCert == "" || in.ServerKey == "" {
		return errors.New("ingest.server_cert and ingest.server_key are required")
	}
	if in.MaxBodyBytes <= 0 {
		return fmt.Errorf("ingest.max_body_bytes must be positive, got %d", in.MaxBodyBytes)
	}

	routed := 0
	for _, signal := range ingestSignals {
		raw := in.signalURL(signal)
		if raw == "" {
			continue
		}
		routed++
		u, err := url.Parse(raw)
		if err != nil {
			return fmt.Errorf("ingest.%s.url: %w", signal, err)
		}
		if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("ingest.%s.url %q must be an absolute http or https URL", signal, raw)
		}
	}
	if routed == 0 {
		return errors.New("ingest needs at least one of metrics.url, logs.url, traces.url")
	}

	if len(in.Writers) == 0 {
		return errors.New("ingest.writers is empty: no caller could push")
	}
	for group, id := range in.Writers {
		if strings.TrimSpace(group) == "" {
			return errors.New("ingest.writers has an empty group")
		}
		if !writerIDPattern.MatchString(id) {
			return fmt.Errorf("ingest.writers[%s] id %q must match %s", group, id, writerIDPattern)
		}
	}

	for _, attr := range in.StripAttributes {
		if err := validateAttributePattern(attr); err != nil {
			return fmt.Errorf("ingest.strip_attributes: %w", err)
		}
	}
	if in.TenantAttribute != "" {
		for _, attr := range in.DropMetricAttributes {
			if attr == in.TenantAttribute {
				return fmt.Errorf("ingest.tenant_attribute %q is also in drop_metric_attributes", attr)
			}
		}
	}
	return nil
}

// validateAttributePattern accepts an exact attribute key, or a prefix ending in ".*".
func validateAttributePattern(p string) error {
	if strings.TrimSpace(p) == "" {
		return errors.New("empty pattern")
	}
	if !strings.Contains(p, "*") {
		return nil
	}
	prefix, ok := strings.CutSuffix(p, ".*")
	if !ok || prefix == "" || strings.Contains(prefix, "*") {
		return fmt.Errorf("pattern %q: a wildcard is only allowed as a trailing \".*\"", p)
	}
	return nil
}

// ingestWriter resolves the writer id a caller pushes as from their group membership.
//
// Exactly one distinct id must match. A caller holding groups that map to two different
// ids is refused rather than guessed at, since the id decides where the data lands.
// Several groups mapping to the same id are fine.
func ingestWriter(token OAuthToken, cfg IngestConfig) (string, error) {
	writer := ""
	for group, id := range cfg.Writers {
		if group == "" || !ContainsIgnoreCase(token.Groups, group) {
			continue
		}
		if writer != "" && writer != id {
			return "", errAmbiguousIngestRole
		}
		writer = id
	}
	if writer == "" {
		return "", errNoIngestRole
	}
	return writer, nil
}

// WithIngest builds the write router, and returns the updated App. It is separate from
// the read router so that the write listener cannot serve a read route, and the read
// listeners cannot serve a push route.
func (a *App) WithIngest() *App {
	if !a.Cfg.Ingest.Enabled {
		return a
	}
	w := mux.NewRouter()
	w.Use(a.loggingMiddleware)
	w.SkipClean(true)

	// For an edge or load balancer health probe: no auth, no upstream call.
	w.HandleFunc("/healthz", func(rw http.ResponseWriter, _ *http.Request) {
		if a.healthy {
			rw.WriteHeader(http.StatusOK)
			_, _ = rw.Write([]byte("Ok"))
			return
		}
		rw.WriteHeader(http.StatusInternalServerError)
		_, _ = rw.Write([]byte("Not Ok"))
	}).Methods(http.MethodGet).Name("ingest /healthz")

	for _, signal := range ingestSignals {
		if a.Cfg.Ingest.signalURL(signal) == "" {
			continue
		}
		path := "/v1/" + signal
		log.Trace().Str("route", path).Msg("Ingest route")
		w.HandleFunc(path, ingestHandler(signal, a)).Methods(http.MethodPost).Name("ingest " + path)
	}

	a.w = w
	return a
}

// ingestHandler authenticates a push and resolves the writer it is made as.
//
// Identity comes from getToken, not getIdentity: the client-certificate and trusted
// header modes trust their source implicitly, which is not acceptable on a listener
// meant to be reachable by untrusted clients.
func ingestHandler(signal string, a *App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, err := getToken(r, a)
		if err != nil {
			logAndWriteError(w, http.StatusForbidden, err, "")
			return
		}
		writer, err := ingestWriter(token, a.Cfg.Ingest)
		if err != nil {
			log.Debug().Str("user", token.PreferredUsername).Err(err).Msg("Ingest refused")
			logAndWriteError(w, http.StatusForbidden, err, "")
			return
		}
		log.Debug().Str("writer", writer).Str("signal", signal).Msg("Ingest accepted")
		logAndWriteError(w, http.StatusNotImplemented, fmt.Errorf("%s ingest not implemented", signal), "")
	}
}

// buildIngestServer constructs the write listener: TLS with the ingest server
// certificate, no client certificate requested, and bounded timeouts.
func (a *App) buildIngestServer(addr string, handler http.Handler) (*http.Server, error) {
	in := a.Cfg.Ingest
	cert, err := tls.LoadX509KeyPair(in.ServerCert, in.ServerKey)
	if err != nil {
		return nil, fmt.Errorf("loading ingest server keypair: %w", err)
	}
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: ingestReadHeaderTimeout,
		ReadTimeout:       ingestReadTimeout,
		WriteTimeout:      ingestWriteTimeout,
		IdleTimeout:       ingestIdleTimeout,
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{cert},
			ClientAuth:   tls.NoClientCert,
		},
	}, nil
}

// ingestHTTPMetrics returns the HTTP metrics middleware for the write listener. Its
// series are prefixed so they register alongside the read listener's identically named
// ones instead of colliding, and so read and write traffic can be told apart.
func ingestHTTPMetrics(reg prometheus.Registerer) middleware.Middleware {
	return middleware.New(middleware.Config{
		Recorder: metrics.NewRecorder(metrics.Config{Prefix: "ingest", Registry: reg}),
		Service:  "lgtm_lbac_proxy_ingest",
	})
}

// serveIngest serves the write router on its own TLS listener.
func (a *App) serveIngest(addr string, handler http.Handler) {
	srv, err := a.buildIngestServer(addr, handler)
	if err != nil {
		log.Fatal().Err(err).Msg("Error while building ingest server")
	}
	log.Info().Str("addr", addr).Msg("Serving OTLP ingest")
	if err := srv.ListenAndServeTLS("", ""); err != nil {
		log.Fatal().Err(err).Msg("Error while serving ingest")
	}
}
