package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
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

const (
	defaultIngestMaxBodyBytes = 5 << 20
	defaultIngestWriterHeader = "X-Ingest-Writer"
)

// The write listener is the one most likely to face untrusted networks, so unlike the
// read listeners it does not run with net/http's unbounded zero-value timeouts.
const (
	ingestReadHeaderTimeout = 10 * time.Second
	ingestReadTimeout       = 30 * time.Second
	ingestWriteTimeout      = 30 * time.Second
	ingestIdleTimeout       = 120 * time.Second
)

// writerIDPattern keeps writer ids usable as a header value, a label value and a
// path-like tenant suffix: lowercase alphanumerics and inner hyphens, at most 63
// characters.
var writerIDPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// headerTokenPattern is an RFC 9110 field-name token.
var headerTokenPattern = regexp.MustCompile("^[!#$%&'*+\\-.^_`|~0-9A-Za-z]+$")

// reservedWriterHeaders may not carry the writer id: they carry credentials, framing or
// content metadata the gateway forwards or strips on its own terms.
var reservedWriterHeaders = []string{
	"Authorization", "Host", "Connection", "Transfer-Encoding",
	"Content-Type", "Content-Encoding", "Content-Length",
}

var (
	errNoIngestRole        = errors.New("no ingest role")
	errAmbiguousIngestRole = errors.New("ambiguous ingest roles")
)

// Rejection reasons, as the reason label of lgtm_lbac_proxy_ingest_rejected_total.
const (
	rejectUnauthenticated = "unauthenticated"
	rejectNoRole          = "no_role"
	rejectAmbiguousRole   = "ambiguous_role"
	rejectTooLarge        = "too_large"
	rejectUpstreamError   = "upstream_error"
)

var (
	ingestRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "lgtm_lbac_proxy_ingest_requests_total",
		Help: "Authorised OTLP pushes forwarded upstream, by writer, signal and response code.",
	}, []string{"writer", "signal", "code"})
	ingestRequestBytes = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "lgtm_lbac_proxy_ingest_request_bytes_total",
		Help: "Request body bytes read from authorised OTLP pushes, as sent (before any decompression).",
	}, []string{"writer", "signal"})
	ingestRejected = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "lgtm_lbac_proxy_ingest_rejected_total",
		Help: "OTLP pushes refused by the gateway, by signal and reason.",
	}, []string{"signal", "reason"})
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

// ingestOnly reports whether the process runs as a write gateway alone.
func (a *App) ingestOnly() bool {
	return a.Cfg.Ingest.Enabled && a.Cfg.Ingest.Only
}

// signalProxy returns the per-upstream proxy settings for signal.
func (c IngestConfig) signalProxy(signal string) *ProxyConfig {
	switch signal {
	case signalMetrics:
		return c.Metrics.Proxy
	case signalLogs:
		return c.Logs.Proxy
	case signalTraces:
		return c.Traces.Proxy
	}
	return nil
}

// writerHeader returns the configured writer header, or the default.
func (c IngestConfig) writerHeader() string {
	if c.WriterHeader == "" {
		return defaultIngestWriterHeader
	}
	return c.WriterHeader
}

// validateIngestConfig reports the first problem with the ingest section, or nil when
// it is disabled or valid.
func validateIngestConfig(c *Config) error {
	in := c.Ingest
	if in.Only && !in.Enabled {
		return errors.New("ingest.only requires ingest.enabled: the process would serve nothing")
	}
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
	if err := validateWriterHeader(in.writerHeader(), c.Auth.AuthHeader); err != nil {
		return fmt.Errorf("ingest.writer_header: %w", err)
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

	if len(in.Writers) == 0 && len(in.StaticKeys) == 0 {
		return errors.New("ingest.writers and ingest.static_keys are both empty: no caller could push")
	}
	if err := validateStaticKeys("ingest.static_keys", in.StaticKeys, func(id string) error {
		if !writerIDPattern.MatchString(id) {
			return fmt.Errorf("writer id %q must match %s", id, writerIDPattern)
		}
		return nil
	}); err != nil {
		return err
	}
	for group, id := range in.Writers {
		if strings.TrimSpace(group) == "" {
			return errors.New("ingest.writers has an empty group")
		}
		if !writerIDPattern.MatchString(id) {
			return fmt.Errorf("ingest.writers[%s] id %q must match %s", group, id, writerIDPattern)
		}
	}
	return nil
}

// validateWriterHeader accepts a header field name that does not collide with one the
// gateway manages, including the header callers authenticate with.
func validateWriterHeader(name, authHeader string) error {
	if !headerTokenPattern.MatchString(name) {
		return fmt.Errorf("%q is not a valid header name", name)
	}
	reserved := reservedWriterHeaders
	if authHeader != "" {
		reserved = append(append([]string{}, reserved...), authHeader)
	}
	for _, r := range reserved {
		if strings.EqualFold(name, r) {
			return fmt.Errorf("%q is reserved", name)
		}
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

// withIngestProxies creates one reverse proxy per routed signal. Called from
// WithProxies.
//
// The transport trusts the root pool WithTLSConfig built, rather than a.TlS, which the
// read upstreams are given but which is never populated.
func (a *App) withIngestProxies() {
	if !a.Cfg.Ingest.Enabled {
		return
	}
	a.ingestProxies = map[string]*httputil.ReverseProxy{}
	for _, signal := range ingestSignals {
		target := a.Cfg.Ingest.signalURL(signal)
		if target == "" {
			continue
		}
		proxyCfg := a.Cfg.GetProxyConfig(a.Cfg.Ingest.signalProxy(signal))
		proxy := a.createProxy(target, "", a.createTransport(proxyCfg, a.ingestTLSConfig()), "ingest-"+signal)
		proxy.ErrorHandler = ingestErrorHandler(signal)
		a.ingestProxies[signal] = proxy
		log.Info().Str("signal", signal).Str("url", target).Msg("Ingest proxy initialized")
	}
}

// ingestTLSConfig is the client TLS configuration for https ingest upstreams.
func (a *App) ingestTLSConfig() *tls.Config {
	if a.rootCAs == nil {
		return nil
	}
	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
		RootCAs:            a.rootCAs,
		InsecureSkipVerify: a.Cfg.Web.TLSVerifySkip,
	}
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

// ingestHandler authenticates a push, resolves the writer it is made as, and forwards
// it with the writer id in the writer header.
//
// Identity comes from getToken, not getIdentity: the client-certificate and trusted
// header modes trust their source implicitly, which is not acceptable on a listener
// meant to be reachable by untrusted clients.
//
// The body is streamed through unread and unmodified. The only assertion the gateway
// adds is the writer header, which it overwrites, so it is only as trustworthy as the
// guarantee that the upstream cannot be reached except through the gateway.
func ingestHandler(signal string, a *App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// A static write key maps straight to its writer. Anything else must be a JWT
		// whose groups resolve to exactly one writer.
		writer, viaKey := staticKeyLookup(a.Cfg.Ingest.StaticKeys, bearerValue(r, a))
		if !viaKey {
			token, err := getToken(r, a)
			if err != nil {
				ingestRejected.WithLabelValues(signal, rejectUnauthenticated).Inc()
				logAndWriteError(w, http.StatusForbidden, err, "")
				return
			}
			writer, err = ingestWriter(token, a.Cfg.Ingest)
			if err != nil {
				reason := rejectNoRole
				if errors.Is(err, errAmbiguousIngestRole) {
					reason = rejectAmbiguousRole
				}
				ingestRejected.WithLabelValues(signal, reason).Inc()
				log.Debug().Str("user", token.PreferredUsername).Err(err).Msg("Ingest refused")
				logAndWriteError(w, http.StatusForbidden, err, "")
				return
			}
		}

		in := a.Cfg.Ingest
		if r.ContentLength > in.MaxBodyBytes {
			ingestRejected.WithLabelValues(signal, rejectTooLarge).Inc()
			logAndWriteError(w, http.StatusRequestEntityTooLarge, fmt.Errorf("request body exceeds %d bytes", in.MaxBodyBytes), "")
			return
		}

		proxy := a.ingestProxies[signal]
		if proxy == nil {
			ingestRejected.WithLabelValues(signal, rejectUpstreamError).Inc()
			logAndWriteError(w, http.StatusBadGateway, fmt.Errorf("no upstream for %s", signal), "")
			return
		}

		body := &ingestBody{ReadCloser: http.MaxBytesReader(w, r.Body, in.MaxBodyBytes)}
		r = r.WithContext(context.WithValue(r.Context(), ingestBodyKey{}, body))
		r.Body = body

		header := in.writerHeader()
		r.Header.Del(header)
		r.Header.Set(header, writer)
		// The caller's credentials are for the gateway, not the upstream.
		r.Header.Del("Authorization")
		if a.Cfg.Auth.AuthHeader != "" {
			r.Header.Del(a.Cfg.Auth.AuthHeader)
		}
		if a.Cfg.Alert.TokenHeader != "" {
			r.Header.Del(a.Cfg.Alert.TokenHeader)
		}

		log.Debug().Str("writer", writer).Str("signal", signal).Bool("static_key", viaKey).Msg("Forwarding ingest")
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		proxy.ServeHTTP(rec, r)

		ingestRequests.WithLabelValues(writer, signal, strconv.Itoa(rec.status)).Inc()
		ingestRequestBytes.WithLabelValues(writer, signal).Add(float64(body.n))
	}
}

// ingestBodyKey carries the request's ingestBody to the proxy's error handler.
type ingestBodyKey struct{}

// ingestBody counts the bytes read from a push and records whether the size cap cut
// it off, so a failed forward can be told apart from an oversized one.
type ingestBody struct {
	io.ReadCloser
	n        int64
	tooLarge bool
}

func (b *ingestBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.n += int64(n)
	var maxErr *http.MaxBytesError
	if errors.As(err, &maxErr) {
		b.tooLarge = true
	}
	return n, err
}

// ingestErrorHandler answers a failed forward: 413 when the body overran the size cap
// mid-stream, 502 for anything else.
func ingestErrorHandler(signal string) func(http.ResponseWriter, *http.Request, error) {
	return func(w http.ResponseWriter, r *http.Request, err error) {
		if body, ok := r.Context().Value(ingestBodyKey{}).(*ingestBody); ok && body.tooLarge {
			ingestRejected.WithLabelValues(signal, rejectTooLarge).Inc()
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		ingestRejected.WithLabelValues(signal, rejectUpstreamError).Inc()
		log.Error().Err(err).Str("upstream", "ingest-"+signal).Msg("Proxy error")
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
	}
}

// statusRecorder captures the response status for metrics.
type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if !s.wroteHeader {
		s.status = code
		s.wroteHeader = true
	}
	s.ResponseWriter.WriteHeader(code)
}

// Unwrap lets http.ResponseController reach the underlying writer (flush, deadlines).
func (s *statusRecorder) Unwrap() http.ResponseWriter {
	return s.ResponseWriter
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
