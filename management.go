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

// Upstreams the management listener can write to, by the target label of its metrics.
const (
	targetMimirRules  = "mimir-rules"
	targetLokiRules   = "loki-rules"
	targetAlertConfig = "alertmanager-config"
)

var managementTargets = []string{targetMimirRules, targetLokiRules, targetAlertConfig}

// Rule groups and Alertmanager configurations are small documents; the cap only stops a
// caller streaming an unbounded body through the listener.
const defaultManagementMaxBodyBytes = 5 << 20

// Like the write gateway, the management listener does not run with net/http's
// unbounded zero-value timeouts.
const (
	managementReadHeaderTimeout = 10 * time.Second
	managementReadTimeout       = 30 * time.Second
	managementWriteTimeout      = 60 * time.Second
	managementIdleTimeout       = 120 * time.Second
)

var (
	errNoManagerRole        = errors.New("no management role")
	errAmbiguousManagerRole = errors.New("ambiguous management roles")
)

var (
	managementRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "lgtm_lbac_proxy_management_requests_total",
		Help: "Authorised rule and Alertmanager configuration requests forwarded upstream, by manager, target, method and response code.",
	}, []string{"manager", "target", "method", "code"})
	managementRejected = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "lgtm_lbac_proxy_management_rejected_total",
		Help: "Rule and Alertmanager configuration requests refused by the management listener, by target and reason.",
	}, []string{"target", "reason"})
)

// managementRoute is one configuration API endpoint and the methods it accepts.
type managementRoute struct {
	Url     string
	Methods []string
}

// managementRoutes returns the configuration API routes for target. Paths are those the
// upstream serves, so tools that speak the API directly (mimirtool, lokitool, cortextool)
// work unchanged when pointed at the listener.
func managementRoutes(target string) []managementRoute {
	ruler := func(base string) []managementRoute {
		return []managementRoute{
			{Url: base, Methods: []string{http.MethodGet}},
			{Url: base + "/{namespace}", Methods: []string{http.MethodGet, http.MethodPost, http.MethodDelete}},
			{Url: base + "/{namespace}/{group}", Methods: []string{http.MethodGet, http.MethodDelete}},
		}
	}
	switch target {
	case targetMimirRules:
		// Mimir/Cortex ruler configuration API.
		return ruler("/prometheus/config/v1/rules")
	case targetLokiRules:
		// Loki ruler configuration API.
		return ruler("/loki/api/v1/rules")
	case targetAlertConfig:
		// Mimir/Cortex Alertmanager configuration API. On the read listener this path is
		// the ruler's alert list; here nothing else claims it.
		return []managementRoute{
			{Url: "/api/v1/alerts", Methods: []string{http.MethodGet, http.MethodPost, http.MethodDelete}},
		}
	}
	return nil
}

// upstream returns the configured upstream for target.
func (c ManagementConfig) upstream(target string) ManagementUpstream {
	switch target {
	case targetMimirRules:
		return c.MimirRuler
	case targetLokiRules:
		return c.LokiRuler
	case targetAlertConfig:
		return c.Alertmanager
	}
	return ManagementUpstream{}
}

// upstreamField is the config key of target's upstream, for error messages.
func upstreamField(target string) string {
	switch target {
	case targetMimirRules:
		return "management.mimir_ruler"
	case targetLokiRules:
		return "management.loki_ruler"
	case targetAlertConfig:
		return "management.alertmanager"
	}
	return "management." + target
}

// managementOnly reports whether the process runs as a management listener with no
// read path.
func (a *App) managementOnly() bool {
	return a.Cfg().Management.Enabled && a.Cfg().Management.Only
}

// readPathDisabled reports whether an "only" mode has switched the read path off: no
// label store, read upstreams, read routes or read listeners.
func (a *App) readPathDisabled() bool {
	return a.ingestOnly() || a.managementOnly()
}

// validateManagementConfig reports the first problem with the management section, or
// nil when it is disabled or valid.
func validateManagementConfig(c *Config) error {
	m := c.Management
	if m.Only && !m.Enabled {
		return errors.New("management.only requires management.enabled: the process would serve nothing")
	}
	if !m.Enabled {
		return nil
	}

	if m.Port <= 0 || m.Port > 65535 {
		return fmt.Errorf("management.port %d is not a valid port", m.Port)
	}
	others := []struct {
		name string
		port int
	}{
		{"web.proxy_port", c.Web.ProxyPort},
		{"web.metrics_port", c.Web.MetricsPort},
		{"auth.client_cert.mtls_port", c.Auth.ClientCert.MTLSPort},
	}
	if c.Ingest.Enabled {
		others = append(others, struct {
			name string
			port int
		}{"ingest.port", c.Ingest.Port})
	}
	for _, o := range others {
		if o.port != 0 && o.port == m.Port {
			return fmt.Errorf("management.port %d collides with %s", m.Port, o.name)
		}
	}

	if m.ServerCert == "" || m.ServerKey == "" {
		return errors.New("management.server_cert and management.server_key are required")
	}
	if m.MaxBodyBytes <= 0 {
		return fmt.Errorf("management.max_body_bytes must be positive, got %d", m.MaxBodyBytes)
	}

	routed := 0
	for _, target := range managementTargets {
		up := m.upstream(target)
		if up.URL == "" {
			continue
		}
		routed++
		field := upstreamField(target)
		u, err := url.Parse(up.URL)
		if err != nil {
			return fmt.Errorf("%s.url: %w", field, err)
		}
		if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("%s.url %q must be an absolute http or https URL", field, up.URL)
		}
		for name := range up.Headers {
			if err := validateWriterHeader(name, c.Auth.AuthHeader); err != nil {
				return fmt.Errorf("%s.headers: %w", field, err)
			}
		}
	}
	if routed == 0 {
		return errors.New("management needs at least one of mimir_ruler.url, loki_ruler.url, alertmanager.url")
	}

	if len(m.Managers) == 0 && len(m.StaticKeys) == 0 {
		return errors.New("management.managers and management.static_keys are both empty: no caller could manage anything")
	}
	if err := validateStaticKeys("management.static_keys", m.StaticKeys, func(id string) error {
		if !writerIDPattern.MatchString(id) {
			return fmt.Errorf("manager id %q must match %s", id, writerIDPattern)
		}
		return nil
	}); err != nil {
		return err
	}
	for group, id := range m.Managers {
		if strings.TrimSpace(group) == "" {
			return errors.New("management.managers has an empty group")
		}
		if !writerIDPattern.MatchString(id) {
			return fmt.Errorf("management.managers[%s] id %q must match %s", group, id, writerIDPattern)
		}
	}
	return nil
}

// managerID resolves the manager id a caller acts as from their group membership.
//
// Exactly one distinct id must match, as for ingest writers: the id is what the audit
// log and metrics attribute every change to, so two candidates are refused rather than
// guessed at.
func managerID(token OAuthToken, cfg ManagementConfig) (string, error) {
	manager := ""
	for group, id := range cfg.Managers {
		if group == "" || !ContainsIgnoreCase(token.Groups, group) {
			continue
		}
		if manager != "" && manager != id {
			return "", errAmbiguousManagerRole
		}
		manager = id
	}
	if manager == "" {
		return "", errNoManagerRole
	}
	return manager, nil
}

// withManagementProxies creates one reverse proxy per routed target. Called from
// WithProxies.
func (a *App) withManagementProxies() {
	if !a.Cfg().Management.Enabled {
		return
	}
	a.managementProxies = map[string]*httputil.ReverseProxy{}
	for _, target := range managementTargets {
		up := a.Cfg().Management.upstream(target)
		if up.URL == "" {
			continue
		}
		proxyCfg := a.Cfg().GetProxyConfig(up.Proxy)
		proxy := a.createProxy(up.URL, "", a.createTransport(proxyCfg, a.ingestTLSConfig()), "management-"+target)
		proxy.ErrorHandler = managementErrorHandler(target)
		a.managementProxies[target] = proxy
		log.Info().Str("target", target).Str("url", up.URL).Msg("Management proxy initialized")
	}
}

// WithManagement builds the management router, and returns the updated App. It is
// separate from the read and write routers, so the management listener serves only the
// configuration APIs and the other listeners never serve them.
func (a *App) WithManagement() *App {
	if !a.Cfg().Management.Enabled {
		return a
	}
	m := mux.NewRouter()
	m.Use(a.loggingMiddleware)
	m.SkipClean(true)
	// Match on the escaped path, so a namespace or group name containing an encoded
	// slash stays one path segment.
	m.UseEncodedPath()

	// For a load balancer or ingress health probe: no auth, no upstream call.
	m.HandleFunc("/healthz", a.healthHandler).Methods(http.MethodGet).Name("management /healthz")

	for _, target := range managementTargets {
		if a.Cfg().Management.upstream(target).URL == "" {
			continue
		}
		for _, route := range managementRoutes(target) {
			log.Trace().Str("route", route.Url).Str("target", target).Msg("Management route")
			m.HandleFunc(route.Url, managementHandler(target, a)).
				Methods(route.Methods...).
				Name(target + " " + route.Url)
		}
	}

	a.m = m
	return a
}

// managementHandler authenticates a request, resolves the manager it is made as, and
// forwards it to the target's upstream.
//
// Identity comes from a management static key or getToken, never getIdentity: the
// client-certificate and trusted-header modes trust their source implicitly, and read
// static keys (auth.static_keys) grant nothing here. The admin group does not imply
// management either; every manager is named explicitly.
//
// Changes are logged at info with the manager, method and path, so the log is an audit
// trail of who changed which rules.
func managementHandler(target string, a *App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		mc := a.Cfg().Management

		manager, viaKey := staticKeyLookup(mc.StaticKeys, bearerValue(r, a))
		user := ""
		if !viaKey {
			token, err := getToken(r, a)
			if err != nil {
				managementRejected.WithLabelValues(target, rejectUnauthenticated).Inc()
				logAndWriteError(w, http.StatusForbidden, err, "")
				return
			}
			user = token.PreferredUsername
			manager, err = managerID(token, mc)
			if err != nil {
				reason := rejectNoRole
				if errors.Is(err, errAmbiguousManagerRole) {
					reason = rejectAmbiguousRole
				}
				managementRejected.WithLabelValues(target, reason).Inc()
				log.Info().Str("user", user).Str("target", target).Str("method", r.Method).
					Str("path", r.URL.Path).Err(err).Msg("Management refused")
				logAndWriteError(w, http.StatusForbidden, err, "")
				return
			}
		}

		if r.ContentLength > mc.MaxBodyBytes {
			managementRejected.WithLabelValues(target, rejectTooLarge).Inc()
			logAndWriteError(w, http.StatusRequestEntityTooLarge, fmt.Errorf("request body exceeds %d bytes", mc.MaxBodyBytes), "")
			return
		}

		proxy := a.managementProxies[target]
		if proxy == nil {
			managementRejected.WithLabelValues(target, rejectUpstreamError).Inc()
			logAndWriteError(w, http.StatusBadGateway, fmt.Errorf("no upstream for %s", target), "")
			return
		}

		up := mc.upstream(target)
		ctx := r.Context()
		if timeout := a.Cfg().GetProxyConfig(up.Proxy).RequestTimeout; timeout > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, timeout)
			defer cancel()
		}
		body := &cappedBody{ReadCloser: http.MaxBytesReader(w, r.Body, mc.MaxBodyBytes)}
		ctx = context.WithValue(ctx, cappedBodyKey{}, body)
		r = r.WithContext(ctx)
		r.Body = body

		// The caller's credentials are for the listener, not the upstream.
		r.Header.Del("Authorization")
		if a.Cfg().Auth.AuthHeader != "" {
			r.Header.Del(a.Cfg().Auth.AuthHeader)
		}
		if a.Cfg().Alert.TokenHeader != "" {
			r.Header.Del(a.Cfg().Alert.TokenHeader)
		}
		// Configured headers overwrite the caller's, so a tenant header set here pins
		// the tenant whatever the client sends.
		for k, v := range up.Headers {
			r.Header.Set(k, v)
		}

		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		proxy.ServeHTTP(rec, r)

		managementRequests.WithLabelValues(manager, target, r.Method, strconv.Itoa(rec.status)).Inc()
		event := log.Debug()
		if r.Method != http.MethodGet {
			event = log.Info()
		}
		event.Str("manager", manager).Str("user", user).Bool("static_key", viaKey).
			Str("target", target).Str("method", r.Method).Str("path", r.URL.Path).
			Int("status", rec.status).Str("client", r.RemoteAddr).Msg("Management request")
	}
}

// cappedBodyKey carries the request's cappedBody to the proxy's error handler.
type cappedBodyKey struct{}

// cappedBody records whether the size cap cut a body off, so a failed forward can be
// told apart from an oversized one.
type cappedBody struct {
	io.ReadCloser
	tooLarge bool
}

func (b *cappedBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	var maxErr *http.MaxBytesError
	if errors.As(err, &maxErr) {
		b.tooLarge = true
	}
	return n, err
}

// managementErrorHandler answers a failed forward: 413 when the body overran the size
// cap mid-stream, 502 for anything else.
func managementErrorHandler(target string) func(http.ResponseWriter, *http.Request, error) {
	return func(w http.ResponseWriter, r *http.Request, err error) {
		if body, ok := r.Context().Value(cappedBodyKey{}).(*cappedBody); ok && body.tooLarge {
			managementRejected.WithLabelValues(target, rejectTooLarge).Inc()
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		managementRejected.WithLabelValues(target, rejectUpstreamError).Inc()
		log.Error().Err(err).Str("upstream", "management-"+target).Msg("Proxy error")
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
	}
}

// buildManagementServer constructs the management listener: TLS with its own server
// certificate, no client certificate requested, and bounded timeouts.
func (a *App) buildManagementServer(addr string, handler http.Handler) (*http.Server, error) {
	mc := a.Cfg().Management
	cert, err := tls.LoadX509KeyPair(mc.ServerCert, mc.ServerKey)
	if err != nil {
		return nil, fmt.Errorf("loading management server keypair: %w", err)
	}
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: managementReadHeaderTimeout,
		ReadTimeout:       managementReadTimeout,
		WriteTimeout:      managementWriteTimeout,
		IdleTimeout:       managementIdleTimeout,
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{cert},
			ClientAuth:   tls.NoClientCert,
		},
	}, nil
}

// managementHTTPMetrics returns the HTTP metrics middleware for the management
// listener, prefixed so its series register alongside the other listeners' ones.
func managementHTTPMetrics(reg prometheus.Registerer) middleware.Middleware {
	return middleware.New(middleware.Config{
		Recorder: metrics.NewRecorder(metrics.Config{Prefix: "management", Registry: reg}),
		Service:  "lgtm_lbac_proxy_management",
	})
}

// serveManagement serves the management router on its own TLS listener.
func (a *App) serveManagement(addr string, handler http.Handler) {
	srv, err := a.buildManagementServer(addr, handler)
	if err != nil {
		log.Fatal().Err(err).Msg("Error while building management server")
	}
	log.Info().Str("addr", addr).Msg("Serving rule and Alertmanager configuration management")
	if err := srv.ListenAndServeTLS("", ""); err != nil {
		log.Fatal().Err(err).Msg("Error while serving management")
	}
}
