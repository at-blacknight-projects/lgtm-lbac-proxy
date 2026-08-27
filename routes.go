package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/http/pprof"
	"net/url"

	"github.com/rs/zerolog/log"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Route struct {
	Url       string
	MatchWord string
}

// WithHealthz sets up and adds health check endpoints (/healthz and /debug/pprof/)
// and metrics endpoint (/metrics) to a new router
func (a *App) WithHealthz() *App {
	i := mux.NewRouter()
	a.healthy = true
	i.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if a.healthy {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Ok"))
		} else {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("Not Ok"))
		}
	})
	i.HandleFunc("/debug/pprof/", pprof.Index)
	i.Handle("/metrics", promhttp.Handler())
	a.i = i
	return a
}

// WithRoutes initializes a new router, sets up logging middleware, and assigns
// the router to the App's router field, returning the updated App.
func (a *App) WithRoutes() *App {
	e := mux.NewRouter()
	e.Use(a.loggingMiddleware)
	e.SkipClean(true)
	a.e = e
	a.WithLoki()
	a.WithThanos()
	a.WithTempo()
	a.WithRuler()
	a.WithAlertmanager()
	return a
}

// WithLoki configures and adds a set of Loki API routes to the App's router,
// logging warnings if the Loki URL is not set, and returns the updated App.
//
// Routes are based on Loki HTTP API Query Endpoints:
// https://grafana.com/docs/loki/latest/reference/loki-http-api/#query-endpoints
func (a *App) WithLoki() *App {
	if a.Cfg.Loki.URL == "" {
		log.Warn().Msg("Loki URL not set, skipping Loki routes")
		return a
	}
	routes := []Route{
		// Query Endpoints - https://grafana.com/docs/loki/latest/reference/loki-http-api/#instant-queries
		{Url: "/api/v1/query", MatchWord: "query"},
		// Range Queries - https://grafana.com/docs/loki/latest/reference/loki-http-api/#range-queries
		{Url: "/api/v1/query_range", MatchWord: "query"},
		// Labels - https://grafana.com/docs/loki/latest/reference/loki-http-api/#query-labels
		{Url: "/api/v1/labels", MatchWord: "query"},
		// Label Values - https://grafana.com/docs/loki/latest/reference/loki-http-api/#query-label-values
		{Url: "/api/v1/label/{label}/values", MatchWord: "query"},
		// Series - https://grafana.com/docs/loki/latest/reference/loki-http-api/#series
		{Url: "/api/v1/series", MatchWord: "match[]"},
		// Index Stats - https://grafana.com/docs/loki/latest/reference/loki-http-api/#statistics
		{Url: "/api/v1/index/stats", MatchWord: "query"},
		// Index Volume - https://grafana.com/docs/loki/latest/reference/loki-http-api/#volume
		{Url: "/api/v1/index/volume", MatchWord: "query"},
		// Index Volume Range - https://grafana.com/docs/loki/latest/reference/loki-http-api/#volume-range
		{Url: "/api/v1/index/volume_range", MatchWord: "query"},
		// Patterns - https://grafana.com/docs/loki/latest/reference/loki-http-api/#detected-patterns
		{Url: "/api/v1/patterns", MatchWord: "query"},
		// Tail - https://grafana.com/docs/loki/latest/reference/loki-http-api/#stream-logs
		{Url: "/api/v1/tail", MatchWord: "query"},
		// Additional Loki endpoints (not query endpoints)
		// Format Query - https://grafana.com/docs/loki/latest/reference/loki-http-api/#format-a-logql-query
		{Url: "/api/v1/format_query", MatchWord: "query"},
		// Build Info - https://grafana.com/docs/loki/latest/reference/loki-http-api/#show-build-information
		{Url: "/api/v1/status/buildinfo", MatchWord: "query"},
		// Query Exemplars - Prometheus endpoint (https://prometheus.io/docs/prometheus/latest/querying/api/#querying-exemplars)
		// Note: This is a Prometheus/Thanos endpoint, not a Loki endpoint, but included for compatibility
		{Url: "/api/v1/query_exemplars", MatchWord: "query"},
	}
	lokiRouter := a.e.PathPrefix("/loki").Subrouter()
	proxyCfg := a.Cfg.GetProxyConfig(a.Cfg.Loki.Proxy)
	for _, route := range routes {
		log.Trace().Any("route", route).Msg("Loki route")
		lokiRouter.HandleFunc(route.Url, handlerWithProxy(route.MatchWord,
			LogQLEnforcer(struct{}{}),
			a.lokiProxy,
			proxyCfg,
			a.Cfg.Loki.UseMutualTLS,
			a.Cfg.Loki.Headers,
			a)).Name(route.Url)
	}
	return a
}

// WithTempo configures and adds a set of Tempo API routes to the App's router,
// logging warnings if the Tempo URL is not set, and returns the updated App.
//
// Routes are based on Tempo HTTP API:
// https://grafana.com/docs/tempo/latest/api_docs/
//
// Note: Tempo routes use empty prefix to match official Tempo API paths (/api/search, /api/v2/*, etc.)
// There are no conflicts with Thanos routes because:
// - Thanos uses /api/v1/* exclusively
// - Tempo uses /api/search, /api/v2/*, /api/metrics/*, /api/echo, /api/traces/*
func (a *App) WithTempo() *App {
	if a.Cfg.Tempo.URL == "" {
		log.Warn().Msg("Tempo URL not set, skipping Tempo routes")
		return a
	}
	routes := []Route{
		// Query Echo - https://grafana.com/docs/tempo/latest/api_docs/#query-echo-endpoint
		// Note: Health check endpoint, no query parameters
		{Url: "/api/echo", MatchWord: ""},
		// Search Endpoints - https://grafana.com/docs/tempo/latest/api_docs/#search
		{Url: "/api/search", MatchWord: "q"},
		{Url: "/api/v2/search", MatchWord: "q"},
		// Tag Discovery - https://grafana.com/docs/tempo/latest/api_docs/#search-tags
		{Url: "/api/search/tags", MatchWord: "scope"},
		{Url: "/api/v2/search/tags", MatchWord: "scope"},
		// Tag Values - https://grafana.com/docs/tempo/latest/api_docs/#search-tag-values
		{Url: "/api/search/tag/{tag}/values", MatchWord: "q"},
		{Url: "/api/v2/search/tag/{tag}/values", MatchWord: "q"},
		// Metrics (Experimental) - https://grafana.com/docs/tempo/latest/api_docs/#metrics
		{Url: "/api/metrics/query_range", MatchWord: "q"},
		{Url: "/api/metrics/query", MatchWord: "q"},
		// Trace Retrieval - https://grafana.com/docs/tempo/latest/api_docs/#query
		// Note: These endpoints don't use query parameters, so enforcement is skipped
		{Url: "/api/traces/{traceID}", MatchWord: ""},
		{Url: "/api/v2/traces/{traceID}", MatchWord: ""},
	}
	tempoRouter := a.e.PathPrefix("").Subrouter()
	proxyCfg := a.Cfg.GetProxyConfig(a.Cfg.Tempo.Proxy)
	for _, route := range routes {
		log.Trace().Any("route", route).Msg("Tempo route")
		tempoRouter.HandleFunc(route.Url, handlerWithProxy(route.MatchWord,
			TraceQLEnforcer(struct{}{}),
			a.tempoProxy,
			proxyCfg,
			a.Cfg.Tempo.UseMutualTLS,
			a.Cfg.Tempo.Headers,
			a)).Name(route.Url)
	}
	return a
}

// WithThanos configures and adds a set of Thanos API routes to the App's router,
// logging warnings if the Thanos URL is not set, and returns the updated App.
//
// Routes are based on Prometheus HTTP API:
// https://prometheus.io/docs/prometheus/latest/querying/api/
func (a *App) WithThanos() *App {
	if a.Cfg.Thanos.URL == "" {
		log.Warn().Msg("Thanos URL not set, skipping Thanos routes")
		return a
	}
	routes := []Route{
		// Query Endpoints - https://prometheus.io/docs/prometheus/latest/querying/api/#instant-queries
		{Url: "/api/v1/query", MatchWord: "query"},
		// Range Queries - https://prometheus.io/docs/prometheus/latest/querying/api/#range-queries
		{Url: "/api/v1/query_range", MatchWord: "query"},
		// Format Query - https://prometheus.io/docs/prometheus/latest/querying/api/#formatting-query-expressions
		{Url: "/api/v1/format_query", MatchWord: "query"},
		// Metadata Endpoints
		// Series - https://prometheus.io/docs/prometheus/latest/querying/api/#finding-series-by-label-matchers
		{Url: "/api/v1/series", MatchWord: "match[]"},
		// Labels - https://prometheus.io/docs/prometheus/latest/querying/api/#getting-label-names
		{Url: "/api/v1/labels", MatchWord: "match[]"},
		// Label Values - https://prometheus.io/docs/prometheus/latest/querying/api/#querying-label-values
		{Url: "/api/v1/label/{label}/values", MatchWord: "match[]"},
		// Query Exemplars - https://prometheus.io/docs/prometheus/latest/querying/api/#querying-exemplars
		{Url: "/api/v1/query_exemplars", MatchWord: "query"},
		// Metadata - https://prometheus.io/docs/prometheus/latest/querying/api/#querying-metric-metadata
		{Url: "/api/v1/metadata", MatchWord: "query"},
		// Status Endpoints
		// Build Info - https://prometheus.io/docs/prometheus/latest/querying/api/#build-information
		{Url: "/api/v1/status/buildinfo", MatchWord: "query"},
		// Non-Prometheus endpoints (Thanos or compatibility)
		// Note: These endpoints are not part of standard Prometheus API
		{Url: "/api/v1/tail", MatchWord: "query"},
		{Url: "/api/v1/index/stats", MatchWord: "query"},
	}
	thanosRouter := a.e.PathPrefix("").Subrouter()
	proxyCfg := a.Cfg.GetProxyConfig(a.Cfg.Thanos.Proxy)
	for _, route := range routes {
		log.Trace().Any("route", route).Msg("Thanos route")
		thanosRouter.HandleFunc(route.Url,
			handlerWithProxy(route.MatchWord,
				PromQLEnforcer(struct{}{}),
				a.thanosProxy,
				proxyCfg,
				a.Cfg.Thanos.UseMutualTLS,
				a.Cfg.Thanos.Headers,
				a)).Name(route.Url)

	}
	return a
}

// Empty result sets returned to callers without alerting access, in place of an error.
// Grafana's alert list loads the ruler endpoints unprompted for every signed-in user, so
// answering 403 there would paint a failure on a page the caller never asked for.
const (
	emptyRuleGroups = `{"status":"success","data":{"groups":[]}}`
	emptyAlerts     = `{"status":"success","data":{"alerts":[]}}`
)

// AlertRoute is a ruler or Alertmanager endpoint.
//
// Methods are the HTTP methods the route accepts; WriteMethods is the subset requiring
// AlertAccessWrite. Empty, when set, is the JSON body returned to a caller with no
// alerting access instead of an error — a route without it refuses them outright.
type AlertRoute struct {
	Url          string
	Methods      []string
	WriteMethods []string
	Empty        string
}

// isWrite reports whether method on this route requires AlertAccessWrite.
func (r AlertRoute) isWrite(method string) bool {
	for _, m := range r.WriteMethods {
		if m == method {
			return true
		}
	}
	return false
}

// alertDecision is what alertHandler does with a request once the caller's access is known.
type alertDecision int

const (
	// alertForward proxies the request to the upstream.
	alertForward alertDecision = iota
	// alertEmpty answers 200 with the route's empty result set.
	alertEmpty
	// alertDeny answers 403: the caller has no alerting access at all.
	alertDeny
	// alertDenyWrite answers 403: the caller may read but not write.
	alertDenyWrite
)

// decideAlertRequest resolves a request to an outcome from the caller's access and the
// request method.
//
// A caller with no access reads the route's empty result set where one is defined, so a
// UI that loads these endpoints unprompted renders clean rather than showing a failure
// the caller never asked for. Writes, and routes with no meaningful empty form, are
// refused outright.
func decideAlertRequest(route AlertRoute, method string, access AlertAccess) alertDecision {
	switch {
	case access == AlertAccessWrite:
		return alertForward
	case route.isWrite(method):
		if access == AlertAccessRead {
			return alertDenyWrite
		}
		return alertDeny
	case access == AlertAccessRead:
		return alertForward
	case route.Empty != "":
		return alertEmpty
	default:
		return alertDeny
	}
}

// WithRuler adds the read-only ruler endpoints that Grafana's alerting UI queries to list
// data source managed rules and their firing instances, and returns the updated App.
//
// These endpoints carry no query parameter, so there is nothing for the PromQL/LogQL
// enforcers to rewrite and no way to scope a response per tenant; access is by group
// instead (see AlertingConfig). The ruler *configuration* API is deliberately absent, so
// rules stay read-only in Grafana and whatever manages them as code remains authoritative.
//
// Prometheus HTTP API: https://prometheus.io/docs/prometheus/latest/querying/api/#rules
func (a *App) WithRuler() *App {
	if !a.Cfg.Alerting.Enabled {
		log.Info().Msg("Alerting disabled, skipping ruler routes")
		return a
	}

	if a.Cfg.Thanos.URL != "" {
		// Mimir serves the Prometheus API under a base path; carry that on thanos.url
		// so these sit at the root alongside the query routes, as Grafana expects.
		routes := []AlertRoute{
			{Url: "/api/v1/rules", Methods: []string{http.MethodGet}, Empty: emptyRuleGroups},
			{Url: "/api/v1/alerts", Methods: []string{http.MethodGet}, Empty: emptyAlerts},
		}
		a.registerAlertRoutes(a.e.PathPrefix("").Subrouter(), routes, a.thanosProxy,
			a.Cfg.GetProxyConfig(a.Cfg.Thanos.Proxy), a.Cfg.Thanos.UseMutualTLS,
			a.Cfg.Thanos.Headers, "thanos-ruler")
	}

	if a.Cfg.Loki.URL != "" {
		// Loki's ruler serves the Prometheus-compatible API under /prometheus.
		routes := []AlertRoute{
			{Url: "/prometheus/api/v1/rules", Methods: []string{http.MethodGet}, Empty: emptyRuleGroups},
			{Url: "/prometheus/api/v1/alerts", Methods: []string{http.MethodGet}, Empty: emptyAlerts},
		}
		a.registerAlertRoutes(a.e.PathPrefix("").Subrouter(), routes, a.lokiProxy,
			a.Cfg.GetProxyConfig(a.Cfg.Loki.Proxy), a.Cfg.Loki.UseMutualTLS,
			a.Cfg.Loki.Headers, "loki-ruler")
	}

	return a
}

// WithAlertmanager adds the Alertmanager API routes to the App's router, logging a
// warning if the Alertmanager URL is not set, and returns the updated App.
//
// Silences are global to the Alertmanager and carry no tenant identity, so creating and
// expiring them requires AlertAccessWrite rather than being label-scoped.
//
// The Cortex/Mimir Alertmanager *configuration* API is deliberately absent, for the same
// reason as the ruler's: contact points and the routing tree are managed as code. It
// would also be unroutable here — clients ask for it at /api/v1/alerts on the root
// rather than under the Alertmanager base path, where it collides with the ruler's
// endpoint of the same name.
//
// Alertmanager HTTP API: https://prometheus.io/docs/alerting/latest/https/#api
func (a *App) WithAlertmanager() *App {
	if !a.Cfg.Alerting.Enabled {
		return a
	}
	if a.Cfg.Alertmanager.URL == "" {
		log.Warn().Msg("Alertmanager URL not set, skipping Alertmanager routes")
		return a
	}

	routes := []AlertRoute{
		{Url: "/api/v2/status", Methods: []string{http.MethodGet}},
		{Url: "/api/v2/receivers", Methods: []string{http.MethodGet}},
		{Url: "/api/v2/alerts", Methods: []string{http.MethodGet}},
		{Url: "/api/v2/alerts/groups", Methods: []string{http.MethodGet}},
		{Url: "/api/v2/silences", Methods: []string{http.MethodGet, http.MethodPost}, WriteMethods: []string{http.MethodPost}},
		{Url: "/api/v2/silence/{id}", Methods: []string{http.MethodGet, http.MethodDelete}, WriteMethods: []string{http.MethodDelete}},
	}

	router := a.e.PathPrefix(a.Cfg.Alertmanager.PathPrefix).Subrouter()
	a.registerAlertRoutes(router, routes, a.alertmanagerProxy,
		a.Cfg.GetProxyConfig(a.Cfg.Alertmanager.Proxy), a.Cfg.Alertmanager.UseMutualTLS,
		a.Cfg.Alertmanager.Headers, "alertmanager")

	return a
}

// registerAlertRoutes binds each route to the group-gated alerting handler on router.
func (a *App) registerAlertRoutes(router *mux.Router, routes []AlertRoute, proxy *httputil.ReverseProxy, proxyCfg ProxyConfig, tls bool, headers map[string]string, upstream string) {
	for _, route := range routes {
		log.Trace().Any("route", route).Str("upstream", upstream).Msg("Alerting route")
		router.HandleFunc(route.Url, alertHandler(route, proxy, proxyCfg, tls, headers, a)).
			Methods(route.Methods...).
			Name(upstream + " " + route.Url)
	}
}

// alertHandler authenticates the caller, resolves their alerting access from group
// membership, and forwards to the upstream. Unlike handlerWithProxy there is no query
// enforcement step — see AlertingConfig for why.
func alertHandler(route AlertRoute, proxy *httputil.ReverseProxy, proxyCfg ProxyConfig, tls bool, headers map[string]string, a *App) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), proxyCfg.RequestTimeout)
		defer cancel()
		r = r.WithContext(ctx)

		oauthToken, err := getIdentity(r, a)
		if err != nil {
			logAndWriteError(w, http.StatusForbidden, err, "")
			return
		}

		switch decideAlertRequest(route, r.Method, alertingAccess(oauthToken, a)) {
		case alertEmpty:
			log.Debug().Str("user", oauthToken.PreferredUsername).Str("path", r.URL.Path).
				Msg("No alerting access, returning empty result")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(route.Empty))
			return
		case alertDeny:
			logAndWriteError(w, http.StatusForbidden, fmt.Errorf("no alerting access"), "")
			return
		case alertDenyWrite:
			logAndWriteError(w, http.StatusForbidden, fmt.Errorf("alerting write access required"), "")
			return
		}

		// Matches handlerWithProxy: the Director reads these for actor header injection.
		ctx = context.WithValue(ctx, "username", oauthToken.PreferredUsername)
		ctx = context.WithValue(ctx, "email", oauthToken.Email)
		r = r.WithContext(ctx)

		setHeaders(r, tls, headers, a.ServiceAccountToken)
		proxy.ServeHTTP(w, r)
	}
}

// handlerWithProxy orchestrates the request flow through the proxy using pre-created
// reverse proxy instances, comprising authentication, conditional enforcement, request
// timeouts, and forwarding to the upstream server.
//
// This function uses pre-created proxy instances for better performance through connection
// reuse and per-upstream configuration. Request timeouts are enforced using context deadlines.
func handlerWithProxy(matchWord string, enforcer EnforceQL, proxy *httputil.ReverseProxy, proxyCfg ProxyConfig, tls bool, headers map[string]string, a *App) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		// Create timeout context for the request
		ctx, cancel := context.WithTimeout(r.Context(), proxyCfg.RequestTimeout)
		defer cancel()
		r = r.WithContext(ctx)

		oauthToken, err := getIdentity(r, a)
		if err != nil {
			logAndWriteError(w, http.StatusForbidden, err, "")
			return
		}

		// Policy-based enforcement (only method supported)
		policy, skip, err := validateLabelPolicy(oauthToken, a)
		if err != nil {
			logAndWriteError(w, http.StatusForbidden, err, "")
			return
		}

		// Store user information in context for actor header injection in Director function
		ctx = context.WithValue(ctx, "username", oauthToken.PreferredUsername)
		ctx = context.WithValue(ctx, "email", oauthToken.Email)
		r = r.WithContext(ctx)

		if skip {
			setHeaders(r, tls, headers, a.ServiceAccountToken)
			proxy.ServeHTTP(w, r)
			return
		}

		err = enforceRequest(r, enforcer, policy, matchWord)
		if err != nil {
			logAndWriteError(w, http.StatusForbidden, err, "")
			return
		}

		setHeaders(r, tls, headers, a.ServiceAccountToken)
		proxy.ServeHTTP(w, r)
	}
}

// handler function orchestrates the request flow through the proxy, comprising
// authentication, conditional enforcement, and forwarding to the upstream server.
// This is the legacy handler kept for backward compatibility during migration.
// DEPRECATED: Use handlerWithProxy instead for better performance.
func handler(matchWord string, enforcer EnforceQL, dsURL string, tls bool, headers map[string]string, a *App) func(http.ResponseWriter, *http.Request) {
	upstreamURL, err := url.Parse(dsURL)
	if err != nil {
		log.Fatal().Err(err).Str("url", dsURL).Msg("Error parsing URL")
	}
	return func(w http.ResponseWriter, r *http.Request) {
		oauthToken, err := getIdentity(r, a)
		if err != nil {
			logAndWriteError(w, http.StatusForbidden, err, "")
		}

		// Policy-based enforcement (only method supported)
		policy, skip, err := validateLabelPolicy(oauthToken, a)
		if err != nil {
			logAndWriteError(w, http.StatusForbidden, err, "")
			return
		}

		if skip {
			streamUp(w, r, upstreamURL, tls, headers, a)
			return
		}

		err = enforceRequest(r, enforcer, policy, matchWord)
		if err != nil {
			logAndWriteError(w, http.StatusForbidden, err, "")
			return
		}

		if _, ok := enforcer.(LogQLEnforcer); ok {
			err := setActorHeaderLogQL(r, oauthToken, a)
			if err != nil {
				logAndWriteError(w, http.StatusForbidden, err, "")
				return
			}
		}
		if _, ok := enforcer.(PromQLEnforcer); ok {
			err := setActorHeaderPromQL(r, oauthToken, a)
			if err != nil {
				logAndWriteError(w, http.StatusForbidden, err, "")
				return
			}
		}
		if _, ok := enforcer.(TraceQLEnforcer); ok {
			err := setActorHeaderTraceQL(r, oauthToken, a)
			if err != nil {
				logAndWriteError(w, http.StatusForbidden, err, "")
				return
			}
		}

		streamUp(w, r, upstreamURL, tls, headers, a)
	}
}

func setActorHeaderLogQL(r *http.Request, token OAuthToken, a *App) error {
	if a.Cfg.Loki.ActorHeader != "" {
		data := fmt.Sprintf("%s%s", token.PreferredUsername, token.Email)
		encoded := base64.StdEncoding.EncodeToString([]byte(data))
		r.Header.Set(a.Cfg.Loki.ActorHeader, encoded)
	}
	return nil
}

func setActorHeaderPromQL(r *http.Request, token OAuthToken, a *App) error {
	if a.Cfg.Thanos.ActorHeader != "" {
		data := fmt.Sprintf("%s%s", token.PreferredUsername, token.Email)
		encoded := base64.StdEncoding.EncodeToString([]byte(data))
		r.Header.Set(a.Cfg.Thanos.ActorHeader, encoded)
	}
	return nil
}

func setActorHeaderTraceQL(r *http.Request, token OAuthToken, a *App) error {
	if a.Cfg.Tempo.ActorHeader != "" {
		data := fmt.Sprintf("%s%s", token.PreferredUsername, token.Email)
		encoded := base64.StdEncoding.EncodeToString([]byte(data))
		r.Header.Set(a.Cfg.Tempo.ActorHeader, encoded)
	}
	return nil
}

// streamUp forwards the provided HTTP request to the specified upstream URL using
// a reverse proxy.It serves the upstream content back to the original client.
func streamUp(w http.ResponseWriter, r *http.Request, upstreamURL *url.URL, tls bool, headers map[string]string, a *App) {
	setHeaders(r, tls, headers, a.ServiceAccountToken)
	proxy := httputil.NewSingleHostReverseProxy(upstreamURL)
	proxy.ServeHTTP(w, r)
}

// setHeaders modifies the HTTP request headers to set the Authorization and
// other headers based on the provided arguments.
func setHeaders(r *http.Request, tls bool, header map[string]string, sat string) {
	if !tls {
		r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", sat))
	}
	for k, v := range header {
		r.Header.Set(k, v)
	}
}
