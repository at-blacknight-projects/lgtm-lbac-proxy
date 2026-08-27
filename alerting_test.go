package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
)

func alertingApp(cfg AlertingConfig, adminGroup string) *App {
	return &App{Cfg: &Config{
		Alerting: cfg,
		Admin:    AdminConfig{Group: adminGroup},
	}}
}

func TestAlertingAccess(t *testing.T) {
	cfg := AlertingConfig{
		Enabled:      true,
		ViewerGroups: []string{"alert-viewer"},
		AdminGroups:  []string{"alert-admin"},
	}

	tests := []struct {
		name       string
		groups     []string
		adminGroup string
		want       AlertAccess
	}{
		{"admin group implies write", []string{"cluster-admin"}, "cluster-admin", AlertAccessWrite},
		{"alerting admin group", []string{"alert-admin"}, "cluster-admin", AlertAccessWrite},
		{"alerting viewer group", []string{"alert-viewer"}, "cluster-admin", AlertAccessRead},
		{"unrelated group", []string{"team-audio"}, "cluster-admin", AlertAccessNone},
		{"no groups", nil, "cluster-admin", AlertAccessNone},
		{"case insensitive", []string{"Alert-Viewer"}, "cluster-admin", AlertAccessRead},
		{"admin wins over viewer", []string{"alert-viewer", "cluster-admin"}, "cluster-admin", AlertAccessWrite},
		{"alerting admin wins over viewer", []string{"alert-viewer", "alert-admin"}, "cluster-admin", AlertAccessWrite},
		// An unset admin.group must not match a caller carrying an empty group string.
		{"empty admin group never matches", []string{""}, "", AlertAccessNone},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := alertingApp(cfg, tt.adminGroup)
			token := OAuthToken{PreferredUsername: "user", Groups: tt.groups}
			assert.Equal(t, tt.want, alertingAccess(token, app))
		})
	}
}

// An unconfigured alerting section must grant nothing, so enabling the routes without
// naming groups cannot silently open them.
func TestAlertingAccessUnconfiguredGrantsNothing(t *testing.T) {
	app := alertingApp(AlertingConfig{Enabled: true}, "")
	token := OAuthToken{PreferredUsername: "user", Groups: []string{"team-audio", "alert-viewer"}}
	assert.Equal(t, AlertAccessNone, alertingAccess(token, app))
}

func TestDecideAlertRequest(t *testing.T) {
	readable := AlertRoute{
		Url:     "/api/v1/rules",
		Methods: []string{http.MethodGet},
		Empty:   emptyRuleGroups,
	}
	silences := AlertRoute{
		Url:          "/api/v2/silences",
		Methods:      []string{http.MethodGet, http.MethodPost},
		WriteMethods: []string{http.MethodPost},
	}

	tests := []struct {
		name   string
		route  AlertRoute
		method string
		access AlertAccess
		want   alertDecision
	}{
		{"no access reads empty rules", readable, http.MethodGet, AlertAccessNone, alertEmpty},
		{"viewer reads rules", readable, http.MethodGet, AlertAccessRead, alertForward},
		{"admin reads rules", readable, http.MethodGet, AlertAccessWrite, alertForward},
		// No empty form defined, so a caller with no access is refused rather than
		// handed a misleading "no silences" answer.
		{"no access denied silences", silences, http.MethodGet, AlertAccessNone, alertDeny},
		{"viewer reads silences", silences, http.MethodGet, AlertAccessRead, alertForward},
		{"viewer cannot create silence", silences, http.MethodPost, AlertAccessRead, alertDenyWrite},
		{"no access cannot create silence", silences, http.MethodPost, AlertAccessNone, alertDeny},
		{"admin creates silence", silences, http.MethodPost, AlertAccessWrite, alertForward},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, decideAlertRequest(tt.route, tt.method, tt.access))
		})
	}
}

// registeredRoutes walks the router and returns "METHOD path" for every registered route.
func registeredRoutes(t *testing.T, router *mux.Router) map[string]bool {
	t.Helper()
	got := map[string]bool{}
	err := router.Walk(func(route *mux.Route, _ *mux.Router, _ []*mux.Route) error {
		path, err := route.GetPathTemplate()
		if err != nil {
			return nil
		}
		methods, err := route.GetMethods()
		if err != nil || len(methods) == 0 {
			got[path] = true
			return nil
		}
		for _, m := range methods {
			got[m+" "+path] = true
		}
		return nil
	})
	assert.NoError(t, err)
	return got
}

func alertingRoutesApp(enabled bool) *App {
	return &App{Cfg: &Config{
		Alerting:     AlertingConfig{Enabled: enabled, ViewerGroups: []string{"alert-viewer"}},
		Thanos:       ThanosConfig{URL: "http://thanos.example.com/prometheus"},
		Loki:         LokiConfig{URL: "http://loki.example.com"},
		Alertmanager: AlertmanagerConfig{URL: "http://mimir.example.com", PathPrefix: "/alertmanager"},
	}}
}

// The reported failure was a 404 from the router: Grafana asks for these paths and
// nothing was registered to answer, so the alert list came up empty for everyone.
func TestRulerAndAlertmanagerRoutesRegistered(t *testing.T) {
	app := alertingRoutesApp(true)
	app.e = mux.NewRouter()
	app.WithRuler().WithAlertmanager()

	got := registeredRoutes(t, app.e)

	want := []string{
		// Grafana's Prometheus-compatible rules endpoints, Mimir then Loki.
		"GET /api/v1/rules",
		"GET /api/v1/alerts",
		"GET /prometheus/api/v1/rules",
		"GET /prometheus/api/v1/alerts",
		// Alertmanager.
		"GET /alertmanager/api/v2/status",
		"GET /alertmanager/api/v2/alerts",
		"GET /alertmanager/api/v2/alerts/groups",
		"GET /alertmanager/api/v2/silences",
		"POST /alertmanager/api/v2/silences",
		"DELETE /alertmanager/api/v2/silence/{id}",
		// Grafana probes buildinfo before it will talk to an Alertmanager at all.
		"GET /alertmanager/api/v1/status/buildinfo",
		// Opening a single rule group is a different endpoint from listing them, and a
		// UI needs both. Read-only: see the write assertions below.
		"GET /config/v1/rules",
		"GET /config/v1/rules/{namespace}/{group}",
		"GET /loki/api/v1/rules/{namespace}/{group}",
	}
	for _, route := range want {
		assert.True(t, got[route], "expected route %q to be registered", route)
	}

	// Rules are managed as code; routing the ruler's write methods would let a UI save
	// rules that the next sync silently reverts.
	for _, route := range []string{
		"POST /config/v1/rules", "POST /config/v1/rules/{namespace}",
		"DELETE /config/v1/rules/{namespace}/{group}",
		"POST /loki/api/v1/rules/{namespace}", "DELETE /loki/api/v1/rules/{namespace}/{group}",
	} {
		assert.False(t, got[route], "ruler configuration API must stay read-only, got %q", route)
	}

	// Same for the Alertmanager configuration API. Clients ask for it at the root, where
	// it would shadow the ruler's /api/v1/alerts and forward to the wrong upstream.
	assert.False(t, got["POST /api/v1/alerts"], "Alertmanager configuration API must not be exposed")
	assert.False(t, got["POST /alertmanager/api/v1/alerts"], "Alertmanager configuration API must not be exposed")
}

func TestAlertingRoutesAbsentWhenDisabled(t *testing.T) {
	app := alertingRoutesApp(false)
	app.e = mux.NewRouter()
	app.WithRuler().WithAlertmanager()

	got := registeredRoutes(t, app.e)
	assert.Empty(t, got, "no alerting routes should be registered when alerting is disabled")
}

// A standalone Alertmanager serves the API at the root, so an empty path prefix must
// still register the routes there.
func TestAlertmanagerRoutesWithoutPathPrefix(t *testing.T) {
	app := &App{Cfg: &Config{
		Alerting:     AlertingConfig{Enabled: true},
		Alertmanager: AlertmanagerConfig{URL: "http://alertmanager.example.com", PathPrefix: ""},
	}}
	app.e = mux.NewRouter()
	app.WithAlertmanager()

	got := registeredRoutes(t, app.e)
	assert.True(t, got["GET /api/v2/silences"], "Alertmanager routes should be registered at the root")
	assert.True(t, got["POST /api/v2/silences"], "Alertmanager routes should be registered at the root")
}

// Identity is resolved before access, so an unauthenticated caller is refused rather
// than being handed the empty result set reserved for authenticated non-holders.
func TestAlertRouteRequiresAuthentication(t *testing.T) {
	app := alertingRoutesApp(true)
	app.Cfg.Web.AuthHeader = "Authorization"
	app.e = mux.NewRouter()
	app.WithRuler()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/rules", nil)
	rec := httptest.NewRecorder()
	app.e.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "no Authorization header found")
}
