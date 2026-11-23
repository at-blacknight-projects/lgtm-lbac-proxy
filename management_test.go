package main

import (
	"bytes"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	metrics "github.com/slok/go-http-metrics/metrics/prometheus"
	"github.com/slok/go-http-metrics/middleware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestManagerID(t *testing.T) {
	managers := map[string]string{
		"rules-admin":     "ci",
		"rules-admin-alt": "ci",
		"platform-oncall": "oncall",
	}

	tests := []struct {
		name    string
		groups  []string
		want    string
		wantErr error
	}{
		{"single manager group", []string{"rules-admin"}, "ci", nil},
		{"case insensitive", []string{"Rules-Admin"}, "ci", nil},
		{"unrelated groups ignored", []string{"team-a", "platform-oncall"}, "oncall", nil},
		{"two groups, same id", []string{"rules-admin", "rules-admin-alt"}, "ci", nil},
		// The id is what every change is attributed to, so two candidates are refused.
		{"two groups, different ids", []string{"rules-admin", "platform-oncall"}, "", errAmbiguousManagerRole},
		{"no manager group", []string{"team-a"}, "", errNoManagerRole},
		{"no groups", nil, "", errNoManagerRole},
		{"admin group is not a manager", []string{"cluster-admin"}, "", errNoManagerRole},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := managerID(OAuthToken{Groups: tt.groups}, ManagementConfig{Managers: managers})
			assert.Equal(t, tt.want, got)
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

// An empty group key must never match a caller carrying an empty group string.
func TestManagerIDEmptyGroupNeverMatches(t *testing.T) {
	_, err := managerID(OAuthToken{Groups: []string{""}}, ManagementConfig{Managers: map[string]string{"": "ci"}})
	assert.ErrorIs(t, err, errNoManagerRole)
}

func validManagementConfig() *Config {
	return &Config{
		Web:  WebConfig{ProxyPort: 8080, MetricsPort: 8081},
		Auth: AuthConfig{AuthHeader: "Authorization", ClientCert: ClientCertConfig{MTLSPort: 8443}},
		Management: ManagementConfig{
			Enabled:      true,
			Port:         8445,
			ServerCert:   "/certs/tls.crt",
			ServerKey:    "/certs/tls.key",
			MaxBodyBytes: defaultManagementMaxBodyBytes,
			MimirRuler:   ManagementUpstream{URL: "http://ruler.example.com:8080"},
			Managers:     map[string]string{"rules-admin": "ci"},
		},
	}
}

func TestValidateManagementConfig(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(c *Config)
		wantErr string
	}{
		{"valid", func(c *Config) {}, ""},
		{"disabled skips validation", func(c *Config) { c.Management = ManagementConfig{} }, ""},
		{"zero port", func(c *Config) { c.Management.Port = 0 }, "not a valid port"},
		{"port above range", func(c *Config) { c.Management.Port = 70000 }, "not a valid port"},
		{"collides with proxy port", func(c *Config) { c.Management.Port = 8080 }, "web.proxy_port"},
		{"collides with metrics port", func(c *Config) { c.Management.Port = 8081 }, "web.metrics_port"},
		{"collides with mtls port", func(c *Config) { c.Management.Port = 8443 }, "mtls_port"},
		{"collides with ingest port", func(c *Config) {
			c.Ingest = IngestConfig{Enabled: true, Port: 8445}
		}, "ingest.port"},
		{"disabled ingest port is not a collision", func(c *Config) {
			c.Ingest = IngestConfig{Enabled: false, Port: 8445}
		}, ""},
		{"missing cert", func(c *Config) { c.Management.ServerCert = "" }, "server_cert"},
		{"non-positive body cap", func(c *Config) { c.Management.MaxBodyBytes = 0 }, "max_body_bytes"},
		{"no upstream", func(c *Config) { c.Management.MimirRuler.URL = "" }, "at least one"},
		{"relative url", func(c *Config) { c.Management.LokiRuler.URL = "/loki" }, "absolute http or https"},
		{"bad scheme", func(c *Config) { c.Management.Alertmanager.URL = "ftp://am.example.com" }, "absolute http or https"},
		{"bad header name", func(c *Config) {
			c.Management.MimirRuler.Headers = map[string]string{"Bad Header": "x"}
		}, "not a valid header name"},
		{"credential header refused", func(c *Config) {
			c.Management.MimirRuler.Headers = map[string]string{"Authorization": "Basic x"}
		}, "reserved"},
		{"tenant header allowed", func(c *Config) {
			c.Management.MimirRuler.Headers = map[string]string{"X-Scope-OrgID": "tenant-a"}
		}, ""},
		{"no managers and no static keys", func(c *Config) { c.Management.Managers = nil }, "both empty"},
		{"static keys alone are enough", func(c *Config) {
			c.Management.Managers = nil
			c.Management.StaticKeys = map[string]string{testKeyHash("k"): "ci"}
		}, ""},
		{"raw key instead of hash", func(c *Config) {
			c.Management.StaticKeys = map[string]string{"not-a-hash-but-a-key": "ci"}
		}, "not a SHA-256 hash"},
		{"bad static key manager id", func(c *Config) {
			c.Management.StaticKeys = map[string]string{testKeyHash("k"): "Not Valid"}
		}, "manager id"},
		{"empty manager group", func(c *Config) {
			c.Management.Managers = map[string]string{" ": "ci"}
		}, "empty group"},
		{"bad manager id", func(c *Config) {
			c.Management.Managers = map[string]string{"rules-admin": "CI_Job"}
		}, "must match"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := validManagementConfig()
			tt.mutate(c)
			err := validateManagementConfig(c)
			if tt.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			assert.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestValidateManagementOnlyRequiresEnabled(t *testing.T) {
	c := validManagementConfig()
	c.Management.Enabled = false
	c.Management.Only = true
	assert.ErrorContains(t, validateManagementConfig(c), "management.only requires management.enabled")
}

func TestManagementConfigLoadsFromRenderedYAML(t *testing.T) {
	rendered := `
web:
  proxy_port: 8080
  metrics_port: 8081
management:
  enabled: true
  only: true
  port: 8445
  server_cert: /etc/secrets/management/tls.crt
  server_key: /etc/secrets/management/tls.key
  managers:
    "Rules-Admin": "ci"
  static_keys:
    "` + testKeyHash("k") + `": "pipeline"
  mimir_ruler:
    url: "http://ruler.example.com:8080"
    headers:
      X-Scope-OrgID: "tenant-a"
  alertmanager:
    url: "http://am.example.com:8080"
`
	v := newConfigViper()
	require.NoError(t, v.ReadConfig(strings.NewReader(rendered)))
	cfg, err := loadConfig(v)
	require.NoError(t, err)

	m := cfg.Management
	assert.True(t, m.Only)
	assert.Equal(t, int64(defaultManagementMaxBodyBytes), m.MaxBodyBytes, "default applied")
	assert.Equal(t, "http://ruler.example.com:8080", m.upstream(targetMimirRules).URL)
	assert.Empty(t, m.upstream(targetLokiRules).URL)
	// viper lowercases map keys; groups still match case-insensitively.
	got, err := managerID(OAuthToken{Groups: []string{"rules-admin"}}, m)
	require.NoError(t, err)
	assert.Equal(t, "ci", got)
	assert.Equal(t, "pipeline", m.StaticKeys[testKeyHash("k")])
	// Header values survive; viper lowercases the name, and net/http canonicalises it
	// again when the header is set on the request.
	assert.Equal(t, "tenant-a", m.MimirRuler.Headers["x-scope-orgid"])
}

func managementRoutesApp(m ManagementConfig) *App {
	return newTestApp(&Config{
		Alerting:     AlertingConfig{Enabled: true},
		Thanos:       ThanosConfig{URL: "http://metrics.example.com/prometheus"},
		Loki:         LokiConfig{URL: "http://logs.example.com"},
		Alertmanager: AlertmanagerConfig{URL: "http://alerts.example.com", PathPrefix: "/alertmanager"},
		Management:   m,
	})
}

func allManagementUpstreams(url string) ManagementConfig {
	return ManagementConfig{
		Enabled:      true,
		MimirRuler:   ManagementUpstream{URL: url},
		LokiRuler:    ManagementUpstream{URL: url},
		Alertmanager: ManagementUpstream{URL: url},
		Managers:     map[string]string{"group1": "ci"},
		MaxBodyBytes: defaultManagementMaxBodyBytes,
	}
}

// In management-only mode the process sets up nothing on the read side.
func TestManagementOnlySetsUpNoReadPath(t *testing.T) {
	m := allManagementUpstreams(okReceiverURL(t))
	m.Only = true
	app := managementRoutesApp(m)
	app.Cfg().LabelStore.ConfigPaths = []string{t.TempDir()}
	labelsLastReloadSuccessful.Set(0)

	app.WithLabelStore().WithProxies().WithRoutes().WithIngest().WithManagement()

	assert.Nil(t, app.LabelStore)
	assert.Equal(t, 1.0, gaugeValue(labelsLastReloadSuccessful), "no labels reload to fail")
	assert.Nil(t, app.thanosProxy)
	assert.Nil(t, app.lokiProxy)
	assert.Nil(t, app.alertmanagerProxy)
	assert.Nil(t, app.e, "no read router in management-only mode")
	assert.Nil(t, app.w, "ingest not enabled")
	assert.Len(t, app.managementProxies, 3)
	assert.True(t, registeredRoutes(t, app.m)["POST /prometheus/config/v1/rules/{namespace}"])
}

// Without management.only, enabling management leaves the read side as it was.
func TestManagementAlongsideReadPath(t *testing.T) {
	app := managementRoutesApp(allManagementUpstreams(okReceiverURL(t)))
	app.WithProxies().WithRoutes().WithManagement()

	assert.NotNil(t, app.thanosProxy)
	assert.NotNil(t, app.e)
	assert.NotNil(t, app.m)
}

// The management router serves the configuration APIs and the probe, and nothing else;
// the read router keeps no write method on any of those paths.
func TestManagementRoutesIsolated(t *testing.T) {
	app := managementRoutesApp(allManagementUpstreams("http://upstream.example.com"))
	app.WithRoutes().WithManagement()

	assert.Equal(t, map[string]bool{
		"GET /healthz": true,

		"GET /prometheus/config/v1/rules":                        true,
		"GET /prometheus/config/v1/rules/{namespace}":            true,
		"POST /prometheus/config/v1/rules/{namespace}":           true,
		"DELETE /prometheus/config/v1/rules/{namespace}":         true,
		"GET /prometheus/config/v1/rules/{namespace}/{group}":    true,
		"DELETE /prometheus/config/v1/rules/{namespace}/{group}": true,

		"GET /loki/api/v1/rules":                        true,
		"GET /loki/api/v1/rules/{namespace}":            true,
		"POST /loki/api/v1/rules/{namespace}":           true,
		"DELETE /loki/api/v1/rules/{namespace}":         true,
		"GET /loki/api/v1/rules/{namespace}/{group}":    true,
		"DELETE /loki/api/v1/rules/{namespace}/{group}": true,

		"GET /api/v1/alerts":    true,
		"POST /api/v1/alerts":   true,
		"DELETE /api/v1/alerts": true,
	}, registeredRoutes(t, app.m))

	// The read router keeps its GET-only rule routes; it must gain no rule or
	// Alertmanager configuration write.
	for route := range registeredRoutes(t, app.e) {
		if strings.Contains(route, "/rules") || strings.HasSuffix(route, "/api/v1/alerts") {
			assert.True(t, strings.HasPrefix(route, "GET "), "read router has a write route: %s", route)
		}
	}
}

func TestManagementRoutesOnlyForConfiguredUpstreams(t *testing.T) {
	app := managementRoutesApp(ManagementConfig{
		Enabled:   true,
		LokiRuler: ManagementUpstream{URL: "http://loki.example.com"},
		Managers:  map[string]string{"group1": "ci"},
	})
	app.WithManagement()

	got := registeredRoutes(t, app.m)
	assert.True(t, got["POST /loki/api/v1/rules/{namespace}"])
	assert.False(t, got["POST /prometheus/config/v1/rules/{namespace}"])
	assert.False(t, got["POST /api/v1/alerts"])
}

func TestManagementDisabledBuildsNoRouter(t *testing.T) {
	app := managementRoutesApp(ManagementConfig{})
	app.WithManagement()
	assert.Nil(t, app.m)
}

// managementHandlerApp is a full test app (real JWT validation) with the management
// proxies and router built, every API forwarding to upstreamURL.
func managementHandlerApp(t *testing.T, upstreamURL string, mutate ...func(*ManagementConfig)) (*App, map[string]string) {
	t.Helper()
	app, tokens := setupTestMain()
	app.healthy = true
	app.Cfg().Management = allManagementUpstreams(upstreamURL)
	for _, m := range mutate {
		m(&app.Cfg().Management)
	}
	app.withManagementProxies()
	app.WithManagement()
	return &app, tokens
}

func serveManagement(app *App, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	app.m.ServeHTTP(rec, req)
	return rec
}

const testRuleGroup = "name: example\nrules:\n  - record: job:up:sum\n    expr: sum by (job) (up)\n"

func TestManagementHandlerAuth(t *testing.T) {
	readKey, writeKey := "read-key", "manage-key"
	app, tokens := managementHandlerApp(t, okReceiverURL(t), func(m *ManagementConfig) {
		m.StaticKeys = map[string]string{testKeyHash(writeKey): "pipeline"}
	})
	app.Cfg().Auth.StaticKeys = map[string]string{testKeyHash(readKey): "reader"}
	app.Cfg().Admin = AdminConfig{Bypass: true, Group: "admins"}

	tests := []struct {
		name     string
		token    string
		wantCode int
		wantBody string
	}{
		{"no token", "", http.StatusForbidden, "no Authorization header found"},
		{"invalid token", "not-a-jwt", http.StatusForbidden, "error parsing token"},
		{"no manager group", tokens["noGroupsTenant"], http.StatusForbidden, errNoManagerRole.Error()},
		{"admin group is not a manager", tokens["adminUserToken"], http.StatusForbidden, errNoManagerRole.Error()},
		{"read static key grants nothing", readKey, http.StatusForbidden, "error parsing token"},
		{"manager group", tokens["groupTenant"], http.StatusOK, ""},
		{"management static key", writeKey, http.StatusOK, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/prometheus/config/v1/rules/example", strings.NewReader(testRuleGroup))
			if tt.token != "" {
				req.Header.Set("Authorization", "Bearer "+tt.token)
			}
			rec := serveManagement(app, req)
			assert.Equal(t, tt.wantCode, rec.Code)
			assert.Contains(t, rec.Body.String(), tt.wantBody)
		})
	}
}

func TestManagementHandlerAmbiguousManager(t *testing.T) {
	app, tokens := managementHandlerApp(t, okReceiverURL(t), func(m *ManagementConfig) {
		m.Managers = map[string]string{"group1": "ci", "group2": "oncall"}
	})

	req := httptest.NewRequest(http.MethodDelete, "/loki/api/v1/rules/example", nil)
	req.Header.Set("Authorization", "Bearer "+tokens["groupsTenant"])
	rec := serveManagement(app, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), errAmbiguousManagerRole.Error())
}

// A trusted CN header must not stand in for a credential, even with trusted-header
// identity enabled for the read path.
func TestManagementHandlerIgnoresTrustedClientHeader(t *testing.T) {
	app, _ := managementHandlerApp(t, okReceiverURL(t), func(m *ManagementConfig) {
		m.Managers = map[string]string{"svc-ci": "ci"}
	})
	app.Cfg().Auth.TrustedClientHeader = TrustedClientHeaderConfig{Enabled: true, CNHeader: "X-Client-CN"}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/alerts", strings.NewReader("route: {}"))
	req.Header.Set("X-Client-CN", "svc-ci")
	rec := serveManagement(app, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestManagementRouterRefusesEverythingElse(t *testing.T) {
	app, tokens := managementHandlerApp(t, okReceiverURL(t))

	tests := []struct {
		name     string
		method   string
		path     string
		wantCode int
	}{
		{"healthz needs no auth", http.MethodGet, "/healthz", http.StatusOK},
		{"query route is not served", http.MethodGet, "/api/v1/query?query=up", http.StatusNotFound},
		{"log query is not served", http.MethodGet, "/loki/api/v1/query_range", http.StatusNotFound},
		{"push route is not served", http.MethodPost, "/v1/metrics", http.StatusNotFound},
		{"silences are not served", http.MethodPost, "/alertmanager/api/v2/silences", http.StatusNotFound},
		{"rule list cannot be posted to", http.MethodPost, "/prometheus/config/v1/rules", http.StatusMethodNotAllowed},
		{"rule group cannot be posted to", http.MethodPost, "/loki/api/v1/rules/ns/group", http.StatusMethodNotAllowed},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			req.Header.Set("Authorization", "Bearer "+tokens["groupTenant"])
			rec := serveManagement(app, req)
			assert.Equal(t, tt.wantCode, rec.Code)
		})
	}
}

// The request reaches the upstream with its method, path and body intact, the caller's
// credentials removed, and configured headers overwriting the caller's.
func TestManagementForwardsRequest(t *testing.T) {
	upstream, got := fakeReceiver(t, http.StatusAccepted, "")
	app, tokens := managementHandlerApp(t, upstream.URL+"/base", func(m *ManagementConfig) {
		m.MimirRuler.Headers = map[string]string{"X-Scope-OrgID": "tenant-a"}
	})

	req := httptest.NewRequest(http.MethodPost, "/prometheus/config/v1/rules/example", strings.NewReader(testRuleGroup))
	req.Header.Set("Authorization", "Bearer "+tokens["groupTenant"])
	req.Header.Set("X-Scope-OrgID", "tenant-b")
	req.Header.Set("Content-Type", "application/yaml")
	rec := serveManagement(app, req)
	require.Equal(t, http.StatusAccepted, rec.Code)

	push := receive(t, got)
	assert.Equal(t, "/base/prometheus/config/v1/rules/example", push.path)
	assert.Equal(t, testRuleGroup, string(push.body))
	assert.Empty(t, push.header.Get("Authorization"), "caller credentials stripped")
	assert.Equal(t, "tenant-a", push.header.Get("X-Scope-OrgID"), "configured header wins")
	assert.Equal(t, "application/yaml", push.header.Get("Content-Type"))
}

// Without a configured header the caller's tenant header passes through.
func TestManagementPassesTenantHeaderWhenNotPinned(t *testing.T) {
	upstream, got := fakeReceiver(t, http.StatusOK, "")
	app, tokens := managementHandlerApp(t, upstream.URL)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/alerts", nil)
	req.Header.Set("Authorization", "Bearer "+tokens["groupTenant"])
	req.Header.Set("X-Scope-OrgID", "anonymous")
	require.Equal(t, http.StatusOK, serveManagement(app, req).Code)

	assert.Equal(t, "anonymous", receive(t, got).header.Get("X-Scope-OrgID"))
}

// An escaped slash in a namespace stays one segment, matched and forwarded as sent.
func TestManagementEncodedNamespace(t *testing.T) {
	upstream, got := fakeReceiver(t, http.StatusAccepted, "")
	app, tokens := managementHandlerApp(t, upstream.URL)

	req := httptest.NewRequest(http.MethodPost, "/loki/api/v1/rules/team%2Fapp", strings.NewReader(testRuleGroup))
	req.Header.Set("Authorization", "Bearer "+tokens["groupTenant"])
	require.Equal(t, http.StatusAccepted, serveManagement(app, req).Code)

	assert.Equal(t, "/loki/api/v1/rules/team/app", receive(t, got).path)
}

func TestManagementRelaysUpstreamResponse(t *testing.T) {
	upstream, _ := fakeReceiver(t, http.StatusBadRequest, "bad rule group")
	app, tokens := managementHandlerApp(t, upstream.URL)

	req := httptest.NewRequest(http.MethodPost, "/prometheus/config/v1/rules/example", strings.NewReader("not yaml"))
	req.Header.Set("Authorization", "Bearer "+tokens["groupTenant"])
	rec := serveManagement(app, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "bad rule group", rec.Body.String())
}

func TestManagementUnreachableUpstream(t *testing.T) {
	upstream := httptest.NewServer(http.NotFoundHandler())
	url := upstream.URL
	upstream.Close()
	app, tokens := managementHandlerApp(t, url)
	before := counterValue(managementRejected.WithLabelValues(targetAlertConfig, rejectUpstreamError))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/alerts", nil)
	req.Header.Set("Authorization", "Bearer "+tokens["groupTenant"])
	rec := serveManagement(app, req)

	assert.Equal(t, http.StatusBadGateway, rec.Code)
	assert.Equal(t, before+1, counterValue(managementRejected.WithLabelValues(targetAlertConfig, rejectUpstreamError)))
}

func TestManagementBodySizeCap(t *testing.T) {
	upstream, got := fakeReceiver(t, http.StatusAccepted, "")
	app, tokens := managementHandlerApp(t, upstream.URL, func(m *ManagementConfig) { m.MaxBodyBytes = 16 })
	big := bytes.Repeat([]byte("x"), 64)

	t.Run("declared length over the cap", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/alerts", bytes.NewReader(big))
		req.Header.Set("Authorization", "Bearer "+tokens["groupTenant"])
		rec := serveManagement(app, req)
		assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
		assert.Empty(t, got, "nothing forwarded")
	})

	t.Run("undeclared length over the cap", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/alerts", bytes.NewReader(big))
		req.ContentLength = -1
		req.Header.Set("Authorization", "Bearer "+tokens["groupTenant"])
		rec := serveManagement(app, req)
		assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
	})
}

func TestManagementMetrics(t *testing.T) {
	app, tokens := managementHandlerApp(t, okReceiverURL(t))
	forwarded := managementRequests.WithLabelValues("ci", targetLokiRules, http.MethodDelete, "200")
	refused := managementRejected.WithLabelValues(targetLokiRules, rejectNoRole)
	beforeForwarded, beforeRefused := counterValue(forwarded), counterValue(refused)

	req := httptest.NewRequest(http.MethodDelete, "/loki/api/v1/rules/example/group", nil)
	req.Header.Set("Authorization", "Bearer "+tokens["groupTenant"])
	require.Equal(t, http.StatusOK, serveManagement(app, req).Code)

	req = httptest.NewRequest(http.MethodDelete, "/loki/api/v1/rules/example/group", nil)
	req.Header.Set("Authorization", "Bearer "+tokens["noGroupsTenant"])
	require.Equal(t, http.StatusForbidden, serveManagement(app, req).Code)

	assert.Equal(t, beforeForwarded+1, counterValue(forwarded))
	assert.Equal(t, beforeRefused+1, counterValue(refused))
}

func TestManagementHealthzReflectsHealth(t *testing.T) {
	app, _ := managementHandlerApp(t, okReceiverURL(t))
	app.healthy = false

	rec := serveManagement(app, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestBuildManagementServer(t *testing.T) {
	certPath, keyPath := writeTestKeyPair(t, t.TempDir())
	app := newTestApp(&Config{Management: ManagementConfig{ServerCert: certPath, ServerKey: keyPath}})

	srv, err := app.buildManagementServer(":0", mux.NewRouter())
	require.NoError(t, err)

	assert.Equal(t, tls.NoClientCert, srv.TLSConfig.ClientAuth)
	assert.Equal(t, uint16(tls.VersionTLS12), srv.TLSConfig.MinVersion)
	assert.Equal(t, managementReadHeaderTimeout, srv.ReadHeaderTimeout)
	assert.Equal(t, managementReadTimeout, srv.ReadTimeout)
	assert.Equal(t, managementWriteTimeout, srv.WriteTimeout)
	assert.Equal(t, managementIdleTimeout, srv.IdleTimeout)
}

func TestBuildManagementServerMissingKeyPair(t *testing.T) {
	dir := t.TempDir()
	app := newTestApp(&Config{Management: ManagementConfig{
		ServerCert: filepath.Join(dir, "missing.crt"),
		ServerKey:  filepath.Join(dir, "missing.key"),
	}})

	_, err := app.buildManagementServer(":0", mux.NewRouter())
	assert.ErrorContains(t, err, "management server keypair")
}

// End to end over a real TLS listener: the probe answers, a query route does not, and a
// rule write needs a credential.
func TestManagementServerOverTLS(t *testing.T) {
	app, tokens := managementHandlerApp(t, okReceiverURL(t))
	app.Cfg().Management.ServerCert, app.Cfg().Management.ServerKey = writeTestKeyPair(t, t.TempDir())

	srv, err := app.buildManagementServer("127.0.0.1:0", app.m)
	require.NoError(t, err)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })

	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, // self-signed test cert
	}
	base := "https://" + ln.Addr().String()

	resp, err := client.Get(base + "/healthz")
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	resp, err = client.Get(base + "/api/v1/query?query=up")
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)

	resp, err = client.Post(base+"/prometheus/config/v1/rules/example", "application/yaml", strings.NewReader(testRuleGroup))
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)

	req, err := http.NewRequest(http.MethodPost, base+"/prometheus/config/v1/rules/example", strings.NewReader(testRuleGroup))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+tokens["groupTenant"])
	resp, err = client.Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// Every listener records HTTP metrics on the shared registry without colliding.
func TestManagementHTTPMetricsCoexist(t *testing.T) {
	reg := prometheus.NewRegistry()
	assert.NotPanics(t, func() {
		middleware.New(middleware.Config{
			Recorder: metrics.NewRecorder(metrics.Config{Registry: reg}),
			Service:  "lgtm_lbac_proxy",
		})
		ingestHTTPMetrics(reg)
		managementHTTPMetrics(reg)
	})
}

func TestRestartOnlyChangesIncludesManagement(t *testing.T) {
	old := validManagementConfig()
	next := validManagementConfig()
	next.Management.LokiRuler.URL = "http://loki.example.com"
	assert.Contains(t, restartOnlyChanges(old, next), "management listener and upstreams")

	// Managers follow reloads, so changing them is not a restart-only change.
	next = validManagementConfig()
	next.Management.Managers = map[string]string{"other-group": "ci"}
	assert.NotContains(t, restartOnlyChanges(old, next), "management listener and upstreams")
}
