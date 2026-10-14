package main

import (
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	metrics "github.com/slok/go-http-metrics/metrics/prometheus"
	"github.com/slok/go-http-metrics/middleware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIngestWriter(t *testing.T) {
	writers := map[string]string{
		"otlp-writer-app-a": "app-a",
		"otlp-app-a-alt":    "app-a",
		"otlp-writer-app-b": "app-b",
	}

	tests := []struct {
		name    string
		groups  []string
		want    string
		wantErr error
	}{
		{"single writer group", []string{"otlp-writer-app-a"}, "app-a", nil},
		{"case insensitive", []string{"OTLP-Writer-App-A"}, "app-a", nil},
		{"unrelated groups ignored", []string{"team-a", "otlp-writer-app-b"}, "app-b", nil},
		{"two groups, same id", []string{"otlp-writer-app-a", "otlp-app-a-alt"}, "app-a", nil},
		// The id decides where the data lands, so two candidates are refused, not guessed.
		{"two groups, different ids", []string{"otlp-writer-app-a", "otlp-writer-app-b"}, "", errAmbiguousIngestRole},
		{"no writer group", []string{"team-a"}, "", errNoIngestRole},
		{"no groups", nil, "", errNoIngestRole},
		// The admin group is not a writer unless named as one.
		{"admin group is not a writer", []string{"cluster-admin"}, "", errNoIngestRole},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := OAuthToken{PreferredUsername: "user", Groups: tt.groups}
			got, err := ingestWriter(token, IngestConfig{Writers: writers})
			assert.Equal(t, tt.want, got)
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

// An empty group key must never match a caller carrying an empty group string.
func TestIngestWriterEmptyGroupNeverMatches(t *testing.T) {
	token := OAuthToken{Groups: []string{""}}
	_, err := ingestWriter(token, IngestConfig{Writers: map[string]string{"": "app-a"}})
	assert.ErrorIs(t, err, errNoIngestRole)
}

func validIngestConfig() *Config {
	return &Config{
		Web:  WebConfig{ProxyPort: 8080, MetricsPort: 8081},
		Auth: AuthConfig{AuthHeader: "Authorization", ClientCert: ClientCertConfig{MTLSPort: 8443}},
		Ingest: IngestConfig{
			Enabled:      true,
			Port:         8444,
			ServerCert:   "/certs/tls.crt",
			ServerKey:    "/certs/tls.key",
			MaxBodyBytes: defaultIngestMaxBodyBytes,
			Metrics:      IngestSignalConfig{URL: "http://receiver.example.com:4318"},
			Writers:      map[string]string{"otlp-writer-app-a": "app-a"},
		},
	}
}

func TestValidateIngestConfig(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(c *Config)
		wantErr string
	}{
		{"valid", func(c *Config) {}, ""},
		{"disabled skips validation", func(c *Config) { c.Ingest = IngestConfig{} }, ""},
		{"zero port", func(c *Config) { c.Ingest.Port = 0 }, "not a valid port"},
		{"port above range", func(c *Config) { c.Ingest.Port = 70000 }, "not a valid port"},
		{"collides with proxy port", func(c *Config) { c.Ingest.Port = 8080 }, "web.proxy_port"},
		{"collides with metrics port", func(c *Config) { c.Ingest.Port = 8081 }, "web.metrics_port"},
		{"collides with mtls port", func(c *Config) { c.Ingest.Port = 8443 }, "mtls_port"},
		{"missing cert", func(c *Config) { c.Ingest.ServerCert = "" }, "server_cert"},
		{"non-positive body cap", func(c *Config) { c.Ingest.MaxBodyBytes = 0 }, "max_body_bytes"},
		{"no signal routed", func(c *Config) { c.Ingest.Metrics.URL = "" }, "at least one"},
		{"relative url", func(c *Config) { c.Ingest.Logs.URL = "/v1" }, "absolute http or https"},
		{"bad scheme", func(c *Config) { c.Ingest.Traces.URL = "grpc://receiver.example.com:4317" }, "absolute http or https"},
		{"no writers", func(c *Config) { c.Ingest.Writers = nil }, "writers is empty"},
		{"empty group", func(c *Config) { c.Ingest.Writers = map[string]string{" ": "app-a"} }, "empty group"},
		{"uppercase id", func(c *Config) { c.Ingest.Writers = map[string]string{"g": "App-A"} }, "must match"},
		{"slash in id", func(c *Config) { c.Ingest.Writers = map[string]string{"g": "a/b"} }, "must match"},
		{"trailing hyphen id", func(c *Config) { c.Ingest.Writers = map[string]string{"g": "app-"} }, "must match"},
		// An unset writer header falls back to the default rather than failing.
		{"default writer header", func(c *Config) { c.Ingest.WriterHeader = "" }, ""},
		{"tenant header as writer header", func(c *Config) { c.Ingest.WriterHeader = "X-Scope-OrgID" }, ""},
		{"writer header with a space", func(c *Config) { c.Ingest.WriterHeader = "X Writer" }, "not a valid header name"},
		{"writer header is Authorization", func(c *Config) { c.Ingest.WriterHeader = "authorization" }, "reserved"},
		{"writer header is Content-Type", func(c *Config) { c.Ingest.WriterHeader = "Content-Type" }, "reserved"},
		{"writer header is the auth header", func(c *Config) {
			c.Auth.AuthHeader = "X-Auth-Token"
			c.Ingest.WriterHeader = "x-auth-token"
		}, "reserved"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := validIngestConfig()
			tt.mutate(c)
			err := validateIngestConfig(c)
			if tt.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			if assert.Error(t, err) {
				assert.Contains(t, err.Error(), tt.wantErr)
			}
		})
	}
}

// ingestRoutesApp configures every read upstream and alerting, so the read router has
// its full route set to compare the write router against.
func ingestRoutesApp(ingest IngestConfig) *App {
	return &App{Cfg: &Config{
		Alerting:     AlertingConfig{Enabled: true},
		Thanos:       ThanosConfig{URL: "http://metrics.example.com/prometheus"},
		Loki:         LokiConfig{URL: "http://logs.example.com"},
		Tempo:        TempoConfig{URL: "http://traces.example.com"},
		Alertmanager: AlertmanagerConfig{URL: "http://alerts.example.com", PathPrefix: "/alertmanager"},
		Ingest:       ingest,
	}}
}

// The write router must serve the push routes and the probe, and nothing else, so the
// write listener cannot be used to read.
func TestIngestRoutesIsolatedFromReadRoutes(t *testing.T) {
	app := ingestRoutesApp(IngestConfig{
		Enabled: true,
		Metrics: IngestSignalConfig{URL: "http://receiver.example.com:4318"},
		Logs:    IngestSignalConfig{URL: "http://receiver.example.com:4318"},
		Traces:  IngestSignalConfig{URL: "http://traces.example.com:4318"},
	})
	app.WithRoutes().WithIngest()

	write := registeredRoutes(t, app.w)
	assert.Equal(t, map[string]bool{
		"GET /healthz":     true,
		"POST /v1/metrics": true,
		"POST /v1/logs":    true,
		"POST /v1/traces":  true,
	}, write)

	read := registeredRoutes(t, app.e)
	assert.NotEmpty(t, read)
	for route := range read {
		assert.NotContains(t, route, "/v1/metrics")
		assert.NotContains(t, route, "/v1/logs")
		assert.NotContains(t, route, "/v1/traces")
	}
}

// A signal with no upstream is not routed, so a push for it is a 404 rather than an
// error from a missing upstream.
func TestIngestRoutesOnlyForConfiguredSignals(t *testing.T) {
	app := ingestRoutesApp(IngestConfig{
		Enabled: true,
		Metrics: IngestSignalConfig{URL: "http://receiver.example.com:4318"},
		Logs:    IngestSignalConfig{URL: "http://receiver.example.com:4318"},
	})
	app.WithIngest()

	got := registeredRoutes(t, app.w)
	assert.True(t, got["POST /v1/metrics"])
	assert.True(t, got["POST /v1/logs"])
	assert.False(t, got["POST /v1/traces"])
}

func TestIngestDisabledBuildsNoRouter(t *testing.T) {
	app := ingestRoutesApp(IngestConfig{Enabled: false})
	app.WithIngest()
	assert.Nil(t, app.w)
}

// receivedPush is what a fake OTLP receiver saw.
type receivedPush struct {
	path   string
	header http.Header
	body   []byte
}

// fakeReceiver is an OTLP/HTTP upstream that records each request and answers with
// the given status and body.
func fakeReceiver(t *testing.T, status int, respBody string) (*httptest.Server, chan receivedPush) {
	t.Helper()
	got := make(chan receivedPush, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got <- receivedPush{path: r.URL.Path, header: r.Header.Clone(), body: body}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(respBody))
	}))
	t.Cleanup(srv.Close)
	return srv, got
}

// ingestHandlerApp is a full test app (real JWT validation) with the ingest proxies and
// write router built, forwarding metrics and logs to upstreamURL.
func ingestHandlerApp(t *testing.T, writers map[string]string, upstreamURL string, mutate ...func(*IngestConfig)) (*App, map[string]string) {
	t.Helper()
	app, tokens := setupTestMain()
	app.healthy = true
	app.Cfg.Ingest = IngestConfig{
		Enabled:      true,
		Metrics:      IngestSignalConfig{URL: upstreamURL},
		Logs:         IngestSignalConfig{URL: upstreamURL},
		Writers:      writers,
		MaxBodyBytes: defaultIngestMaxBodyBytes,
	}
	for _, m := range mutate {
		m(&app.Cfg.Ingest)
	}
	app.withIngestProxies()
	app.WithIngest()
	return &app, tokens
}

// okReceiverURL starts a receiver that accepts everything, for tests that only care
// about the gateway's own decisions.
func okReceiverURL(t *testing.T) string {
	srv, _ := fakeReceiver(t, http.StatusOK, "")
	return srv.URL
}

func serveIngest(app *App, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	app.w.ServeHTTP(rec, req)
	return rec
}

func TestIngestHandlerAuth(t *testing.T) {
	app, tokens := ingestHandlerApp(t, map[string]string{"group1": "app-a"}, okReceiverURL(t))

	tests := []struct {
		name     string
		token    string
		wantCode int
		wantBody string
	}{
		{"no token", "", http.StatusForbidden, "no Authorization header found"},
		{"invalid token", "not-a-jwt", http.StatusForbidden, "error parsing token"},
		{"no writer group", tokens["noGroupsTenant"], http.StatusForbidden, errNoIngestRole.Error()},
		{"writer group", tokens["groupTenant"], http.StatusOK, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/v1/metrics", nil)
			if tt.token != "" {
				req.Header.Set("Authorization", "Bearer "+tt.token)
			}
			rec := serveIngest(app, req)
			assert.Equal(t, tt.wantCode, rec.Code)
			assert.Contains(t, rec.Body.String(), tt.wantBody)
		})
	}
}

func TestIngestHandlerAmbiguousWriter(t *testing.T) {
	app, tokens := ingestHandlerApp(t, map[string]string{"group1": "app-a", "group2": "app-b"}, okReceiverURL(t))

	req := httptest.NewRequest(http.MethodPost, "/v1/logs", nil)
	req.Header.Set("Authorization", "Bearer "+tokens["groupsTenant"])
	rec := serveIngest(app, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), errAmbiguousIngestRole.Error())
}

// Holding the admin group grants nothing on the write path.
func TestIngestHandlerAdminIsNotAWriter(t *testing.T) {
	app, tokens := ingestHandlerApp(t, map[string]string{"group1": "app-a"}, okReceiverURL(t))
	app.Cfg.Admin = AdminConfig{Bypass: true, Group: "admins"}

	req := httptest.NewRequest(http.MethodPost, "/v1/metrics", nil)
	req.Header.Set("Authorization", "Bearer "+tokens["adminUserToken"])
	rec := serveIngest(app, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
}

// The write path is JWT-only: a trusted CN header must not stand in for a token, even
// with trusted-header identity enabled for the read path.
func TestIngestHandlerIgnoresTrustedClientHeader(t *testing.T) {
	app, _ := ingestHandlerApp(t, map[string]string{"svc-writer": "app-a"}, okReceiverURL(t))
	app.Cfg.Auth.TrustedClientHeader = TrustedClientHeaderConfig{Enabled: true, CNHeader: "X-Client-CN"}

	req := httptest.NewRequest(http.MethodPost, "/v1/metrics", nil)
	req.Header.Set("X-Client-CN", "svc-writer")
	rec := serveIngest(app, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestIngestRouterRefusesEverythingElse(t *testing.T) {
	app, tokens := ingestHandlerApp(t, map[string]string{"group1": "app-a"}, okReceiverURL(t))

	tests := []struct {
		name     string
		method   string
		path     string
		wantCode int
	}{
		{"healthz needs no auth", http.MethodGet, "/healthz", http.StatusOK},
		{"read route is not served", http.MethodGet, "/api/v1/query?query=up", http.StatusNotFound},
		{"log query is not served", http.MethodGet, "/loki/api/v1/query_range", http.StatusNotFound},
		{"unrouted signal", http.MethodPost, "/v1/traces", http.StatusNotFound},
		{"wrong method on push route", http.MethodGet, "/v1/metrics", http.StatusMethodNotAllowed},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			req.Header.Set("Authorization", "Bearer "+tokens["groupTenant"])
			rec := serveIngest(app, req)
			assert.Equal(t, tt.wantCode, rec.Code)
		})
	}
}

func TestIngestHealthzReflectsHealth(t *testing.T) {
	app, _ := ingestHandlerApp(t, map[string]string{"group1": "app-a"}, okReceiverURL(t))
	app.healthy = false

	rec := serveIngest(app, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

// writeTestKeyPair writes a self-signed server certificate and key to dir.
func writeTestKeyPair(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ingest.example.com"},
		DNSNames:     []string{"ingest.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)

	certPath = filepath.Join(dir, "tls.crt")
	keyPath = filepath.Join(dir, "tls.key")
	require.NoError(t, os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600))
	return certPath, keyPath
}

func TestBuildIngestServer(t *testing.T) {
	certPath, keyPath := writeTestKeyPair(t, t.TempDir())
	app := &App{Cfg: &Config{Ingest: IngestConfig{ServerCert: certPath, ServerKey: keyPath}}}

	srv, err := app.buildIngestServer(":0", mux.NewRouter())
	require.NoError(t, err)

	// No client certificate is requested, so none can be used as identity.
	assert.Equal(t, tls.NoClientCert, srv.TLSConfig.ClientAuth)
	assert.Equal(t, uint16(tls.VersionTLS12), srv.TLSConfig.MinVersion)
	assert.Len(t, srv.TLSConfig.Certificates, 1)
	assert.Equal(t, ingestReadHeaderTimeout, srv.ReadHeaderTimeout)
	assert.Equal(t, ingestReadTimeout, srv.ReadTimeout)
	assert.Equal(t, ingestWriteTimeout, srv.WriteTimeout)
	assert.Equal(t, ingestIdleTimeout, srv.IdleTimeout)
}

// End to end over a real TLS listener: the probe answers, a read route does not.
func TestIngestServerOverTLS(t *testing.T) {
	app, _ := ingestHandlerApp(t, map[string]string{"group1": "app-a"}, okReceiverURL(t))
	app.Cfg.Ingest.ServerCert, app.Cfg.Ingest.ServerKey = writeTestKeyPair(t, t.TempDir())

	srv, err := app.buildIngestServer("127.0.0.1:0", app.w)
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

	resp, err = client.Post(base+"/v1/metrics", "application/x-protobuf", nil)
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestBuildIngestServerMissingKeyPair(t *testing.T) {
	dir := t.TempDir()
	app := &App{Cfg: &Config{Ingest: IngestConfig{
		ServerCert: filepath.Join(dir, "missing.crt"),
		ServerKey:  filepath.Join(dir, "missing.key"),
	}}}
	_, err := app.buildIngestServer(":0", mux.NewRouter())
	assert.ErrorContains(t, err, "ingest server keypair")
}

// The read and write listeners each record HTTP metrics; on a shared registry the write
// listener's must not collide with the read listener's.
func TestIngestHTTPMetricsCoexistWithReadMetrics(t *testing.T) {
	reg := prometheus.NewRegistry()
	assert.NotPanics(t, func() {
		middleware.New(middleware.Config{
			Recorder: metrics.NewRecorder(metrics.Config{Registry: reg}),
			Service:  "lgtm_lbac_proxy",
		})
		ingestHTTPMetrics(reg)
	})
}

// counterValue reads a counter's current value.
func counterValue(c prometheus.Counter) float64 {
	m := &dto.Metric{}
	_ = c.Write(m)
	return m.GetCounter().GetValue()
}

func gzipped(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, err := zw.Write(b)
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	return buf.Bytes()
}

func receive(t *testing.T, got chan receivedPush) receivedPush {
	t.Helper()
	select {
	case p := <-got:
		return p
	case <-time.After(5 * time.Second):
		t.Fatal("upstream received nothing")
		return receivedPush{}
	}
}

// The body reaches the upstream untouched, whatever its encoding, with the writer id in
// the writer header and none of the caller's credentials.
func TestIngestForwardsBodyUnchanged(t *testing.T) {
	protobuf := []byte{0x0a, 0x03, 0x01, 0x02, 0x03, 0x00, 0xff}
	tests := []struct {
		name        string
		contentType string
		encoding    string
		body        []byte
	}{
		{"protobuf", "application/x-protobuf", "", protobuf},
		{"json", "application/json", "", []byte(`{"resourceMetrics":[]}`)},
		{"gzip protobuf", "application/x-protobuf", "gzip", gzipped(t, protobuf)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, got := fakeReceiver(t, http.StatusOK, "")
			app, tokens := ingestHandlerApp(t, map[string]string{"group1": "app-a"}, srv.URL)

			req := httptest.NewRequest(http.MethodPost, "/v1/metrics", bytes.NewReader(tt.body))
			req.Header.Set("Authorization", "Bearer "+tokens["groupTenant"])
			req.Header.Set("Content-Type", tt.contentType)
			if tt.encoding != "" {
				req.Header.Set("Content-Encoding", tt.encoding)
			}
			rec := serveIngest(app, req)
			require.Equal(t, http.StatusOK, rec.Code)

			p := receive(t, got)
			assert.Equal(t, "/v1/metrics", p.path)
			assert.Equal(t, tt.body, p.body, "body must be forwarded byte for byte")
			assert.Equal(t, tt.contentType, p.header.Get("Content-Type"))
			assert.Equal(t, tt.encoding, p.header.Get("Content-Encoding"))
			assert.Equal(t, []string{"app-a"}, p.header.Values(defaultIngestWriterHeader))
			assert.Empty(t, p.header.Get("Authorization"), "the caller's token must not reach the upstream")
		})
	}
}

// A writer header supplied by the caller is replaced, never passed through or appended
// to: it is the one assertion the upstream trusts.
func TestIngestOverwritesClientWriterHeader(t *testing.T) {
	srv, got := fakeReceiver(t, http.StatusOK, "")
	app, tokens := ingestHandlerApp(t, map[string]string{"group1": "app-a"}, srv.URL)

	req := httptest.NewRequest(http.MethodPost, "/v1/logs", strings.NewReader("x"))
	req.Header.Set("Authorization", "Bearer "+tokens["groupTenant"])
	req.Header.Add("x-ingest-writer", "app-b")
	req.Header.Add("X-INGEST-WRITER", "app-c")
	rec := serveIngest(app, req)
	require.Equal(t, http.StatusOK, rec.Code)

	assert.Equal(t, []string{"app-a"}, receive(t, got).header.Values(defaultIngestWriterHeader))
}

// For a multi-tenant backend the writer header can be its own tenant header.
func TestIngestCustomWriterHeader(t *testing.T) {
	srv, got := fakeReceiver(t, http.StatusOK, "")
	app, tokens := ingestHandlerApp(t, map[string]string{"group1": "app-a"}, srv.URL,
		func(c *IngestConfig) { c.WriterHeader = "X-Scope-OrgID" })

	req := httptest.NewRequest(http.MethodPost, "/v1/metrics", strings.NewReader("x"))
	req.Header.Set("Authorization", "Bearer "+tokens["groupTenant"])
	req.Header.Set("X-Scope-OrgID", "someone-else")
	rec := serveIngest(app, req)
	require.Equal(t, http.StatusOK, rec.Code)

	p := receive(t, got)
	assert.Equal(t, []string{"app-a"}, p.header.Values("X-Scope-OrgID"))
	assert.Empty(t, p.header.Get(defaultIngestWriterHeader))
}

// An upstream mounted under a prefix keeps it, and each signal goes to its own upstream.
func TestIngestUpstreamBasePathAndPerSignalUpstreams(t *testing.T) {
	metricsSrv, metricsGot := fakeReceiver(t, http.StatusOK, "")
	tracesSrv, tracesGot := fakeReceiver(t, http.StatusOK, "")
	app, tokens := ingestHandlerApp(t, map[string]string{"group1": "app-a"}, metricsSrv.URL+"/otlp",
		func(c *IngestConfig) { c.Traces.URL = tracesSrv.URL })

	for _, path := range []string{"/v1/metrics", "/v1/traces"} {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader("x"))
		req.Header.Set("Authorization", "Bearer "+tokens["groupTenant"])
		require.Equal(t, http.StatusOK, serveIngest(app, req).Code)
	}

	assert.Equal(t, "/otlp/v1/metrics", receive(t, metricsGot).path)
	assert.Equal(t, "/v1/traces", receive(t, tracesGot).path)
}

// The upstream's answer is the client's answer, including partial-success and
// throttling responses the client's exporter acts on.
func TestIngestRelaysUpstreamResponse(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusBadRequest, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			srv, _ := fakeReceiver(t, status, "upstream says hi")
			app, tokens := ingestHandlerApp(t, map[string]string{"group1": "app-a"}, srv.URL)

			req := httptest.NewRequest(http.MethodPost, "/v1/metrics", strings.NewReader("x"))
			req.Header.Set("Authorization", "Bearer "+tokens["groupTenant"])
			rec := serveIngest(app, req)

			assert.Equal(t, status, rec.Code)
			assert.Equal(t, "upstream says hi", rec.Body.String())
		})
	}
}

func TestIngestUnreachableUpstream(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()
	app, tokens := ingestHandlerApp(t, map[string]string{"group1": "app-a"}, url)
	before := counterValue(ingestRejected.WithLabelValues(signalMetrics, rejectUpstreamError))

	req := httptest.NewRequest(http.MethodPost, "/v1/metrics", strings.NewReader("x"))
	req.Header.Set("Authorization", "Bearer "+tokens["groupTenant"])
	rec := serveIngest(app, req)

	assert.Equal(t, http.StatusBadGateway, rec.Code)
	assert.Equal(t, before+1, counterValue(ingestRejected.WithLabelValues(signalMetrics, rejectUpstreamError)))
}

func TestIngestBodySizeCap(t *testing.T) {
	const limit = 16
	big := bytes.Repeat([]byte("a"), limit+1)

	t.Run("declared length over the cap is refused before forwarding", func(t *testing.T) {
		srv, got := fakeReceiver(t, http.StatusOK, "")
		app, tokens := ingestHandlerApp(t, map[string]string{"group1": "app-a"}, srv.URL,
			func(c *IngestConfig) { c.MaxBodyBytes = limit })

		req := httptest.NewRequest(http.MethodPost, "/v1/metrics", bytes.NewReader(big))
		req.Header.Set("Authorization", "Bearer "+tokens["groupTenant"])
		rec := serveIngest(app, req)

		assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
		assert.Empty(t, got, "nothing should reach the upstream")
	})

	t.Run("undeclared length overrunning the cap is cut off", func(t *testing.T) {
		app, tokens := ingestHandlerApp(t, map[string]string{"group1": "app-a"}, okReceiverURL(t),
			func(c *IngestConfig) { c.MaxBodyBytes = limit })

		req := httptest.NewRequest(http.MethodPost, "/v1/metrics", io.NopCloser(bytes.NewReader(big)))
		req.ContentLength = -1
		req.Header.Set("Authorization", "Bearer "+tokens["groupTenant"])
		rec := serveIngest(app, req)

		assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
	})

	t.Run("at the cap is accepted", func(t *testing.T) {
		app, tokens := ingestHandlerApp(t, map[string]string{"group1": "app-a"}, okReceiverURL(t),
			func(c *IngestConfig) { c.MaxBodyBytes = limit })

		req := httptest.NewRequest(http.MethodPost, "/v1/metrics", bytes.NewReader(big[:limit]))
		req.Header.Set("Authorization", "Bearer "+tokens["groupTenant"])
		assert.Equal(t, http.StatusOK, serveIngest(app, req).Code)
	})
}

func TestIngestMetrics(t *testing.T) {
	app, tokens := ingestHandlerApp(t, map[string]string{"group1": "app-a"}, okReceiverURL(t))
	forwarded := ingestRequests.WithLabelValues("app-a", signalLogs, "200")
	bytesRead := ingestRequestBytes.WithLabelValues("app-a", signalLogs)
	noRole := ingestRejected.WithLabelValues(signalLogs, rejectNoRole)
	unauth := ingestRejected.WithLabelValues(signalLogs, rejectUnauthenticated)
	f0, b0, n0, u0 := counterValue(forwarded), counterValue(bytesRead), counterValue(noRole), counterValue(unauth)

	req := httptest.NewRequest(http.MethodPost, "/v1/logs", strings.NewReader("12345"))
	req.Header.Set("Authorization", "Bearer "+tokens["groupTenant"])
	serveIngest(app, req)

	req = httptest.NewRequest(http.MethodPost, "/v1/logs", nil)
	req.Header.Set("Authorization", "Bearer "+tokens["noGroupsTenant"])
	serveIngest(app, req)

	serveIngest(app, httptest.NewRequest(http.MethodPost, "/v1/logs", nil))

	assert.Equal(t, f0+1, counterValue(forwarded))
	assert.Equal(t, b0+5, counterValue(bytesRead))
	assert.Equal(t, n0+1, counterValue(noRole))
	assert.Equal(t, u0+1, counterValue(unauth))
}
