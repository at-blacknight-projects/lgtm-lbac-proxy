package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"testing"
)

// rewrite runs the proxy's Rewrite on req the way ReverseProxy does and returns the
// outbound request.
func rewrite(proxy *httputil.ReverseProxy, req *http.Request) *http.Request {
	out := req.Clone(req.Context())
	// ReverseProxy strips these before calling Rewrite.
	out.Header.Del("X-Forwarded-For")
	out.Header.Del("X-Forwarded-Host")
	out.Header.Del("X-Forwarded-Proto")
	proxy.Rewrite(&httputil.ProxyRequest{In: req, Out: out})
	return out
}

// TestCreateProxyJoinsUpstreamBasePath verifies the Rewrite prepends a configured
// upstream base path (e.g. Mimir's /prometheus) to the incoming request path, while
// leaving paths unchanged when the upstream URL has no base path (Thanos/Loki at root).
func TestCreateProxyJoinsUpstreamBasePath(t *testing.T) {
	app := &App{}
	tr := &http.Transport{}

	tests := []struct {
		name        string
		upstreamURL string
		inPath      string
		wantPath    string
	}{
		{
			name:        "mimir prometheus prefix is prepended",
			upstreamURL: "http://mimir-gateway/prometheus",
			inPath:      "/api/v1/query",
			wantPath:    "/prometheus/api/v1/query",
		},
		{
			name:        "trailing slash on base path does not double up",
			upstreamURL: "http://mimir-gateway/prometheus/",
			inPath:      "/api/v1/labels",
			wantPath:    "/prometheus/api/v1/labels",
		},
		{
			name:        "no base path leaves incoming path unchanged (thanos at root)",
			upstreamURL: "http://thanos-querier:9091",
			inPath:      "/api/v1/query",
			wantPath:    "/api/v1/query",
		},
		{
			name:        "bare slash base path leaves incoming path unchanged",
			upstreamURL: "http://loki:3100/",
			inPath:      "/loki/api/v1/query",
			wantPath:    "/loki/api/v1/query",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			proxy := app.createProxy(tc.upstreamURL, "", tr, "test")
			req := httptest.NewRequest(http.MethodGet, "http://proxy"+tc.inPath, nil)
			out := rewrite(proxy, req)
			if out.URL.Path != tc.wantPath {
				t.Errorf("path = %q, want %q", out.URL.Path, tc.wantPath)
			}
		})
	}
}

// TestCreateProxyForwardsHeaders sends real requests through the proxy to a stub upstream
// and pins what arrives: the upstream Host, the client's X-Forwarded-For chain with this
// hop appended, and the actor header from the username, falling back to the email.
func TestCreateProxyForwardsHeaders(t *testing.T) {
	var got *http.Request
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r
	}))
	defer upstream.Close()

	app := &App{}
	proxy := app.createProxy(upstream.URL, "X-Actor", &http.Transport{}, "test")
	send := func(ctx context.Context, forwardedFor string) {
		t.Helper()
		got = nil
		req := httptest.NewRequest(http.MethodGet, "http://proxy.example.com/loki/api/v1/query", nil)
		req.RemoteAddr = "192.0.2.10:51000"
		if forwardedFor != "" {
			req.Header.Set("X-Forwarded-For", forwardedFor)
		}
		proxy.ServeHTTP(httptest.NewRecorder(), req.WithContext(ctx))
		if got == nil {
			t.Fatal("request did not reach the upstream")
		}
	}

	t.Run("host, forwarded chain and username actor", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), ctxKeyUsername, "alice")
		ctx = context.WithValue(ctx, ctxKeyEmail, "alice@example.com")
		send(ctx, "198.51.100.7")

		if want := upstream.Listener.Addr().String(); got.Host != want {
			t.Errorf("Host = %q, want the upstream %q", got.Host, want)
		}
		if h := got.Header.Get("X-Forwarded-For"); h != "198.51.100.7, 192.0.2.10" {
			t.Errorf("X-Forwarded-For = %q, want the client chain with this hop appended", h)
		}
		if h := got.Header.Get("X-Actor"); h != "alice" {
			t.Errorf("X-Actor = %q, want the username", h)
		}
	})

	t.Run("email when there is no username", func(t *testing.T) {
		send(context.WithValue(context.Background(), ctxKeyEmail, "bob@example.com"), "")
		if h := got.Header.Get("X-Actor"); h != "bob@example.com" {
			t.Errorf("X-Actor = %q, want the email", h)
		}
		if h := got.Header.Get("X-Forwarded-For"); h != "192.0.2.10" {
			t.Errorf("X-Forwarded-For = %q, want just this hop", h)
		}
	})

	t.Run("a plain string key cannot set the actor", func(t *testing.T) {
		send(context.WithValue(context.Background(), "username", "mallory"), "") //nolint:staticcheck // the collision under test
		if h := got.Header.Get("X-Actor"); h != "" {
			t.Errorf("X-Actor = %q, want none", h)
		}
	})
}
