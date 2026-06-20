package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestCreateProxyJoinsUpstreamBasePath verifies the Director prepends a configured
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
			proxy.Director(req)
			if req.URL.Path != tc.wantPath {
				t.Errorf("path = %q, want %q", req.URL.Path, tc.wantPath)
			}
		})
	}
}
