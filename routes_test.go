package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSetActorHeaderLogQL(t *testing.T) {
	app := &App{
		Cfg: &Config{
			Loki: LokiConfig{
				ActorHeader: "X-Actor",
			},
		},
	}
	token := OAuthToken{
		PreferredUsername: "user",
		Email:             "user@example.com",
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	err := setActorHeaderLogQL(req, token, app)
	assert.NoError(t, err)
	assert.Equal(t, "dXNlcnVzZXJAZXhhbXBsZS5jb20=", req.Header.Get("X-Actor"))
	fmt.Println(req.Header)
}

func TestSetActorHeaderPromQL(t *testing.T) {
	app := &App{
		Cfg: &Config{
			Thanos: ThanosConfig{
				ActorHeader: "X-Actor",
			},
		},
	}
	token := OAuthToken{
		PreferredUsername: "user",
		Email:             "user@example.com",
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	err := setActorHeaderPromQL(req, token, app)
	assert.NoError(t, err)
	assert.Equal(t, "dXNlcnVzZXJAZXhhbXBsZS5jb20=", req.Header.Get("X-Actor"))
}

// Clients that treat the proxy as a Prometheus server probe /-/healthy (and
// sometimes /-/ready) before querying and give up on anything but a 200. They
// must be answered on the proxy router, without credentials, and follow the
// same liveness state as /healthz.
func TestPrometheusHealthRoutes(t *testing.T) {
	app := &App{Cfg: &Config{}}
	app = app.WithHealthz().WithRoutes()

	for _, path := range []string{"/-/healthy", "/-/ready"} {
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			t.Run(method+" "+path+" healthy", func(t *testing.T) {
				app.healthy = true
				rec := httptest.NewRecorder()
				// Deliberately no Authorization header and no client certificate.
				app.e.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
				assert.Equal(t, http.StatusOK, rec.Code)
			})

			t.Run(method+" "+path+" unhealthy", func(t *testing.T) {
				app.healthy = false
				rec := httptest.NewRecorder()
				app.e.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
				assert.Equal(t, http.StatusInternalServerError, rec.Code)
			})
		}
	}

	t.Run("not writable", func(t *testing.T) {
		app.healthy = true
		rec := httptest.NewRecorder()
		app.e.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/-/healthy", nil))
		assert.NotEqual(t, http.StatusOK, rec.Code)
	})
}

// The health endpoints must not open a path past authentication: the query API
// still refuses a caller with no credentials once they are registered.
func TestPrometheusHealthDoesNotBypassQueryAuth(t *testing.T) {
	app := &App{Cfg: &Config{
		Thanos: ThanosConfig{URL: "http://thanos.example.com"},
		Web:    WebConfig{AuthHeader: "Authorization"},
	}}
	app = app.WithHealthz().WithRoutes()

	rec := httptest.NewRecorder()
	app.e.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/query?query=up", nil))
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestWithHealthz(t *testing.T) {
	app := &App{
		Cfg: &Config{
			Alert: AlertConfig{
				Enabled: false,
			},
		},
	}

	app = app.WithHealthz()

	ts := httptest.NewServer(app.i)
	defer ts.Close()

	t.Run("Healthz OK", func(t *testing.T) {
		app.healthy = true
		resp, err := http.Get(ts.URL + "/healthz")
		if err != nil {
			t.Fatalf("Failed to send GET request: %v", err)
		}
		defer func(Body io.ReadCloser) {
			err := Body.Close()
			if err != nil {
				t.Fatalf("Failed to close response body: %v", err)
			}
		}(resp.Body)

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status %d, got %d", http.StatusOK, resp.StatusCode)
		}
	})

	t.Run("Healthz Not OK", func(t *testing.T) {
		app.healthy = false
		resp, err := http.Get(ts.URL + "/healthz")
		if err != nil {
			t.Fatalf("Failed to send GET request: %v", err)
		}
		defer func(Body io.ReadCloser) {
			err := Body.Close()
			if err != nil {
				t.Fatalf("Failed to close response body: %v", err)
			}
		}(resp.Body)

		if resp.StatusCode != http.StatusInternalServerError {
			t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, resp.StatusCode)
		}
	})

	t.Run("Metrics endpoint", func(t *testing.T) {
		resp, err := http.Get(ts.URL + "/metrics")
		if err != nil {
			t.Fatalf("Failed to send GET request: %v", err)
		}
		defer func(Body io.ReadCloser) {
			err := Body.Close()
			if err != nil {
				t.Fatalf("Failed to close response body: %v", err)
			}
		}(resp.Body)

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status %d, got %d", http.StatusOK, resp.StatusCode)
		}
	})
}
