package main

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestApp returns an App serving cfg.
func newTestApp(cfg *Config) *App {
	a := &App{}
	a.SetConfig(cfg)
	return a
}

const reloadBaseConfig = `
log:
  level: 1
web:
  proxy_port: 8080
  metrics_port: 8081
auth:
  audiences: ["api://lbac"]
alerting:
  viewer_groups: ["viewers"]
`

// withConfigFile points the loader at a temporary config.yaml holding body and returns
// a function that rewrites it.
func withConfigFile(t *testing.T, body string) func(string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	write := func(b string) { require.NoError(t, os.WriteFile(path, []byte(b), 0o600)) }
	write(body)
	saved := configSearchPaths
	configSearchPaths = []string{dir}
	t.Cleanup(func() { configSearchPaths = saved })
	return write
}

// loadedApp is an App serving the config file, loaded the way WithConfig loads it but
// without starting a file watcher.
func loadedApp(t *testing.T) *App {
	t.Helper()
	cfg, err := readConfig()
	require.NoError(t, err)
	return newTestApp(cfg)
}

func gaugeValue(g prometheus.Gauge) float64 {
	m := &dto.Metric{}
	_ = g.Write(m)
	return m.GetGauge().GetValue()
}

// A reload that fails validation never exits and never half-applies: the previous
// Config keeps serving, untouched, and the rejection is counted.
func TestReloadRejectsBadConfigAndKeepsServing(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"unparseable yaml", "web: [unclosed\n"},
		{"invalid ingest", reloadBaseConfig + "ingest:\n  enabled: true\n  port: 8444\n"},
		{"invalid client_cert admission (used to log.Fatal)", `
log:
  level: 1
web:
  proxy_port: 8080
  metrics_port: 8081
auth:
  audiences: ["api://lbac"]
  client_cert:
    enabled: true
    admission:
      rules:
        - field: nonsense
          operator: "="
          values: ["x"]
alerting:
  viewer_groups: ["viewers"]
`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			write := withConfigFile(t, reloadBaseConfig)
			app := loadedApp(t)
			before := app.Cfg()
			rejected := counterValue(configReloads.WithLabelValues(reloadRejected))

			write(tt.body)
			app.reloadConfig()

			assert.Same(t, before, app.Cfg(), "the previous configuration must keep serving")
			assert.Equal(t, []string{"viewers"}, app.Cfg().Alerting.ViewerGroups, "and must be unchanged")
			assert.Equal(t, rejected+1, counterValue(configReloads.WithLabelValues(reloadRejected)))
			assert.Equal(t, 0.0, gaugeValue(configLastReloadSuccessful))
		})
	}
}

// A valid reload publishes a new Config built from scratch, so a setting removed from
// the file is gone rather than lingering from the old one.
func TestReloadAppliesAndClearsRemovedSettings(t *testing.T) {
	write := withConfigFile(t, reloadBaseConfig)
	app := loadedApp(t)
	before := app.Cfg()
	applied := counterValue(configReloads.WithLabelValues(reloadApplied))

	write(`
log:
  level: 1
web:
  proxy_port: 8080
  metrics_port: 8081
auth:
  audiences: ["api://lbac", "lbac"]
`)
	app.reloadConfig()

	after := app.Cfg()
	assert.NotSame(t, before, after, "a reload publishes a new Config")
	assert.Equal(t, []string{"api://lbac", "lbac"}, after.Auth.Audiences)
	assert.Empty(t, after.Alerting.ViewerGroups, "removed from the file, so removed from the config")
	assert.Equal(t, []string{"viewers"}, before.Alerting.ViewerGroups, "the old Config is never modified")
	assert.Equal(t, applied+1, counterValue(configReloads.WithLabelValues(reloadApplied)))
	assert.Equal(t, 1.0, gaugeValue(configLastReloadSuccessful))
}

// Requests read the config while reloads publish new ones. Under -race this fails on
// the old in-place Unmarshal; with publish-by-swap there is nothing to race on.
func TestReloadWhileRequestsReadConfig(t *testing.T) {
	write := withConfigFile(t, reloadBaseConfig+"ingest:\n  writers:\n    group-a: app-a\n")
	app := loadedApp(t)

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				cfg := app.Cfg()
				_ = len(cfg.Auth.Audiences)
				for group, id := range cfg.Ingest.Writers {
					_, _ = group, id
				}
			}
		}()
	}
	for i := 0; i < 50; i++ {
		if i%2 == 0 {
			write(reloadBaseConfig + "ingest:\n  writers:\n    group-a: app-a\n    group-b: app-b\n")
		} else {
			write(reloadBaseConfig + "ingest:\n  writers:\n    group-c: app-c\n")
		}
		app.reloadConfig()
	}
	close(stop)
	wg.Wait()
	assert.Equal(t, map[string]string{"group-c": "app-c"}, app.Cfg().Ingest.Writers)
}

func TestRestartOnlyChanges(t *testing.T) {
	base := func() *Config {
		return &Config{
			Web:    WebConfig{ProxyPort: 8080, MetricsPort: 8081},
			Thanos: ThanosConfig{URL: "http://thanos.example.com:9090"},
			Ingest: IngestConfig{Enabled: true, Port: 8444, Writers: map[string]string{"g": "app-a"}},
		}
	}
	tests := []struct {
		name   string
		mutate func(*Config)
		want   []string
	}{
		{"nothing changed", func(*Config) {}, nil},
		{"per-request settings only", func(c *Config) {
			c.Ingest.Writers = map[string]string{"g": "app-b"}
			c.Alerting.ViewerGroups = []string{"v"}
			c.Auth.Audiences = []string{"a"}
		}, nil},
		{"proxy port", func(c *Config) { c.Web.ProxyPort = 9090 }, []string{"web.proxy_port"}},
		{"upstream url", func(c *Config) { c.Thanos.URL = "http://mimir.example.com/prometheus" }, []string{"thanos"}},
		{"ingest listener", func(c *Config) { c.Ingest.Port = 9444 }, []string{"ingest listener and upstreams"}},
		{"jwks and alerting routes", func(c *Config) {
			c.Auth.JwksCertURL = "https://idp.example.com/keys"
			c.Alerting.Enabled = true
		}, []string{"auth.jwks_cert_url", "alerting.enabled"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			next := base()
			tt.mutate(next)
			assert.Equal(t, tt.want, restartOnlyChanges(base(), next))
		})
	}
	assert.Nil(t, restartOnlyChanges(nil, base()), "no previous config, nothing to compare")
}
