package main

import (
	"crypto/tls"
	"testing"
	"time"
)

// BenchmarkProxyFieldAccess benchmarks direct proxy field access (zero overhead expected)
func BenchmarkProxyFieldAccess(b *testing.B) {
	app := &App{}
	app.WithConfig()
	app.Cfg().Loki.URL = "http://loki:3100"
	app.TlS = &tls.Config{InsecureSkipVerify: true}
	app.WithProxies()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = app.lokiProxy
	}
}

// BenchmarkGetProxyConfigDefaults benchmarks proxy config retrieval with defaults
func BenchmarkGetProxyConfigDefaults(b *testing.B) {
	cfg := &Config{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cfg.GetProxyConfig(nil)
	}
}

// BenchmarkGetProxyConfigWithGlobalOverrides benchmarks proxy config with global overrides
func BenchmarkGetProxyConfigWithGlobalOverrides(b *testing.B) {
	cfg := &Config{
		Proxy: ProxyConfig{
			RequestTimeout:      120 * time.Second,
			MaxIdleConnsPerHost: 200,
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cfg.GetProxyConfig(nil)
	}
}

// BenchmarkGetProxyConfigWithUpstreamOverrides benchmarks proxy config with upstream overrides
func BenchmarkGetProxyConfigWithUpstreamOverrides(b *testing.B) {
	cfg := &Config{
		Proxy: ProxyConfig{
			RequestTimeout:      60 * time.Second,
			MaxIdleConnsPerHost: 100,
		},
	}

	upstreamCfg := &ProxyConfig{
		RequestTimeout:      300 * time.Second,
		MaxIdleConnsPerHost: 50,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cfg.GetProxyConfig(upstreamCfg)
	}
}

// BenchmarkCreateTransport benchmarks HTTP transport creation
func BenchmarkCreateTransport(b *testing.B) {
	app := &App{}
	tlsConfig := &tls.Config{InsecureSkipVerify: true}
	proxyCfg := ProxyConfig{
		RequestTimeout:      60 * time.Second,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		MaxIdleConns:        500,
		MaxIdleConnsPerHost: 100,
		ForceHTTP2:          true,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = app.createTransport(proxyCfg, tlsConfig)
	}
}

// BenchmarkProxyInitialization benchmarks proxy initialization (creates proxy + transport)
func BenchmarkProxyInitialization(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		app := &App{}
		app.WithConfig()
		app.Cfg().Loki.URL = "http://loki:3100"
		app.TlS = &tls.Config{InsecureSkipVerify: true}
		app.WithProxies()
	}
}

// BenchmarkProxyInitializationAllUpstreams benchmarks initialization with all 3 upstreams
func BenchmarkProxyInitializationAllUpstreams(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		app := &App{}
		app.WithConfig()
		app.Cfg().Loki.URL = "http://loki:3100"
		app.Cfg().Thanos.URL = "http://thanos:9090"
		app.Cfg().Tempo.URL = "http://tempo:3200"
		app.TlS = &tls.Config{InsecureSkipVerify: true}
		app.WithProxies()
	}
}
