package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"runtime"
	"strings"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/rs/zerolog/pkgerrors"

	metrics "github.com/slok/go-http-metrics/metrics/prometheus"
	"github.com/slok/go-http-metrics/middleware"
	"github.com/slok/go-http-metrics/middleware/std"
)

type App struct {
	Jwks                keyfunc.Keyfunc
	Cfg                 *Config
	TlS                 *tls.Config
	ServiceAccountToken string
	LabelStore          Labelstore
	lokiProxy           *httputil.ReverseProxy
	thanosProxy         *httputil.ReverseProxy
	tempoProxy          *httputil.ReverseProxy
	i                   *mux.Router
	e                   *mux.Router
	healthy             bool
}

var Commit string

func main() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	zerolog.ErrorStackMarshaler = pkgerrors.MarshalStack
	log.Info().Msg("-------Init Proxy-------")
	log.Info().Msgf("Commit: %s", Commit)
	log.Debug().Str("go_version", runtime.Version()).Msg("")
	log.Debug().Str("go_os", runtime.GOOS).Str("go_arch", runtime.GOARCH).Msg("")
	log.Debug().Str("go_compiler", runtime.Compiler).Msg("")

	app := App{}
	app.WithConfig().
		WithSAT().
		WithTLSConfig().
		WithJWKS().
		WithLabelStore().
		WithProxies().
		WithHealthz().
		WithRoutes().
		StartServer()

	log.Info().Any("config", app.Cfg)
	log.Info().Msg("------Init Complete------")
	select {}
}

// StartServer starts the HTTP server for the proxy and metrics.
func (a *App) StartServer() {
	go func() {
		if err := http.ListenAndServe(fmt.Sprintf("%s:%d", a.Cfg.Web.Host, a.Cfg.Web.MetricsPort), a.i); err != nil {
			log.Fatal().Err(err).Msg("Error while serving metrics")
		}
	}()

	go func() {
		mdlw := middleware.New(middleware.Config{
			Recorder: metrics.NewRecorder(metrics.Config{}),
			Service:  "lgtm_lbac_proxy",
		})

		addr := fmt.Sprintf("%s:%d", a.Cfg.Web.Host, a.Cfg.Web.ProxyPort)
		handler := std.Handler("/", mdlw, a.e)

		// Mode B: terminate mTLS at the proxy so the verified peer certificate is the
		// root of admission. Falls back to plain HTTP when not configured (e.g. JWT-only,
		// or client_cert Source "header" behind an mTLS-terminating ingress).
		cc := a.Cfg.Auth.ClientCert
		if cc.Enabled && cc.Source == "mtls" {
			srv, err := a.buildMTLSServer(addr, handler)
			if err != nil {
				log.Fatal().Err(err).Msg("Error while building mTLS proxy server")
			}
			log.Info().Str("addr", addr).Str("client_auth", cc.ClientAuth).Msg("Serving proxy with mTLS client authentication")
			if err := srv.ListenAndServeTLS("", ""); err != nil {
				log.Fatal().Err(err).Msg("Error while serving proxy")
			}
			return
		}

		if err := http.ListenAndServe(addr, handler); err != nil {
			log.Fatal().Err(err).Msg("Error while serving proxy")
		}
	}()
}

// buildMTLSServer constructs an HTTP server that terminates TLS and authenticates client
// certificates against the configured client CA. The verified peer certificate is then
// available to getIdentity for admission. ClientAuth "require" rejects clients without a
// valid cert at handshake; "request" verifies a cert if given, allowing mixed JWT+mTLS.
func (a *App) buildMTLSServer(addr string, handler http.Handler) (*http.Server, error) {
	cc := a.Cfg.Auth.ClientCert

	serverCert, err := tls.LoadX509KeyPair(cc.ServerCert, cc.ServerKey)
	if err != nil {
		return nil, fmt.Errorf("loading proxy server keypair: %w", err)
	}

	caPEM, err := os.ReadFile(cc.CAPath)
	if err != nil {
		return nil, fmt.Errorf("reading client CA bundle %q: %w", cc.CAPath, err)
	}
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("no certificates found in client CA bundle %q", cc.CAPath)
	}

	return &http.Server{
		Addr:    addr,
		Handler: handler,
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{serverCert},
			ClientCAs:    clientCAs,
			ClientAuth:   clientAuthType(cc.ClientAuth),
		},
	}, nil
}

// clientAuthType maps the configured client_auth string to a tls.ClientAuthType.
// Defaults to RequireAndVerifyClientCert for any unrecognised value.
func clientAuthType(s string) tls.ClientAuthType {
	switch s {
	case "request", "verify_if_given":
		return tls.VerifyClientCertIfGiven
	default:
		return tls.RequireAndVerifyClientCert
	}
}

// WithProxies initializes reverse proxy instances for each configured upstream.
// Each proxy gets its own dedicated transport with per-upstream configuration.
func (a *App) WithProxies() *App {
	log.Info().Msg("Initializing reverse proxies")

	// Initialize Loki proxy if URL is configured
	if a.Cfg.Loki.URL != "" {
		proxyCfg := a.Cfg.GetProxyConfig(a.Cfg.Loki.Proxy)
		transport := a.createTransport(proxyCfg, a.TlS)
		a.lokiProxy = a.createProxy(a.Cfg.Loki.URL, a.Cfg.Loki.ActorHeader, transport, "loki")
		log.Info().
			Str("url", a.Cfg.Loki.URL).
			Dur("request_timeout", proxyCfg.RequestTimeout).
			Int("max_idle_conns_per_host", proxyCfg.MaxIdleConnsPerHost).
			Msg("Loki proxy initialized")
	}

	// Initialize Thanos proxy if URL is configured
	if a.Cfg.Thanos.URL != "" {
		proxyCfg := a.Cfg.GetProxyConfig(a.Cfg.Thanos.Proxy)
		transport := a.createTransport(proxyCfg, a.TlS)
		a.thanosProxy = a.createProxy(a.Cfg.Thanos.URL, a.Cfg.Thanos.ActorHeader, transport, "thanos")
		log.Info().
			Str("url", a.Cfg.Thanos.URL).
			Dur("request_timeout", proxyCfg.RequestTimeout).
			Int("max_idle_conns_per_host", proxyCfg.MaxIdleConnsPerHost).
			Msg("Thanos proxy initialized")
	}

	// Initialize Tempo proxy if URL is configured
	if a.Cfg.Tempo.URL != "" {
		proxyCfg := a.Cfg.GetProxyConfig(a.Cfg.Tempo.Proxy)
		transport := a.createTransport(proxyCfg, a.TlS)
		a.tempoProxy = a.createProxy(a.Cfg.Tempo.URL, a.Cfg.Tempo.ActorHeader, transport, "tempo")
		log.Info().
			Str("url", a.Cfg.Tempo.URL).
			Dur("request_timeout", proxyCfg.RequestTimeout).
			Int("max_idle_conns_per_host", proxyCfg.MaxIdleConnsPerHost).
			Msg("Tempo proxy initialized")
	}

	return a
}

// singleJoiningSlash joins two URL path segments with exactly one separating slash.
// Copied from the standard library's net/http/httputil (where it is unexported), so the
// custom Director can prepend a configured upstream base path the same way
// NewSingleHostReverseProxy does.
func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}

// createProxy creates a reverse proxy with custom Director, ErrorHandler, and ModifyResponse.
// Using direct ReverseProxy instantiation instead of NewSingleHostReverseProxy for better control.
func (a *App) createProxy(targetURL string, actorHeader string, transport *http.Transport, upstream string) *httputil.ReverseProxy {
	target, err := url.Parse(targetURL)
	if err != nil {
		log.Fatal().Err(err).Str("url", targetURL).Str("upstream", upstream).Msg("Failed to parse upstream URL")
	}

	proxy := &httputil.ReverseProxy{
		// Custom Director for URL rewriting and actor header injection
		Director: func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.Host = target.Host

			// Honor a base path on the configured upstream URL so it is prepended to the
			// incoming request path. This is required for upstreams that mount the
			// Prometheus-compatible API under a prefix — notably Mimir, which serves it
			// at /prometheus/api/v1/* (vs Thanos at /api/v1/*) — and also enables
			// sub-path-mounted Loki/Tempo. Backwards-compatible: when the upstream URL has
			// no base path ("" or "/"), the incoming path is forwarded unchanged.
			if target.Path != "" && target.Path != "/" {
				req.URL.Path = singleJoiningSlash(target.Path, req.URL.Path)
				if req.URL.RawPath != "" {
					req.URL.RawPath = singleJoiningSlash(target.Path, req.URL.RawPath)
				}
			}

			// Inject actor header if configured (base64 encoded username for fair usage tracking)
			if actorHeader != "" {
				if username, ok := req.Context().Value("username").(string); ok && username != "" {
					req.Header.Set(actorHeader, username)
				} else if email, ok := req.Context().Value("email").(string); ok && email != "" {
					req.Header.Set(actorHeader, email)
				}
			}

			log.Debug().
				Str("upstream", upstream).
				Str("method", req.Method).
				Str("path", req.URL.Path).
				Msg("Proxying request")
		},

		// Custom ErrorHandler with detailed logging per upstream
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Error().
				Err(err).
				Str("upstream", upstream).
				Str("method", r.Method).
				Str("path", r.URL.Path).
				Msg("Proxy error")
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
		},

		// ModifyResponse for response inspection and metrics logging
		ModifyResponse: func(resp *http.Response) error {
			log.Debug().
				Str("upstream", upstream).
				Int("status", resp.StatusCode).
				Str("content_length", resp.Header.Get("Content-Length")).
				Msg("Response received")
			return nil
		},

		Transport: transport,
	}

	return proxy
}
