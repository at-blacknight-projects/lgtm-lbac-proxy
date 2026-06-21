package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"github.com/fsnotify/fsnotify"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type LogConfig struct {
	Level int `mapstructure:"level"`
}

// ClaimsConfig defines the JWT claim field names to extract from tokens.
// Different OAuth providers use different claim names for standard fields.
type ClaimsConfig struct {
	Username string `mapstructure:"username"` // Claim name for username (e.g., "preferred_username", "sub", "unique_name")
	Email    string `mapstructure:"email"`    // Claim name for email (e.g., "email", "upn", "mail")
	Groups   string `mapstructure:"groups"`   // Claim name for groups (e.g., "groups", "roles", "https://example.com/groups")
}

// TrustedClientHeaderConfig configures identity derived from a trusted request
// header instead of a JWT. It is intended for machine clients that cannot present
// an OIDC token (e.g. the Ceph dashboard via an mTLS sidecar): a fronting ingress
// terminates mTLS, verifies the client certificate, and forwards the verified
// Common Name in CNHeader. The proxy then uses that CN as the label-policy identity.
//
// SECURITY: the CN header is trusted implicitly when Enabled. The fronting ingress
// MUST (1) enforce mTLS client authentication, (2) overwrite/strip any
// client-supplied value of CNHeader and set it from the verified certificate, and
// (3) be the only network path to the proxy. Enabling this without those controls
// lets any caller impersonate any identity by setting the header.
type TrustedClientHeaderConfig struct {
	Enabled  bool   `mapstructure:"enabled"`   // Opt-in; default false (JWT-only)
	CNHeader string `mapstructure:"cn_header"` // Header carrying the verified client CN (default "X-Client-CN")
}

// ClientCertConfig configures certificate-based identity and admission (mode B).
//
// When Enabled, the verified client certificate is the root of admission: the proxy
// extracts claims from it, evaluates the configurable Admission policy, and derives the
// label-policy identity from IdentityFrom. The certificate is obtained either from the
// TLS layer when the proxy terminates mTLS (Source "mtls") or from a forwarded PEM header
// set by an mTLS-terminating ingress (Source "header").
type ClientCertConfig struct {
	Enabled      bool                `mapstructure:"enabled"`       // Opt-in; default false
	Source       string              `mapstructure:"source"`        // "mtls" (proxy-terminated) | "header" (forwarded PEM); default "mtls"
	CertHeader   string              `mapstructure:"cert_header"`   // Header carrying the URL-escaped/PEM client cert (Source "header"); default "X-Forwarded-Client-Cert"
	IdentityFrom string              `mapstructure:"identity_from"` // Cert field used as label-policy identity; default "cn"
	CAPath       string              `mapstructure:"ca_path"`       // Client CA bundle to verify against (mTLS listener / header re-verification)
	ServerCert   string              `mapstructure:"server_cert"`   // Proxy server certificate (Source "mtls")
	ServerKey    string              `mapstructure:"server_key"`    // Proxy server key (Source "mtls")
	ClientAuth   string              `mapstructure:"client_auth"`   // mTLS listener policy: "require" (default) or "request" (verify-if-given; enables mixed JWT+mTLS on one port)
	// MTLSPort, when set (Source "mtls"), runs the mTLS listener on this dedicated port
	// while the plain-HTTP proxy keeps serving on web.proxy_port — so in-cluster HTTP/JWT
	// clients are unaffected and only the mTLS port need be exposed externally. When unset
	// (0), the mTLS listener replaces the plain proxy listener on web.proxy_port.
	MTLSPort  int                 `mapstructure:"mtls_port"`
	Admission CertAdmissionPolicy `mapstructure:"admission"` // Configurable {field,operator,values} rules
}

// AuthConfig contains all authentication-related configuration.
// This separates auth concerns from web server configuration.
type AuthConfig struct {
	JwksCertURL         string                    `mapstructure:"jwks_cert_url"`         // JWKS endpoint URL for token validation
	AuthHeader          string                    `mapstructure:"auth_header"`           // HTTP header containing the JWT token
	AuthScheme          string                    `mapstructure:"auth_scheme"`           // Authentication scheme/prefix (e.g., "Bearer")
	Claims              ClaimsConfig              `mapstructure:"claims"`                // JWT claim field names
	TrustedClientHeader TrustedClientHeaderConfig `mapstructure:"trusted_client_header"` // Identity from a trusted CN header (lightweight)
	ClientCert          ClientCertConfig          `mapstructure:"client_cert"`           // Certificate-based identity + configurable admission (mode B)
	// Audiences is the set of accepted `aud` values; a token passes if its aud matches ANY.
	// Empty disables the check (signature+expiry only). Without it, any token signed by the
	// trusted issuer is accepted regardless of which resource it was minted for.
	Audiences []string `mapstructure:"audiences"`
	// Issuer, when set, is the exact `iss` the token must carry. Empty disables the check.
	Issuer string `mapstructure:"issuer"`
}

type WebConfig struct {
	ProxyPort           int    `mapstructure:"proxy_port"`
	MetricsPort         int    `mapstructure:"metrics_port"`
	Host                string `mapstructure:"host"`
	TLSVerifySkip       bool   `mapstructure:"tls_verify_skip"`
	TrustedRootCaPath   string `mapstructure:"trusted_root_ca_path"`
	ServiceAccountToken string `mapstructure:"service_account_token"`

	// DEPRECATED: These fields are deprecated in favor of AuthConfig.
	// They are kept for backward compatibility and will be removed in a future version.
	JwksCertURL        string `mapstructure:"jwks_cert_url"`
	OAuthUsernameClaim string `mapstructure:"oauth_username_claim"`
	OAuthEmailClaim    string `mapstructure:"oauth_email_claim"`
	OAuthGroupName     string `mapstructure:"oauth_group_name"`
	AuthHeader         string `mapstructure:"auth_header"`
}

type AdminConfig struct {
	Bypass bool   `mapstructure:"bypass"`
	Group  string `mapstructure:"group"`
}

type AlertConfig struct {
	Enabled     bool   `mapstructure:"enabled"`
	TokenHeader string `mapstructure:"token_header"`
	CertURL     string `mapstructure:"alert_cert_url"`
	Cert        string `mapstructure:"alert_cert"`
}

type DevConfig struct {
	Enabled  bool   `mapstructure:"enabled"`
	Username string `mapstructure:"username"`
}

// ProxyConfig contains HTTP client transport and timeout configuration for reverse proxy operations.
// These settings optimize connection pooling and request handling for high-throughput scenarios.
type ProxyConfig struct {
	RequestTimeout      time.Duration `mapstructure:"request_timeout"`         // Maximum request duration
	IdleConnTimeout     time.Duration `mapstructure:"idle_conn_timeout"`       // Keep-alive duration for idle connections
	TLSHandshakeTimeout time.Duration `mapstructure:"tls_handshake_timeout"`   // Timeout for TLS handshake
	MaxIdleConns        int           `mapstructure:"max_idle_conns"`          // Total idle connections across all upstreams
	MaxIdleConnsPerHost int           `mapstructure:"max_idle_conns_per_host"` // Idle connections per upstream
	ForceHTTP2          bool          `mapstructure:"force_http2"`             // Enable HTTP/2 when available
}

type ThanosConfig struct {
	URL          string            `mapstructure:"url"`
	UseMutualTLS bool              `mapstructure:"use_mutual_tls"`
	Cert         string            `mapstructure:"cert"`
	Key          string            `mapstructure:"key"`
	Headers      map[string]string `mapstructure:"headers"`
	ActorHeader  string            `mapstructure:"actor_header"`
	Proxy        *ProxyConfig      `mapstructure:"proxy"` // Per-upstream proxy configuration override
}

type LokiConfig struct {
	URL          string            `mapstructure:"url"`
	UseMutualTLS bool              `mapstructure:"use_mutual_tls"`
	Cert         string            `mapstructure:"cert"`
	Key          string            `mapstructure:"key"`
	Headers      map[string]string `mapstructure:"headers"`
	ActorHeader  string            `mapstructure:"actor_header"`
	Proxy        *ProxyConfig      `mapstructure:"proxy"` // Per-upstream proxy configuration override
}

type TempoConfig struct {
	URL          string            `mapstructure:"url"`
	UseMutualTLS bool              `mapstructure:"use_mutual_tls"`
	Cert         string            `mapstructure:"cert"`
	Key          string            `mapstructure:"key"`
	Headers      map[string]string `mapstructure:"headers"`
	ActorHeader  string            `mapstructure:"actor_header"`
	Proxy        *ProxyConfig      `mapstructure:"proxy"` // Per-upstream proxy configuration override
}

type Config struct {
	Log        LogConfig        `mapstructure:"log"`
	Auth       AuthConfig       `mapstructure:"auth"` // Authentication configuration (preferred)
	Web        WebConfig        `mapstructure:"web"`
	Admin      AdminConfig      `mapstructure:"admin"`
	Alert      AlertConfig      `mapstructure:"alert"`
	Dev        DevConfig        `mapstructure:"dev"`
	Proxy      ProxyConfig      `mapstructure:"proxy"` // Global proxy configuration defaults
	Thanos     ThanosConfig     `mapstructure:"thanos"`
	Loki       LokiConfig       `mapstructure:"loki"`
	Tempo      TempoConfig      `mapstructure:"tempo"`
	LabelStore LabelStoreConfig `mapstructure:"labelstore"`
}

// LabelStoreConfig contains configuration needed by label stores during initialization.
// This is a focused configuration subset, avoiding coupling to the entire App struct.
type LabelStoreConfig struct {
	// ConfigPaths are directories to search for label configuration files.
	// Label stores should check these paths in order for their config files.
	// Default: ["/etc/config/labels/", "./configs"]
	ConfigPaths []string `mapstructure:"config_paths"`

	// Additional configuration fields can be added here by custom label store implementations
	// without breaking the existing FileLabelStore. Each label store implementation should
	// document which fields it uses and ignore the rest.
}

func (a *App) WithConfig() *App {
	v := viper.NewWithOptions(viper.KeyDelimiter("::"))
	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath("/etc/config/config/")
	v.AddConfigPath("./configs")

	// Set defaults for label store configuration
	v.SetDefault("labelstore::config_paths", []string{"/etc/config/labels/", "./configs"})

	err := v.MergeInConfig()
	if err != nil {
		log.Fatal().Err(err).Msg("Error no config found")
		return nil
	}
	a.Cfg = &Config{}
	err = v.Unmarshal(a.Cfg)
	if err != nil {
		log.Fatal().Err(err).Msg("Error while unmarshalling config file")
	}

	// Migrate legacy configuration to new auth section with backward compatibility
	a.migrateAuthConfig()
	// Set default label store config paths if not configured
	if len(a.Cfg.LabelStore.ConfigPaths) == 0 {
		a.Cfg.LabelStore.ConfigPaths = []string{"/etc/config/labels/", "./configs"}
	}
	// Validate Tempo configuration if provided
	a.validateTempoConfig()
	v.OnConfigChange(func(e fsnotify.Event) {
		log.Info().Str("file", e.Name).Msg("Config file changed")
		err := v.Unmarshal(a.Cfg)
		if err != nil {
			log.Error().Err(err).Msg("Error while unmarshalling config file")
			a.healthy = false
		}
		// Migrate legacy configuration to new auth section
		a.migrateAuthConfig()
		// Set default label store config paths if not configured
		if len(a.Cfg.LabelStore.ConfigPaths) == 0 {
			a.Cfg.LabelStore.ConfigPaths = []string{"/etc/config/labels/", "./configs"}
		}
		// Validate Tempo configuration if provided
		a.validateTempoConfig()
		zerolog.SetGlobalLevel(zerolog.Level(a.Cfg.Log.Level))
	})
	v.WatchConfig()
	zerolog.SetGlobalLevel(zerolog.Level(a.Cfg.Log.Level))
	log.Debug().Any("config", a.Cfg).Msg("")
	return a
}

func (a *App) WithSAT() *App {
	if a.Cfg.Dev.Enabled {
		a.ServiceAccountToken = a.Cfg.Web.ServiceAccountToken
		return a
	}
	sa, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		log.Fatal().Err(err).Msg("Error while reading service account token")
	}
	a.ServiceAccountToken = string(sa)
	return a
}

func (a *App) WithTLSConfig() *App {
	caCert, err := os.ReadFile("/etc/ssl/ca/ca-certificates.crt")
	if err != nil {
		log.Fatal().Err(err).Msg("Error while reading CA certificate")
	}
	log.Trace().Bytes("caCert", caCert).Msg("")

	rootCAs := x509.NewCertPool()
	if ok := rootCAs.AppendCertsFromPEM(caCert); !ok {
		log.Fatal().Msg("Failed to append CA certificate")
	}
	log.Debug().Any("rootCAs", rootCAs).Msg("")

	if a.Cfg.Web.TrustedRootCaPath != "" {
		err := filepath.Walk(a.Cfg.Web.TrustedRootCaPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() || strings.Contains(info.Name(), "..") {
				return nil
			}

			certs, err := os.ReadFile(path)
			if err != nil {
				log.Error().Err(err).Msg("Error while reading trusted CA")
				return err
			}
			log.Debug().Str("path", path).Msg("Adding trusted CA")
			certs = append(certs, []byte("\n")...)
			rootCAs.AppendCertsFromPEM(certs)

			return nil
		})
		if err != nil {
			log.Error().Err(err).Msg("Error while traversing directory")
		}
	}

	var certificates []tls.Certificate

	lokiCert, err := tls.LoadX509KeyPair(a.Cfg.Loki.Cert, a.Cfg.Loki.Key)
	if err != nil {
		log.Error().Err(err).Msg("Error while loading loki certificate")
	} else {
		log.Debug().Str("path", a.Cfg.Loki.Cert).Msg("Adding Loki certificate")
		certificates = append(certificates, lokiCert)
	}

	thanosCert, err := tls.LoadX509KeyPair(a.Cfg.Thanos.Cert, a.Cfg.Thanos.Key)
	if err != nil {
		log.Error().Err(err).Msg("Error while loading thanos certificate")
	} else {
		log.Debug().Str("path", a.Cfg.Thanos.Cert).Msg("Adding Thanos certificate")
		certificates = append(certificates, thanosCert)
	}

	tempoCert, err := tls.LoadX509KeyPair(a.Cfg.Tempo.Cert, a.Cfg.Tempo.Key)
	if err != nil {
		log.Error().Err(err).Msg("Error while loading tempo certificate")
	} else {
		log.Debug().Str("path", a.Cfg.Tempo.Cert).Msg("Adding Tempo certificate")
		certificates = append(certificates, tempoCert)
	}

	config := &tls.Config{
		InsecureSkipVerify: a.Cfg.Web.TLSVerifySkip,
		RootCAs:            rootCAs,
		Certificates:       certificates,
	}

	http.DefaultTransport.(*http.Transport).TLSClientConfig = config
	return a
}

func (a *App) WithJWKS() *App {
	log.Info().Msg("Init JWKS config")
	urls := []string{a.Cfg.Web.JwksCertURL}
	if a.Cfg.Alert.Enabled {
		urls = []string{a.Cfg.Web.JwksCertURL, a.Cfg.Alert.CertURL}
	}
	var cert json.RawMessage
	cert = nil
	if a.Cfg.Alert.Cert != "" {
		cert = json.RawMessage(a.Cfg.Alert.Cert)
	}
	jwks, err := NewCombinedJwks(context.Background(), urls, cert)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create a keyfunc from the server's URL")
	}
	log.Info().Str("url", a.Cfg.Web.JwksCertURL).Msg("JWKS URL")
	a.Jwks = jwks
	return a
}

// migrateAuthConfig handles backward compatibility by migrating legacy web.* auth fields
// to the new auth.* configuration structure. It supports three scenarios:
// 1. New config only (auth section present): Use auth section, set defaults
// 2. Legacy config only (web section with auth fields): Migrate to auth section with deprecation warning
// 3. Mixed config (both present): Prefer auth section, log warning if web fields also present
func (a *App) migrateAuthConfig() {
	hasNewAuth := a.Cfg.Auth.JwksCertURL != "" || a.Cfg.Auth.AuthHeader != "" ||
		a.Cfg.Auth.Claims.Username != "" || a.Cfg.Auth.Claims.Email != "" || a.Cfg.Auth.Claims.Groups != ""
	hasLegacyAuth := a.Cfg.Web.JwksCertURL != "" || a.Cfg.Web.AuthHeader != "" ||
		a.Cfg.Web.OAuthUsernameClaim != "" || a.Cfg.Web.OAuthEmailClaim != "" || a.Cfg.Web.OAuthGroupName != ""

	if hasNewAuth && hasLegacyAuth {
		// Mixed configuration: both new and legacy present
		log.Warn().Msg("Both 'auth' and 'web' auth configuration detected. Using 'auth' section. Please remove deprecated web.jwks_cert_url, web.auth_header, web.oauth_username_claim, web.oauth_email_claim, and web.oauth_group_name fields.")
	} else if hasLegacyAuth && !hasNewAuth {
		// Legacy configuration: migrate to new structure
		log.Warn().Msg("DEPRECATED: web.jwks_cert_url, web.auth_header, web.oauth_*_claim fields are deprecated. Please migrate to 'auth' section. See documentation for migration guide.")

		// Migrate JWKS URL
		if a.Cfg.Web.JwksCertURL != "" {
			a.Cfg.Auth.JwksCertURL = a.Cfg.Web.JwksCertURL
		}

		// Migrate auth header
		if a.Cfg.Web.AuthHeader != "" {
			a.Cfg.Auth.AuthHeader = a.Cfg.Web.AuthHeader
		}

		// Migrate claim names
		if a.Cfg.Web.OAuthUsernameClaim != "" {
			a.Cfg.Auth.Claims.Username = a.Cfg.Web.OAuthUsernameClaim
		}
		if a.Cfg.Web.OAuthEmailClaim != "" {
			a.Cfg.Auth.Claims.Email = a.Cfg.Web.OAuthEmailClaim
		}
		if a.Cfg.Web.OAuthGroupName != "" {
			a.Cfg.Auth.Claims.Groups = a.Cfg.Web.OAuthGroupName
		}
	}

	// Set defaults for auth configuration
	if a.Cfg.Auth.AuthHeader == "" {
		a.Cfg.Auth.AuthHeader = "Authorization"
	}
	if a.Cfg.Auth.Claims.Username == "" {
		a.Cfg.Auth.Claims.Username = "preferred_username"
	}
	if a.Cfg.Auth.Claims.Email == "" {
		a.Cfg.Auth.Claims.Email = "email"
	}
	if a.Cfg.Auth.Claims.Groups == "" {
		a.Cfg.Auth.Claims.Groups = "groups"
	}
	if a.Cfg.Auth.TrustedClientHeader.Enabled && a.Cfg.Auth.TrustedClientHeader.CNHeader == "" {
		a.Cfg.Auth.TrustedClientHeader.CNHeader = "X-Client-CN"
	}
	if a.Cfg.Auth.ClientCert.Enabled {
		if a.Cfg.Auth.ClientCert.Source == "" {
			a.Cfg.Auth.ClientCert.Source = "mtls"
		}
		if a.Cfg.Auth.ClientCert.CertHeader == "" {
			a.Cfg.Auth.ClientCert.CertHeader = "X-Forwarded-Client-Cert"
		}
		if a.Cfg.Auth.ClientCert.IdentityFrom == "" {
			a.Cfg.Auth.ClientCert.IdentityFrom = CertFieldCN
		}
		if a.Cfg.Auth.ClientCert.ClientAuth == "" {
			a.Cfg.Auth.ClientCert.ClientAuth = "require"
		}
		if err := a.Cfg.Auth.ClientCert.Admission.Validate(); err != nil {
			log.Fatal().Err(err).Msg("Invalid client_cert.admission policy")
		}
	}
	a.Cfg.Auth.AuthScheme = strings.TrimSpace(a.Cfg.Auth.AuthScheme)

	// Also maintain backward compatibility fields for existing code that still references them
	// This allows gradual migration of code references
	a.Cfg.Web.JwksCertURL = a.Cfg.Auth.JwksCertURL
	a.Cfg.Web.AuthHeader = a.Cfg.Auth.AuthHeader
	a.Cfg.Web.OAuthUsernameClaim = a.Cfg.Auth.Claims.Username
	a.Cfg.Web.OAuthEmailClaim = a.Cfg.Auth.Claims.Email
	a.Cfg.Web.OAuthGroupName = a.Cfg.Auth.Claims.Groups

	log.Debug().
		Str("jwks_url", a.Cfg.Auth.JwksCertURL).
		Str("auth_header", a.Cfg.Auth.AuthHeader).
		Str("username_claim", a.Cfg.Auth.Claims.Username).
		Str("email_claim", a.Cfg.Auth.Claims.Email).
		Str("groups_claim", a.Cfg.Auth.Claims.Groups).
		Str("auth_scheme", a.Cfg.Auth.AuthScheme).
		Msg("Authentication configuration loaded")
}

// validateTempoConfig validates Tempo configuration settings
func (a *App) validateTempoConfig() {
	// Skip validation if Tempo URL is not configured
	if a.Cfg.Tempo.URL == "" {
		return
	}

	// Validate URL format
	if !strings.HasPrefix(a.Cfg.Tempo.URL, "http://") && !strings.HasPrefix(a.Cfg.Tempo.URL, "https://") {
		log.Warn().Str("url", a.Cfg.Tempo.URL).Msg("Tempo URL should start with http:// or https://")
	}

	// Validate certificate files exist if mTLS is enabled
	if a.Cfg.Tempo.UseMutualTLS {
		if a.Cfg.Tempo.Cert != "" {
			if _, err := os.Stat(a.Cfg.Tempo.Cert); os.IsNotExist(err) {
				log.Error().Str("cert", a.Cfg.Tempo.Cert).Msg("Tempo certificate file not found")
			}
		}
		if a.Cfg.Tempo.Key != "" {
			if _, err := os.Stat(a.Cfg.Tempo.Key); os.IsNotExist(err) {
				log.Error().Str("key", a.Cfg.Tempo.Key).Msg("Tempo key file not found")
			}
		}
	}

	log.Debug().
		Str("url", a.Cfg.Tempo.URL).
		Bool("use_mutual_tls", a.Cfg.Tempo.UseMutualTLS).
		Msg("Tempo configuration loaded")
}

// GetProxyConfig merges upstream-specific proxy configuration with global defaults.
// Configuration precedence: upstream-specific > global > built-in defaults.
// This allows per-upstream tuning while maintaining sensible global defaults.
func (c *Config) GetProxyConfig(upstreamProxy *ProxyConfig) ProxyConfig {
	// Start with built-in defaults optimized for reverse proxy operations
	cfg := ProxyConfig{
		RequestTimeout:      60 * time.Second,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		MaxIdleConns:        500,
		MaxIdleConnsPerHost: 100,
		ForceHTTP2:          true,
	}

	// Apply global proxy defaults if set
	if c.Proxy.RequestTimeout > 0 {
		cfg.RequestTimeout = c.Proxy.RequestTimeout
	}
	if c.Proxy.IdleConnTimeout > 0 {
		cfg.IdleConnTimeout = c.Proxy.IdleConnTimeout
	}
	if c.Proxy.TLSHandshakeTimeout > 0 {
		cfg.TLSHandshakeTimeout = c.Proxy.TLSHandshakeTimeout
	}
	if c.Proxy.MaxIdleConns > 0 {
		cfg.MaxIdleConns = c.Proxy.MaxIdleConns
	}
	if c.Proxy.MaxIdleConnsPerHost > 0 {
		cfg.MaxIdleConnsPerHost = c.Proxy.MaxIdleConnsPerHost
	}
	// ForceHTTP2 from global config
	if c.Proxy.ForceHTTP2 {
		cfg.ForceHTTP2 = c.Proxy.ForceHTTP2
	}

	// Apply upstream-specific overrides if set
	if upstreamProxy != nil {
		if upstreamProxy.RequestTimeout > 0 {
			cfg.RequestTimeout = upstreamProxy.RequestTimeout
		}
		if upstreamProxy.IdleConnTimeout > 0 {
			cfg.IdleConnTimeout = upstreamProxy.IdleConnTimeout
		}
		if upstreamProxy.TLSHandshakeTimeout > 0 {
			cfg.TLSHandshakeTimeout = upstreamProxy.TLSHandshakeTimeout
		}
		if upstreamProxy.MaxIdleConns > 0 {
			cfg.MaxIdleConns = upstreamProxy.MaxIdleConns
		}
		if upstreamProxy.MaxIdleConnsPerHost > 0 {
			cfg.MaxIdleConnsPerHost = upstreamProxy.MaxIdleConnsPerHost
		}
		// ForceHTTP2 from upstream-specific config
		if upstreamProxy.ForceHTTP2 {
			cfg.ForceHTTP2 = upstreamProxy.ForceHTTP2
		}
	}

	return cfg
}

// createTransport creates an HTTP transport with the specified proxy configuration and TLS settings.
// Each upstream gets its own dedicated transport instance to enable per-upstream connection pooling.
func (a *App) createTransport(proxyCfg ProxyConfig, tlsConfig *tls.Config) *http.Transport {
	return &http.Transport{
		TLSClientConfig:     tlsConfig,
		MaxIdleConns:        proxyCfg.MaxIdleConns,
		MaxIdleConnsPerHost: proxyCfg.MaxIdleConnsPerHost,
		MaxConnsPerHost:     0, // Unlimited active connections
		IdleConnTimeout:     proxyCfg.IdleConnTimeout,
		TLSHandshakeTimeout: proxyCfg.TLSHandshakeTimeout,
		DisableCompression:  false,
		ForceAttemptHTTP2:   proxyCfg.ForceHTTP2,
	}
}
