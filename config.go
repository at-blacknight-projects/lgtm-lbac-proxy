package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/fsnotify/fsnotify"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
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
	// StaticKeys maps the SHA-256 (hex) of a long-lived key to an identity whose
	// labels.yaml entry scopes what it may read. Off when empty. See statickeys.go.
	StaticKeys map[string]string `mapstructure:"static_keys"`
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

// AlertmanagerConfig is the Alertmanager upstream, used by the routes registered in
// WithAlertmanager.
//
// Mimir and Cortex serve the Alertmanager API under a base path (PathPrefix, default
// /alertmanager). A standalone Alertmanager serves it at the root; set path_prefix to ""
// for that.
type AlertmanagerConfig struct {
	URL          string            `mapstructure:"url"`
	PathPrefix   string            `mapstructure:"path_prefix"`
	UseMutualTLS bool              `mapstructure:"use_mutual_tls"`
	Cert         string            `mapstructure:"cert"`
	Key          string            `mapstructure:"key"`
	Headers      map[string]string `mapstructure:"headers"`
	ActorHeader  string            `mapstructure:"actor_header"`
	Proxy        *ProxyConfig      `mapstructure:"proxy"` // Per-upstream proxy configuration override
}

// AlertingConfig gates the ruler and Alertmanager routes.
//
// Those endpoints return whole rule groups and alert instances rather than a query, so
// there is no expression for a label enforcer to rewrite and no per-tenant scoping to
// apply. Access is granted by group membership instead: ViewerGroups may read,
// AdminGroups may additionally create and expire silences and write the Alertmanager
// configuration. A caller in neither group reads an empty result set.
//
// Distinct from AlertConfig above, which configures a second JWKS source for
// alert-webhook tokens and is unrelated.
type AlertingConfig struct {
	Enabled      bool     `mapstructure:"enabled"`
	ViewerGroups []string `mapstructure:"viewer_groups"`
	AdminGroups  []string `mapstructure:"admin_groups"`
}

// IngestConfig is the OTLP write gateway: a dedicated listener that accepts OTLP/HTTP
// pushes from token-holding clients and forwards them, rewritten, to an OTLP receiver.
//
// The listener serves only the push routes and a health probe — never the query,
// ruler or Alertmanager routes — so it can be published more widely than the read
// path. Identity on it is JWT-only: client-certificate and trusted-header identity are
// not consulted.
//
// Writers maps a group (as carried in the configured groups claim) to the writer id
// the caller pushes as. The gateway does not read or modify the payload: it forwards
// the body unchanged and sends the writer id in WriterHeader, overwriting any value the
// client supplied. The upstream derives tenancy from that header, so it must be
// reachable only through the gateway. Groups are matched case-insensitively; viper
// lowercases map keys. The admin group does not imply write access: every writer must
// be named explicitly.
//
// Changes to Enabled, Port, the server certificate and the upstream URLs take effect on
// restart; writers and the header name are read per request and follow config reloads.
type IngestConfig struct {
	Enabled bool `mapstructure:"enabled"`
	// Only runs the process as a write gateway alone: no label store is loaded, no read
	// upstreams or routes are set up, and only the ingest and metrics listeners are
	// served. Deploy it separately from the read proxy so that the pods reachable by
	// writers hold no read access at all.
	Only         bool              `mapstructure:"only"`
	Port         int               `mapstructure:"port"`
	ServerCert   string            `mapstructure:"server_cert"`
	ServerKey    string            `mapstructure:"server_key"`
	Writers      map[string]string `mapstructure:"writers"`        // group -> writer id
	StaticKeys   map[string]string `mapstructure:"static_keys"`    // SHA-256 hex of a long-lived key -> writer id; for exporters that only send fixed headers
	MaxBodyBytes int64             `mapstructure:"max_body_bytes"` // cap on the request body as sent (decompression is the upstream's to bound)
	// WriterHeader is the request header the upstream receives the writer id in. For a
	// multi-tenant backend this can be its tenant header, for example X-Scope-OrgID.
	WriterHeader string `mapstructure:"writer_header"`

	// Edges say how a push reached the gateway when it is published through more than
	// one path, for example directly and through a CDN or tunnel. A push carrying an
	// edge's marker header came through that edge; anything else is "direct". The result
	// labels the ingest metrics and, with EdgeHeader set, is forwarded upstream. A direct
	// client could send a marker header itself, so the edge is observational: never base
	// an access decision on it.
	Edges []IngestEdge `mapstructure:"edges"`
	// EdgeHeader, when set, is the request header the upstream receives the edge name in,
	// overwriting any value the client supplied. Empty = not forwarded.
	EdgeHeader string `mapstructure:"edge_header"`

	// Per-signal OTLP/HTTP upstreams. A signal with no URL is not routed. The request
	// path (/v1/metrics, /v1/logs, /v1/traces) is appended to the URL's base path, so a
	// collector takes its base URL and an OTLP endpoint mounted under a prefix (for
	// example /otlp) takes that prefix.
	Metrics IngestSignalConfig `mapstructure:"metrics"`
	Logs    IngestSignalConfig `mapstructure:"logs"`
	Traces  IngestSignalConfig `mapstructure:"traces"`
}

// IngestEdge is one way pushes can reach the gateway, recognised by a header the edge
// adds to every request it forwards (Cloudflare adds Cf-Ray).
type IngestEdge struct {
	Name           string `mapstructure:"name"`             // label value, e.g. cloudflare
	Header         string `mapstructure:"header"`           // marker header, e.g. Cf-Ray
	ClientIPHeader string `mapstructure:"client_ip_header"` // optional: the edge's client address header, e.g. Cf-Connecting-Ip, logged at debug
}

// IngestSignalConfig is the upstream for one OTLP signal.
type IngestSignalConfig struct {
	URL   string       `mapstructure:"url"`
	Proxy *ProxyConfig `mapstructure:"proxy"` // Per-upstream proxy configuration override
}

type Config struct {
	Log          LogConfig          `mapstructure:"log"`
	Auth         AuthConfig         `mapstructure:"auth"` // Authentication configuration (preferred)
	Web          WebConfig          `mapstructure:"web"`
	Admin        AdminConfig        `mapstructure:"admin"`
	Alert        AlertConfig        `mapstructure:"alert"`
	Alerting     AlertingConfig     `mapstructure:"alerting"` // Ruler + Alertmanager route access
	Dev          DevConfig          `mapstructure:"dev"`
	Proxy        ProxyConfig        `mapstructure:"proxy"` // Global proxy configuration defaults
	Thanos       ThanosConfig       `mapstructure:"thanos"`
	Loki         LokiConfig         `mapstructure:"loki"`
	Tempo        TempoConfig        `mapstructure:"tempo"`
	Alertmanager AlertmanagerConfig `mapstructure:"alertmanager"`
	Ingest       IngestConfig       `mapstructure:"ingest"` // OTLP write gateway
	LabelStore   LabelStoreConfig   `mapstructure:"labelstore"`
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

// configSearchPaths are where config.yaml is looked for, in order. A variable so tests
// can point the loader at a temporary directory.
var configSearchPaths = []string{"/etc/config/config/", "./configs"}

// Config reload outcomes, as the result label of lgtm_lbac_proxy_config_reloads_total.
const (
	reloadApplied  = "applied"
	reloadRejected = "rejected"
)

var (
	configReloads = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "lgtm_lbac_proxy_config_reloads_total",
		Help: "Config file reloads, by result: applied, or rejected (the previous configuration keeps serving).",
	}, []string{"result"})
	configLastReloadSuccessful = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "lgtm_lbac_proxy_config_last_reload_successful",
		Help: "1 if the last config reload was applied (or none has happened yet), 0 if it was rejected.",
	})
)

// Cfg returns the live configuration. Treat it as read-only: a reload never changes a
// published Config, it publishes a new one, so whatever a request reads from it is
// consistent and is never being written.
func (a *App) Cfg() *Config {
	if a.cfg == nil {
		return nil
	}
	return a.cfg.Load()
}

// SetConfig publishes cfg as the live configuration. Call it at startup before serving,
// and from the reload path only with a Config that loadConfig accepted.
func (a *App) SetConfig(cfg *Config) {
	if a.cfg == nil {
		a.cfg = new(atomic.Pointer[Config])
	}
	a.cfg.Store(cfg)
}

// newConfigViper returns a viper set up to find config.yaml, with the defaults every
// load applies.
func newConfigViper() *viper.Viper {
	v := viper.NewWithOptions(viper.KeyDelimiter("::"))
	v.SetConfigName("config")
	v.SetConfigType("yaml")
	for _, p := range configSearchPaths {
		v.AddConfigPath(p)
	}

	// Set defaults for label store configuration
	v.SetDefault("labelstore::config_paths", []string{"/etc/config/labels/", "./configs"})

	// Mimir and Cortex serve the Alertmanager API under /alertmanager. Set explicitly to
	// "" for a standalone Alertmanager, which serves it at the root.
	v.SetDefault("alertmanager::path_prefix", "/alertmanager")
	v.SetDefault("ingest::max_body_bytes", defaultIngestMaxBodyBytes)
	v.SetDefault("ingest::writer_header", defaultIngestWriterHeader)
	return v
}

// readConfig reads config.yaml afresh and returns it migrated and validated. Startup and
// every reload go through it, so both apply exactly the same checks.
func readConfig() (*Config, error) {
	v := newConfigViper()
	if err := v.MergeInConfig(); err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}
	return loadConfig(v)
}

// loadConfig builds a new Config from v: unmarshalled into a fresh struct (so a field
// removed from the file is really gone), migrated and validated. It never touches the
// live configuration.
func loadConfig(v *viper.Viper) (*Config, error) {
	cfg := &Config{}
	if err := v.Unmarshal(cfg); err != nil {
		return nil, fmt.Errorf("unmarshalling config: %w", err)
	}
	// Migrate legacy configuration to new auth section with backward compatibility
	if err := migrateAuthConfig(cfg); err != nil {
		return nil, err
	}
	// Set default label store config paths if not configured
	if len(cfg.LabelStore.ConfigPaths) == 0 {
		cfg.LabelStore.ConfigPaths = []string{"/etc/config/labels/", "./configs"}
	}
	// Validate Tempo configuration if provided
	validateTempoConfig(cfg)
	if err := validateIngestConfig(cfg); err != nil {
		return nil, fmt.Errorf("invalid ingest configuration: %w", err)
	}
	if err := validateAuthStaticKeys(cfg); err != nil {
		return nil, fmt.Errorf("invalid static key configuration: %w", err)
	}
	return cfg, nil
}

func (a *App) WithConfig() *App {
	cfg, err := readConfig()
	if err != nil {
		log.Fatal().Err(err).Msg("Invalid configuration")
		return nil
	}
	a.SetConfig(cfg)
	configLastReloadSuccessful.Set(1)

	// The watcher only signals that the file changed. Its own copy isn't used: if the
	// new file doesn't parse, viper keeps the old values and still fires the callback,
	// which would look like a successful reload. reloadConfig reads the file afresh.
	w := newConfigViper()
	if err := w.MergeInConfig(); err != nil {
		log.Fatal().Err(err).Msg("Error no config found")
		return nil
	}
	w.OnConfigChange(func(e fsnotify.Event) {
		log.Info().Str("file", e.Name).Msg("Config file changed")
		a.reloadConfig()
	})
	w.WatchConfig()
	zerolog.SetGlobalLevel(zerolog.Level(cfg.Log.Level))
	log.Debug().Any("config", cfg).Msg("")
	return a
}

// reloadConfig rebuilds the configuration from the file exactly as startup does and
// publishes it only if it is valid. A rejected file is logged and counted, and the
// previous configuration keeps serving: a bad edit to a ConfigMap that every replica
// mounts must not take them all down, so this path never exits and never marks the
// process unhealthy.
func (a *App) reloadConfig() {
	next, err := readConfig()
	if err != nil {
		configReloads.WithLabelValues(reloadRejected).Inc()
		configLastReloadSuccessful.Set(0)
		log.Error().Err(err).Msg("Config reload rejected; still serving the previous configuration")
		return
	}
	if changed := restartOnlyChanges(a.Cfg(), next); len(changed) > 0 {
		log.Warn().Strs("settings", changed).Msg("These changed settings are read only at startup and take effect after a restart")
	}
	a.SetConfig(next)
	zerolog.SetGlobalLevel(zerolog.Level(next.Log.Level))
	configReloads.WithLabelValues(reloadApplied).Inc()
	configLastReloadSuccessful.Set(1)
	log.Info().Msg("Config reloaded")
}

// restartOnlyChanges names the settings that differ between old and next but are only
// read at startup: listeners and their certificates, the upstreams (whose proxies,
// headers and actor headers are built once), the JWKS sources, the service account
// token, the label store location, and whether the alerting and ingest routes exist.
// A reload publishes them, but nothing reads them again until a restart.
func restartOnlyChanges(old, next *Config) []string {
	if old == nil {
		return nil
	}
	clientCertListener := func(c *Config) any {
		cc := c.Auth.ClientCert
		return []any{cc.Enabled, cc.Source, cc.MTLSPort, cc.ServerCert, cc.ServerKey, cc.CAPath, cc.ClientAuth}
	}
	ingestListener := func(c *Config) any {
		in := c.Ingest
		return []any{in.Enabled, in.Only, in.Port, in.ServerCert, in.ServerKey, in.Metrics, in.Logs, in.Traces}
	}
	settings := []struct {
		name      string
		old, next any
	}{
		{"web.proxy_port", old.Web.ProxyPort, next.Web.ProxyPort},
		{"web.metrics_port", old.Web.MetricsPort, next.Web.MetricsPort},
		{"web.host", old.Web.Host, next.Web.Host},
		{"web.tls_verify_skip", old.Web.TLSVerifySkip, next.Web.TLSVerifySkip},
		{"web.trusted_root_ca_path", old.Web.TrustedRootCaPath, next.Web.TrustedRootCaPath},
		{"web.service_account_token", old.Web.ServiceAccountToken, next.Web.ServiceAccountToken},
		{"dev.enabled", old.Dev.Enabled, next.Dev.Enabled},
		{"auth.jwks_cert_url", old.Auth.JwksCertURL, next.Auth.JwksCertURL},
		{"alert (JWKS source)", []any{old.Alert.Enabled, old.Alert.CertURL, old.Alert.Cert}, []any{next.Alert.Enabled, next.Alert.CertURL, next.Alert.Cert}},
		{"auth.client_cert listener", clientCertListener(old), clientCertListener(next)},
		{"thanos", old.Thanos, next.Thanos},
		{"loki", old.Loki, next.Loki},
		{"tempo", old.Tempo, next.Tempo},
		{"alertmanager", old.Alertmanager, next.Alertmanager},
		{"proxy", old.Proxy, next.Proxy},
		{"alerting.enabled", old.Alerting.Enabled, next.Alerting.Enabled},
		{"ingest listener and upstreams", ingestListener(old), ingestListener(next)},
		{"labelstore.config_paths", old.LabelStore.ConfigPaths, next.LabelStore.ConfigPaths},
	}
	var changed []string
	for _, s := range settings {
		if !reflect.DeepEqual(s.old, s.next) {
			changed = append(changed, s.name)
		}
	}
	return changed
}

func (a *App) WithSAT() *App {
	if a.Cfg().Dev.Enabled {
		a.ServiceAccountToken = a.Cfg().Web.ServiceAccountToken
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

	if a.Cfg().Web.TrustedRootCaPath != "" {
		err := filepath.Walk(a.Cfg().Web.TrustedRootCaPath, func(path string, info os.FileInfo, err error) error {
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

	lokiCert, err := tls.LoadX509KeyPair(a.Cfg().Loki.Cert, a.Cfg().Loki.Key)
	if err != nil {
		log.Error().Err(err).Msg("Error while loading loki certificate")
	} else {
		log.Debug().Str("path", a.Cfg().Loki.Cert).Msg("Adding Loki certificate")
		certificates = append(certificates, lokiCert)
	}

	thanosCert, err := tls.LoadX509KeyPair(a.Cfg().Thanos.Cert, a.Cfg().Thanos.Key)
	if err != nil {
		log.Error().Err(err).Msg("Error while loading thanos certificate")
	} else {
		log.Debug().Str("path", a.Cfg().Thanos.Cert).Msg("Adding Thanos certificate")
		certificates = append(certificates, thanosCert)
	}

	tempoCert, err := tls.LoadX509KeyPair(a.Cfg().Tempo.Cert, a.Cfg().Tempo.Key)
	if err != nil {
		log.Error().Err(err).Msg("Error while loading tempo certificate")
	} else {
		log.Debug().Str("path", a.Cfg().Tempo.Cert).Msg("Adding Tempo certificate")
		certificates = append(certificates, tempoCert)
	}

	a.rootCAs = rootCAs

	config := &tls.Config{
		InsecureSkipVerify: a.Cfg().Web.TLSVerifySkip,
		RootCAs:            rootCAs,
		Certificates:       certificates,
	}

	http.DefaultTransport.(*http.Transport).TLSClientConfig = config
	return a
}

func (a *App) WithJWKS() *App {
	log.Info().Msg("Init JWKS config")
	urls := []string{a.Cfg().Web.JwksCertURL}
	if a.Cfg().Alert.Enabled {
		urls = []string{a.Cfg().Web.JwksCertURL, a.Cfg().Alert.CertURL}
	}
	var cert json.RawMessage
	cert = nil
	if a.Cfg().Alert.Cert != "" {
		cert = json.RawMessage(a.Cfg().Alert.Cert)
	}
	jwks, err := NewCombinedJwks(context.Background(), urls, cert)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create a keyfunc from the server's URL")
	}
	log.Info().Str("url", a.Cfg().Web.JwksCertURL).Msg("JWKS URL")
	a.Jwks = jwks
	return a
}

// migrateAuthConfig handles backward compatibility by migrating legacy web.* auth fields
// to the new auth.* configuration structure. It supports three scenarios:
// 1. New config only (auth section present): Use auth section, set defaults
// 2. Legacy config only (web section with auth fields): Migrate to auth section with deprecation warning
// 3. Mixed config (both present): Prefer auth section, log warning if web fields also present
//
// It changes cfg in place, so call it only on a Config that is not yet published.
func migrateAuthConfig(cfg *Config) error {
	hasNewAuth := cfg.Auth.JwksCertURL != "" || cfg.Auth.AuthHeader != "" ||
		cfg.Auth.Claims.Username != "" || cfg.Auth.Claims.Email != "" || cfg.Auth.Claims.Groups != ""
	hasLegacyAuth := cfg.Web.JwksCertURL != "" || cfg.Web.AuthHeader != "" ||
		cfg.Web.OAuthUsernameClaim != "" || cfg.Web.OAuthEmailClaim != "" || cfg.Web.OAuthGroupName != ""

	if hasNewAuth && hasLegacyAuth {
		// Mixed configuration: both new and legacy present
		log.Warn().Msg("Both 'auth' and 'web' auth configuration detected. Using 'auth' section. Please remove deprecated web.jwks_cert_url, web.auth_header, web.oauth_username_claim, web.oauth_email_claim, and web.oauth_group_name fields.")
	} else if hasLegacyAuth && !hasNewAuth {
		// Legacy configuration: migrate to new structure
		log.Warn().Msg("DEPRECATED: web.jwks_cert_url, web.auth_header, web.oauth_*_claim fields are deprecated. Please migrate to 'auth' section. See documentation for migration guide.")

		// Migrate JWKS URL
		if cfg.Web.JwksCertURL != "" {
			cfg.Auth.JwksCertURL = cfg.Web.JwksCertURL
		}

		// Migrate auth header
		if cfg.Web.AuthHeader != "" {
			cfg.Auth.AuthHeader = cfg.Web.AuthHeader
		}

		// Migrate claim names
		if cfg.Web.OAuthUsernameClaim != "" {
			cfg.Auth.Claims.Username = cfg.Web.OAuthUsernameClaim
		}
		if cfg.Web.OAuthEmailClaim != "" {
			cfg.Auth.Claims.Email = cfg.Web.OAuthEmailClaim
		}
		if cfg.Web.OAuthGroupName != "" {
			cfg.Auth.Claims.Groups = cfg.Web.OAuthGroupName
		}
	}

	// Set defaults for auth configuration
	if cfg.Auth.AuthHeader == "" {
		cfg.Auth.AuthHeader = "Authorization"
	}
	if cfg.Auth.Claims.Username == "" {
		cfg.Auth.Claims.Username = "preferred_username"
	}
	if cfg.Auth.Claims.Email == "" {
		cfg.Auth.Claims.Email = "email"
	}
	if cfg.Auth.Claims.Groups == "" {
		cfg.Auth.Claims.Groups = "groups"
	}
	if cfg.Auth.TrustedClientHeader.Enabled && cfg.Auth.TrustedClientHeader.CNHeader == "" {
		cfg.Auth.TrustedClientHeader.CNHeader = "X-Client-CN"
	}
	if cfg.Auth.ClientCert.Enabled {
		if cfg.Auth.ClientCert.Source == "" {
			cfg.Auth.ClientCert.Source = "mtls"
		}
		if cfg.Auth.ClientCert.CertHeader == "" {
			cfg.Auth.ClientCert.CertHeader = "X-Forwarded-Client-Cert"
		}
		if cfg.Auth.ClientCert.IdentityFrom == "" {
			cfg.Auth.ClientCert.IdentityFrom = CertFieldCN
		}
		if cfg.Auth.ClientCert.ClientAuth == "" {
			cfg.Auth.ClientCert.ClientAuth = "require"
		}
		if err := cfg.Auth.ClientCert.Admission.Validate(); err != nil {
			return fmt.Errorf("invalid client_cert.admission policy: %w", err)
		}
	}
	cfg.Auth.AuthScheme = strings.TrimSpace(cfg.Auth.AuthScheme)

	// Also maintain backward compatibility fields for existing code that still references them
	// This allows gradual migration of code references
	cfg.Web.JwksCertURL = cfg.Auth.JwksCertURL
	cfg.Web.AuthHeader = cfg.Auth.AuthHeader
	cfg.Web.OAuthUsernameClaim = cfg.Auth.Claims.Username
	cfg.Web.OAuthEmailClaim = cfg.Auth.Claims.Email
	cfg.Web.OAuthGroupName = cfg.Auth.Claims.Groups

	log.Debug().
		Str("jwks_url", cfg.Auth.JwksCertURL).
		Str("auth_header", cfg.Auth.AuthHeader).
		Str("username_claim", cfg.Auth.Claims.Username).
		Str("email_claim", cfg.Auth.Claims.Email).
		Str("groups_claim", cfg.Auth.Claims.Groups).
		Str("auth_scheme", cfg.Auth.AuthScheme).
		Msg("Authentication configuration loaded")
	return nil
}

// validateTempoConfig validates Tempo configuration settings
func validateTempoConfig(cfg *Config) {
	// Skip validation if Tempo URL is not configured
	if cfg.Tempo.URL == "" {
		return
	}

	// Validate URL format
	if !strings.HasPrefix(cfg.Tempo.URL, "http://") && !strings.HasPrefix(cfg.Tempo.URL, "https://") {
		log.Warn().Str("url", cfg.Tempo.URL).Msg("Tempo URL should start with http:// or https://")
	}

	// Validate certificate files exist if mTLS is enabled
	if cfg.Tempo.UseMutualTLS {
		if cfg.Tempo.Cert != "" {
			if _, err := os.Stat(cfg.Tempo.Cert); os.IsNotExist(err) {
				log.Error().Str("cert", cfg.Tempo.Cert).Msg("Tempo certificate file not found")
			}
		}
		if cfg.Tempo.Key != "" {
			if _, err := os.Stat(cfg.Tempo.Key); os.IsNotExist(err) {
				log.Error().Str("key", cfg.Tempo.Key).Msg("Tempo key file not found")
			}
		}
	}

	log.Debug().
		Str("url", cfg.Tempo.URL).
		Bool("use_mutual_tls", cfg.Tempo.UseMutualTLS).
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
