package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// Static keys are long-lived shared secrets for callers that cannot obtain an
// expiring token: SaaS exporters configured with fixed headers, data sources in a UI
// that has no signed-in user, scripts on hosts without an identity provider client.
//
// Only the SHA-256 of each key is configured, as 64 lowercase hex characters, so the
// configuration itself is not a secret. A key is presented the same way as a JWT
// (auth.auth_header, auth.auth_scheme). Read keys (auth.static_keys) and write keys
// (ingest.static_keys) are separate maps: a write key never reads and a read key never
// writes. Several hashes may map to the same identity or writer, so a key can be
// rotated without downtime.
//
// A static key never expires on its own. Keep each one narrowly scoped and rotate it.

var sha256HexPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// errStaticKeyClusterWide refuses a cluster-wide (enforcement-bypassing) policy to an
// identity that authenticated with a static key.
var errStaticKeyClusterWide = errors.New("static-key identities cannot have cluster-wide access")

// bearerValue returns the credential presented in the configured auth header and
// scheme, or "" when it is absent or malformed.
func bearerValue(r *http.Request, a *App) string {
	header := a.Cfg.Web.AuthHeader
	if header == "" {
		header = "Authorization"
	}
	v := r.Header.Get(header)
	if v == "" {
		return ""
	}
	token, err := extractTokenValue(v, strings.TrimSpace(a.Cfg.Auth.AuthScheme), header)
	if err != nil {
		return ""
	}
	return token
}

// staticKeyLookup returns the identity or writer mapped to the SHA-256 of key.
//
// The lookup is by hash, so its timing can at most reveal something about the hash of
// the attacker's own input, never about a configured key.
func staticKeyLookup(keys map[string]string, key string) (string, bool) {
	if len(keys) == 0 || key == "" {
		return "", false
	}
	sum := sha256.Sum256([]byte(key))
	v, ok := keys[hex.EncodeToString(sum[:])]
	return v, ok
}

// validateStaticKeys checks that every entry is a SHA-256 hash mapped to an acceptable
// value. A raw key pasted in place of its hash fails the hash check.
func validateStaticKeys(field string, keys map[string]string, checkValue func(string) error) error {
	for hash, value := range keys {
		if !sha256HexPattern.MatchString(hash) {
			return fmt.Errorf("%s: %q is not a SHA-256 hash (64 lowercase hex characters); configure the hash of the key, never the key", field, abbreviate(hash))
		}
		if err := checkValue(value); err != nil {
			return fmt.Errorf("%s[%s…]: %w", field, hash[:8], err)
		}
	}
	return nil
}

// validateAuthStaticKeys validates auth.static_keys.
func validateAuthStaticKeys(c *Config) error {
	return validateStaticKeys("auth.static_keys", c.Auth.StaticKeys, func(identity string) error {
		if strings.TrimSpace(identity) == "" {
			return errors.New("empty identity")
		}
		return nil
	})
}

// abbreviate shortens a configured value for an error message, so a key pasted in by
// mistake is not written to the log in full.
func abbreviate(s string) string {
	if len(s) <= 8 {
		return s
	}
	return s[:8] + "…"
}
