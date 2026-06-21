package main

import (
	"fmt"
	"net/http"
	"strings"
	"unicode"

	"github.com/rs/zerolog/log"

	"github.com/golang-jwt/jwt/v5"
)

// OAuthToken represents the structure of an OAuth token.
// It holds user-related information extracted from the token.
type OAuthToken struct {
	Groups            []string `json:"-,omitempty"`
	PreferredUsername string   `json:"preferred_username"`
	Email             string   `json:"email"`
	jwt.RegisteredClaims
}

// UserIdentity represents the minimal identity information needed for label lookup.
// This is authentication-agnostic and focuses on the authorization concern.
type UserIdentity struct {
	Username string   // Primary user identifier
	Groups   []string // Group memberships for the user
}

// ToIdentity extracts the identity information from an OAuth token.
// This helper encapsulates the conversion from authentication-specific
// token format to the authorization-focused identity representation.
func (t OAuthToken) ToIdentity() UserIdentity {
	return UserIdentity{
		Username: t.PreferredUsername,
		Groups:   t.Groups,
	}
}

// getIdentity resolves the caller identity for label-policy lookup.
//
// When trusted-client-header mode is enabled (auth.trusted_client_header.enabled)
// and the configured header is present, the verified client CN — forwarded by the
// mTLS-terminating ingress — is used as the identity, bypassing JWT validation.
// This supports machine clients that cannot present an OIDC token (e.g. the Ceph
// dashboard via an mTLS sidecar). The CN is used as the username, so a labels.yaml
// entry keyed by the CN drives the label policy. Otherwise it falls back to JWT
// validation via getToken.
//
// SECURITY: the CN header is trusted implicitly. See TrustedClientHeaderConfig —
// the fronting ingress must enforce mTLS, overwrite any client-supplied header
// value from the verified certificate, and be the only path to the proxy.
func getIdentity(r *http.Request, a *App) (OAuthToken, error) {
	// Mode B: certificate-based identity + configurable admission (preferred when enabled).
	if a.Cfg.Auth.ClientCert.Enabled {
		cert, err := clientCertFromRequest(r, &a.Cfg.Auth.ClientCert)
		if err != nil {
			return OAuthToken{}, err
		}
		if cert != nil {
			claims := extractCertClaims(cert)
			if err := Admit(claims, a.Cfg.Auth.ClientCert.Admission); err != nil {
				log.Warn().Err(err).Str("cn", claims.CN).Str("template_oid", claims.TemplateOID).Msg("Client cert admission denied")
				return OAuthToken{}, err
			}
			id := identityFromClaims(claims, a.Cfg.Auth.ClientCert.IdentityFrom)
			if id == "" {
				return OAuthToken{}, fmt.Errorf("client cert admitted but identity field %q is empty", a.Cfg.Auth.ClientCert.IdentityFrom)
			}
			log.Debug().Str("identity", id).Str("field", a.Cfg.Auth.ClientCert.IdentityFrom).Msg("Identity from client certificate")
			return OAuthToken{PreferredUsername: id}, nil
		}
		// No client cert presented — fall through to other auth methods (mixed deployments).
	}

	if a.Cfg.Auth.TrustedClientHeader.Enabled {
		cn := strings.TrimSpace(r.Header.Get(a.Cfg.Auth.TrustedClientHeader.CNHeader))
		if cn != "" {
			log.Debug().Str("cn", cn).Str("header", a.Cfg.Auth.TrustedClientHeader.CNHeader).Msg("Identity from trusted client header")
			return OAuthToken{PreferredUsername: cn}, nil
		}
	}
	return getToken(r, a)
}

// getToken retrieves the OAuth token from the incoming HTTP request.
// It extracts, parses, and validates the token from the configured authentication header.
func getToken(r *http.Request, a *App) (OAuthToken, error) {
	scheme := strings.TrimSpace(a.Cfg.Auth.AuthScheme)
	primaryHeader := a.Cfg.Web.AuthHeader
	primaryValue := r.Header.Get(primaryHeader)
	log.Trace().Str("header", primaryHeader).Str("value", primaryValue).Msg("Auth header value")

	if primaryValue != "" {
		tokenString, err := extractTokenValue(primaryValue, scheme, primaryHeader)
		if err != nil {
			return OAuthToken{}, err
		}
		return parseAndValidateToken(tokenString, a)
	}

	if a.Cfg.Alert.Enabled {
		alertHeader := a.Cfg.Alert.TokenHeader
		alertValue := r.Header.Get(alertHeader)
		if alertValue == "" {
			return OAuthToken{}, fmt.Errorf("no %s header found", primaryHeader)
		}
		log.Trace().Str("header", alertHeader).Str("value", alertValue).Msg("Alert header value")
		tokenString, err := extractTokenValue(alertValue, scheme, alertHeader)
		if err != nil {
			return OAuthToken{}, err
		}
		return parseAndValidateToken(tokenString, a)
	}

	return OAuthToken{}, fmt.Errorf("no %s header found", primaryHeader)
}

func parseAndValidateToken(tokenString string, a *App) (OAuthToken, error) {
	oauthToken, token, err := parseJwtToken(tokenString, a)
	if err != nil {
		return OAuthToken{}, fmt.Errorf("error parsing token")
	}
	if !token.Valid {
		return OAuthToken{}, fmt.Errorf("invalid token")
	}
	return oauthToken, nil
}

func extractTokenValue(headerValue, scheme, headerName string) (string, error) {
	value := strings.TrimSpace(headerValue)
	if value == "" {
		return "", fmt.Errorf("invalid %s header", headerName)
	}

	if strings.TrimSpace(scheme) == "" {
		return value, nil
	}

	if !strings.HasPrefix(value, scheme) {
		return "", fmt.Errorf("invalid %s header", headerName)
	}

	remainder := value[len(scheme):]
	if len(remainder) == 0 {
		return "", fmt.Errorf("invalid %s header", headerName)
	}

	if !unicode.IsSpace(rune(remainder[0])) {
		return "", fmt.Errorf("invalid %s header", headerName)
	}

	token := strings.TrimSpace(remainder)
	if token == "" {
		return "", fmt.Errorf("invalid %s header", headerName)
	}
	return token, nil
}

// parseJwtToken parses the JWT token string and constructs an OAuthToken from the parsed claims.
// It returns the constructed OAuthToken, the parsed jwt.Token, and any error that occurred during parsing.
func parseJwtToken(tokenString string, a *App) (OAuthToken, *jwt.Token, error) {
	var oAuthToken OAuthToken
	var claimsMap jwt.MapClaims

	token, err := jwt.ParseWithClaims(tokenString, &claimsMap, a.Jwks.Keyfunc)
	if err != nil {
		log.Error().Err(err).Msg("Error parsing token")
		return oAuthToken, nil, err
	}

	if !token.Valid {
		log.Trace().Msg("Token is invalid")
	}

	// Issuer check (exact match). Defends against tokens signed by the trusted keys but
	// issued by an unexpected issuer. Skipped when unset.
	if want := a.Cfg.Auth.Issuer; want != "" {
		got, _ := claimsMap["iss"].(string)
		if got != want {
			log.Warn().Str("iss", got).Msg("Token issuer not accepted")
			return oAuthToken, token, fmt.Errorf("invalid issuer")
		}
	}

	// Audience check (any-match). Defends against tokens minted for a different resource
	// (e.g. an ARM token) that would otherwise pass on signature+expiry alone. Skipped when
	// unset. `aud` may be a string or an array per the JWT spec.
	if len(a.Cfg.Auth.Audiences) > 0 {
		if !audienceMatches(claimsMap["aud"], a.Cfg.Auth.Audiences) {
			log.Warn().Interface("aud", claimsMap["aud"]).Msg("Token audience not accepted")
			return oAuthToken, token, fmt.Errorf("invalid audience")
		}
	}

	if v, ok := claimsMap[a.Cfg.Web.OAuthUsernameClaim].(string); ok {
		oAuthToken.PreferredUsername = v
		log.Trace().Str("claim", a.Cfg.Web.OAuthUsernameClaim).Str("value", v).Msg("Username claim")
	}

	if v, ok := claimsMap[a.Cfg.Web.OAuthEmailClaim].(string); ok {
		if !strings.Contains(v, "@") {
			log.Warn().Str("claim", a.Cfg.Web.OAuthEmailClaim).Str("value", v).Msg("Email does not contain '@', therefore not an email. Could be sus")
		}
		log.Trace().Str("claim", a.Cfg.Web.OAuthEmailClaim).Str("value", v).Msg("Email claim")
		oAuthToken.Email = v
	}

	if v, ok := claimsMap[a.Cfg.Web.OAuthGroupName].([]interface{}); ok {
		for _, item := range v {
			if s, ok := item.(string); ok {
				log.Trace().Str("claim", a.Cfg.Web.OAuthGroupName).Str("group", s).Msg("Group claim")
				oAuthToken.Groups = append(oAuthToken.Groups, s)
			}
		}
	}

	return oAuthToken, token, err
}

// audienceMatches reports whether the token's `aud` claim (a string or array of strings,
// per RFC 7519) contains any of the allowed audiences.
func audienceMatches(claim interface{}, allowed []string) bool {
	var auds []string
	switch v := claim.(type) {
	case string:
		auds = []string{v}
	case []interface{}:
		for _, item := range v {
			if s, ok := item.(string); ok {
				auds = append(auds, s)
			}
		}
	case []string:
		auds = v
	}
	for _, got := range auds {
		for _, want := range allowed {
			if got == want {
				return true
			}
		}
	}
	return false
}

// validateLabelPolicy retrieves and validates the label policy for the user.
// It checks if the user is an admin and skips label enforcement if true.
// Returns the LabelPolicy, a boolean indicating whether label enforcement should be skipped,
// and any error that occurred during validation.
func validateLabelPolicy(token OAuthToken, a *App) (*LabelPolicy, bool, error) {
	if isAdmin(token, a) {
		log.Debug().Str("user", token.PreferredUsername).Bool("Admin", true).Msg("Skipping label enforcement")
		return nil, true, nil
	}

	policy, err := a.LabelStore.GetLabelPolicy(token.ToIdentity(), "")
	if err != nil {
		return nil, false, fmt.Errorf("error getting label policy: %w", err)
	}

	// Check for cluster-wide access
	if policy.HasClusterWideAccess() {
		log.Debug().Str("user", token.PreferredUsername).Bool("ClusterWide", true).Msg("Skipping label enforcement")
		return nil, true, nil
	}

	log.Debug().Str("user", token.PreferredUsername).Int("rules", len(policy.Rules)).Str("logic", policy.Logic).Msg("Label policy retrieved")

	if len(policy.Rules) < 1 {
		return nil, false, fmt.Errorf("no label rules found")
	}
	return policy, false, nil
}

func isAdmin(token OAuthToken, a *App) bool {
	return ContainsIgnoreCase(token.Groups, a.Cfg.Admin.Group) && a.Cfg.Admin.Bypass
}
