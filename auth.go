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

// AlertAccess is a caller's level of access to the ruler and Alertmanager routes.
type AlertAccess int

const (
	// AlertAccessNone reads an empty result set and cannot write.
	AlertAccessNone AlertAccess = iota
	// AlertAccessRead may list rules, alert instances and silences.
	AlertAccessRead
	// AlertAccessWrite may additionally create and expire silences and write the
	// Alertmanager configuration.
	AlertAccessWrite
)

// alertingAccess resolves a caller's access to the ruler and Alertmanager routes from
// their group membership.
//
// The admin group always implies write access. Note this does not consult
// admin.bypass: that flag governs whether admins skip label enforcement on queries, and
// these routes carry no query to enforce.
func alertingAccess(token OAuthToken, a *App) AlertAccess {
	if a.Cfg.Admin.Group != "" && ContainsIgnoreCase(token.Groups, a.Cfg.Admin.Group) {
		return AlertAccessWrite
	}
	if containsAnyIgnoreCase(token.Groups, a.Cfg.Alerting.AdminGroups) {
		return AlertAccessWrite
	}
	if containsAnyIgnoreCase(token.Groups, a.Cfg.Alerting.ViewerGroups) {
		return AlertAccessRead
	}
	return AlertAccessNone
}

// containsAnyIgnoreCase reports whether groups contains any of wanted, ignoring case.
// Empty entries in wanted never match, so an unset config grants nothing.
func containsAnyIgnoreCase(groups []string, wanted []string) bool {
	for _, w := range wanted {
		if w == "" {
			continue
		}
		if ContainsIgnoreCase(groups, w) {
			return true
		}
	}
	return false
}
