package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestMigrateAuthConfig_NewConfigOnly tests loading configuration with only the new auth section
func TestMigrateAuthConfig_NewConfigOnly(t *testing.T) {
	app := &App{
		Cfg: &Config{
			Auth: AuthConfig{
				JwksCertURL: "https://auth.example.com/jwks",
				AuthHeader:  "X-Auth-Token",
				Claims: ClaimsConfig{
					Username: "sub",
					Email:    "mail",
					Groups:   "roles",
				},
			},
			Web: WebConfig{}, // No legacy fields
		},
	}

	app.migrateAuthConfig()

	// Verify new auth config is used
	assert.Equal(t, "https://auth.example.com/jwks", app.Cfg.Auth.JwksCertURL)
	assert.Equal(t, "X-Auth-Token", app.Cfg.Auth.AuthHeader)
	assert.Equal(t, "sub", app.Cfg.Auth.Claims.Username)
	assert.Equal(t, "mail", app.Cfg.Auth.Claims.Email)
	assert.Equal(t, "roles", app.Cfg.Auth.Claims.Groups)

	// Verify backward compatibility fields are populated
	assert.Equal(t, "https://auth.example.com/jwks", app.Cfg.Web.JwksCertURL)
	assert.Equal(t, "X-Auth-Token", app.Cfg.Web.AuthHeader)
	assert.Equal(t, "sub", app.Cfg.Web.OAuthUsernameClaim)
	assert.Equal(t, "mail", app.Cfg.Web.OAuthEmailClaim)
	assert.Equal(t, "roles", app.Cfg.Web.OAuthGroupName)
}

// TestMigrateAuthConfig_LegacyConfigOnly tests backward compatibility with legacy web section
func TestMigrateAuthConfig_LegacyConfigOnly(t *testing.T) {
	app := &App{
		Cfg: &Config{
			Auth: AuthConfig{}, // Empty new section
			Web: WebConfig{
				JwksCertURL:        "https://legacy.example.com/jwks",
				AuthHeader:         "Authorization",
				OAuthUsernameClaim: "preferred_username",
				OAuthEmailClaim:    "email",
				OAuthGroupName:     "groups",
			},
		},
	}

	app.migrateAuthConfig()

	// Verify legacy config is migrated to new structure
	assert.Equal(t, "https://legacy.example.com/jwks", app.Cfg.Auth.JwksCertURL)
	assert.Equal(t, "Authorization", app.Cfg.Auth.AuthHeader)
	assert.Equal(t, "preferred_username", app.Cfg.Auth.Claims.Username)
	assert.Equal(t, "email", app.Cfg.Auth.Claims.Email)
	assert.Equal(t, "groups", app.Cfg.Auth.Claims.Groups)

	// Verify backward compatibility fields are maintained
	assert.Equal(t, "https://legacy.example.com/jwks", app.Cfg.Web.JwksCertURL)
	assert.Equal(t, "Authorization", app.Cfg.Web.AuthHeader)
}

// TestMigrateAuthConfig_MixedConfig tests behavior when both new and legacy config present
func TestMigrateAuthConfig_MixedConfig(t *testing.T) {
	app := &App{
		Cfg: &Config{
			Auth: AuthConfig{
				JwksCertURL: "https://new.example.com/jwks",
				Claims: ClaimsConfig{
					Username: "new_username",
				},
			},
			Web: WebConfig{
				JwksCertURL:        "https://old.example.com/jwks",
				OAuthUsernameClaim: "old_username",
			},
		},
	}

	app.migrateAuthConfig()

	// Verify new config takes precedence
	assert.Equal(t, "https://new.example.com/jwks", app.Cfg.Auth.JwksCertURL)
	assert.Equal(t, "new_username", app.Cfg.Auth.Claims.Username)

	// Defaults should be set for missing fields
	assert.Equal(t, "Authorization", app.Cfg.Auth.AuthHeader)
	assert.Equal(t, "email", app.Cfg.Auth.Claims.Email)
	assert.Equal(t, "groups", app.Cfg.Auth.Claims.Groups)
}

// TestMigrateAuthConfig_Defaults tests that defaults are applied correctly
func TestMigrateAuthConfig_Defaults(t *testing.T) {
	app := &App{
		Cfg: &Config{
			Auth: AuthConfig{
				JwksCertURL: "https://auth.example.com/jwks",
				// All other fields empty - should get defaults
			},
			Web: WebConfig{},
		},
	}

	app.migrateAuthConfig()

	// Verify defaults are applied
	assert.Equal(t, "Authorization", app.Cfg.Auth.AuthHeader)
	assert.Equal(t, "preferred_username", app.Cfg.Auth.Claims.Username)
	assert.Equal(t, "email", app.Cfg.Auth.Claims.Email)
	assert.Equal(t, "groups", app.Cfg.Auth.Claims.Groups)

	// Verify JWKS URL is preserved
	assert.Equal(t, "https://auth.example.com/jwks", app.Cfg.Auth.JwksCertURL)
}

// TestMigrateAuthConfig_PartialLegacyConfig tests partial legacy configuration
func TestMigrateAuthConfig_PartialLegacyConfig(t *testing.T) {
	app := &App{
		Cfg: &Config{
			Auth: AuthConfig{},
			Web: WebConfig{
				JwksCertURL:        "https://legacy.example.com/jwks",
				OAuthUsernameClaim: "unique_name", // Only username customized
				// Other fields empty - should get defaults
			},
		},
	}

	app.migrateAuthConfig()

	// Verify migrated custom value
	assert.Equal(t, "unique_name", app.Cfg.Auth.Claims.Username)

	// Verify defaults for non-customized fields
	assert.Equal(t, "Authorization", app.Cfg.Auth.AuthHeader)
	assert.Equal(t, "email", app.Cfg.Auth.Claims.Email)
	assert.Equal(t, "groups", app.Cfg.Auth.Claims.Groups)
}

// TestMigrateAuthConfig_AzureADConfig tests Azure AD style configuration
func TestMigrateAuthConfig_AzureADConfig(t *testing.T) {
	app := &App{
		Cfg: &Config{
			Auth: AuthConfig{
				JwksCertURL: "https://login.microsoftonline.com/tenant/discovery/v2.0/keys",
				Claims: ClaimsConfig{
					Username: "unique_name",
					Email:    "upn",
					Groups:   "roles",
				},
			},
			Web: WebConfig{},
		},
	}

	app.migrateAuthConfig()

	// Verify Azure AD claim mappings
	assert.Equal(t, "unique_name", app.Cfg.Auth.Claims.Username)
	assert.Equal(t, "upn", app.Cfg.Auth.Claims.Email)
	assert.Equal(t, "roles", app.Cfg.Auth.Claims.Groups)
}

// TestMigrateAuthConfig_Auth0Config tests Auth0 style configuration with namespaced claims
func TestMigrateAuthConfig_Auth0Config(t *testing.T) {
	app := &App{
		Cfg: &Config{
			Auth: AuthConfig{
				JwksCertURL: "https://example.auth0.com/.well-known/jwks.json",
				Claims: ClaimsConfig{
					Username: "nickname",
					Email:    "email",
					Groups:   "https://example.com/groups",
				},
			},
			Web: WebConfig{},
		},
	}

	app.migrateAuthConfig()

	// Verify Auth0 claim mappings including namespaced groups
	assert.Equal(t, "nickname", app.Cfg.Auth.Claims.Username)
	assert.Equal(t, "email", app.Cfg.Auth.Claims.Email)
	assert.Equal(t, "https://example.com/groups", app.Cfg.Auth.Claims.Groups)
}

// TestMigrateAuthConfig_BackwardCompatibilityFields tests that legacy fields remain accessible
func TestMigrateAuthConfig_BackwardCompatibilityFields(t *testing.T) {
	app := &App{
		Cfg: &Config{
			Auth: AuthConfig{
				JwksCertURL: "https://auth.example.com/jwks",
				AuthHeader:  "X-Custom-Auth",
				Claims: ClaimsConfig{
					Username: "sub",
					Email:    "mail",
					Groups:   "roles",
				},
			},
			Web: WebConfig{},
		},
	}

	app.migrateAuthConfig()

	// Verify legacy fields are populated for backward compatibility
	// This allows existing code that references a.Cfg.Web.* to continue working
	assert.Equal(t, app.Cfg.Auth.JwksCertURL, app.Cfg.Web.JwksCertURL)
	assert.Equal(t, app.Cfg.Auth.AuthHeader, app.Cfg.Web.AuthHeader)
	assert.Equal(t, app.Cfg.Auth.Claims.Username, app.Cfg.Web.OAuthUsernameClaim)
	assert.Equal(t, app.Cfg.Auth.Claims.Email, app.Cfg.Web.OAuthEmailClaim)
	assert.Equal(t, app.Cfg.Auth.Claims.Groups, app.Cfg.Web.OAuthGroupName)
}

// TestMigrateAuthConfig_EmptyConfig tests behavior with completely empty configuration
func TestMigrateAuthConfig_EmptyConfig(t *testing.T) {
	app := &App{
		Cfg: &Config{
			Auth: AuthConfig{},
			Web:  WebConfig{},
		},
	}

	app.migrateAuthConfig()

	// Verify all defaults are applied
	assert.Equal(t, "Authorization", app.Cfg.Auth.AuthHeader)
	assert.Equal(t, "preferred_username", app.Cfg.Auth.Claims.Username)
	assert.Equal(t, "email", app.Cfg.Auth.Claims.Email)
	assert.Equal(t, "groups", app.Cfg.Auth.Claims.Groups)
}
