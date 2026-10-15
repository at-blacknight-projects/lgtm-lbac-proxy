package main

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testKeyHash is the configured form of a static key: its SHA-256 as lowercase hex.
func testKeyHash(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

const (
	readKey  = "read-key-for-tests-0123456789abcdef"
	writeKey = "write-key-for-tests-0123456789abcdef"
)

func TestStaticKeyLookup(t *testing.T) {
	keys := map[string]string{testKeyHash("k1"): "a", testKeyHash("k2"): "a", testKeyHash("k3"): "b"}

	tests := []struct {
		name   string
		keys   map[string]string
		key    string
		want   string
		wantOK bool
	}{
		{"configured key", keys, "k3", "b", true},
		// Two keys for one identity: how a key rotates without downtime.
		{"rotation: old key", keys, "k1", "a", true},
		{"rotation: new key", keys, "k2", "a", true},
		{"unknown key", keys, "k4", "", false},
		{"empty key", keys, "", "", false},
		{"no keys configured", nil, "k1", "", false},
		// The hash itself is not a credential.
		{"presenting the hash", keys, testKeyHash("k1"), "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := staticKeyLookup(tt.keys, tt.key)
			assert.Equal(t, tt.wantOK, ok)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestValidateAuthStaticKeys(t *testing.T) {
	tests := []struct {
		name    string
		keys    map[string]string
		wantErr string
	}{
		{"off", nil, ""},
		{"valid", map[string]string{testKeyHash("k"): "public-viewer"}, ""},
		{"raw key", map[string]string{"a-raw-key-pasted-in-by-mistake": "public-viewer"}, "not a SHA-256 hash"},
		{"empty identity", map[string]string{testKeyHash("k"): " "}, "empty identity"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAuthStaticKeys(&Config{Auth: AuthConfig{StaticKeys: tt.keys}})
			if tt.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			if assert.Error(t, err) {
				assert.Contains(t, err.Error(), tt.wantErr)
			}
		})
	}
}

// A raw key pasted where its hash belongs must not end up in the log in full.
func TestValidateStaticKeysDoesNotEchoAKey(t *testing.T) {
	key := "super-secret-raw-key-value-that-must-not-be-logged"
	err := validateAuthStaticKeys(&Config{Auth: AuthConfig{StaticKeys: map[string]string{key: "x"}}})
	require.Error(t, err)
	assert.NotContains(t, err.Error(), key)
}

// Both maps as the chart renders them must load through viper as WithConfig loads it,
// and still match a presented key afterwards (viper lowercases map keys; hashes are
// configured lowercase so nothing changes).
func TestStaticKeysLoadFromRenderedYAML(t *testing.T) {
	rendered := `
auth:
  static_keys:
    "` + testKeyHash(readKey) + `": "public-viewer"
ingest:
  static_keys:
    "` + testKeyHash(writeKey) + `": "app-b"
`
	v := viper.NewWithOptions(viper.KeyDelimiter("::"))
	v.SetConfigType("yaml")
	require.NoError(t, v.ReadConfig(strings.NewReader(rendered)))
	cfg := &Config{}
	require.NoError(t, v.Unmarshal(cfg))

	assert.NoError(t, validateAuthStaticKeys(cfg))
	id, ok := staticKeyLookup(cfg.Auth.StaticKeys, readKey)
	assert.True(t, ok)
	assert.Equal(t, "public-viewer", id)
	writer, ok := staticKeyLookup(cfg.Ingest.StaticKeys, writeKey)
	assert.True(t, ok)
	assert.Equal(t, "app-b", writer)
}

func TestBearerValue(t *testing.T) {
	app := &App{Cfg: &Config{
		Web:  WebConfig{AuthHeader: "Authorization"},
		Auth: AuthConfig{AuthScheme: "Bearer"},
	}}
	tests := []struct {
		name   string
		header string
		want   string
	}{
		{"bearer", "Bearer abc", "abc"},
		{"no header", "", ""},
		{"wrong scheme", "Basic abc", ""},
		{"scheme only", "Bearer", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.header != "" {
				r.Header.Set("Authorization", tt.header)
			}
			assert.Equal(t, tt.want, bearerValue(r, app))
		})
	}
}

// staticReadApp is the shared test app (real JWT validation, label store with
// group1/group2/user/admins entries) with a read key for identity `group1` and one for
// an identity whose entry is cluster-wide.
func staticReadApp(t *testing.T) (*App, map[string]string) {
	t.Helper()
	app, tokens := setupTestMain()
	app.Cfg.Auth.AuthScheme = "Bearer"
	app.Cfg.Auth.StaticKeys = map[string]string{
		testKeyHash(readKey):         "group1",
		testKeyHash("admin-ish-key"): "cluster-wide-entry",
	}
	parser := NewPolicyParser()
	policy, err := parser.ParseUserPolicy(RawLabelData{
		"_rules": []interface{}{map[string]interface{}{
			"name": "#cluster-wide", "operator": "=", "values": []interface{}{"true"},
		}},
	}, "")
	require.NoError(t, err)
	app.LabelStore.(*FileLabelStore).policyCache["entry:cluster-wide-entry"] = policy
	return &app, tokens
}

func TestGetIdentityFromStaticReadKey(t *testing.T) {
	app, tokens := staticReadApp(t)

	t.Run("key resolves to its identity, with no groups", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Authorization", "Bearer "+readKey)
		token, err := getIdentity(r, app)
		require.NoError(t, err)
		assert.Equal(t, "group1", token.PreferredUsername)
		assert.Empty(t, token.Groups)
		assert.True(t, token.viaStaticKey)
		assert.False(t, isAdmin(token, app))
	})

	t.Run("a JWT still works alongside keys", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Authorization", "Bearer "+tokens["userTenant"])
		token, err := getIdentity(r, app)
		require.NoError(t, err)
		assert.Equal(t, "user", token.PreferredUsername)
		assert.False(t, token.viaStaticKey)
	})

	t.Run("an unknown key falls through to JWT validation and fails", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Authorization", "Bearer not-a-configured-key")
		_, err := getIdentity(r, app)
		assert.Error(t, err)
	})

	// Read and write keys are separate maps.
	t.Run("a write key is not a read key", func(t *testing.T) {
		app.Cfg.Ingest.StaticKeys = map[string]string{testKeyHash(writeKey): "app-a"}
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Authorization", "Bearer "+writeKey)
		_, err := getIdentity(r, app)
		assert.Error(t, err)
	})
}

func TestStaticReadKeyScopedByPolicy(t *testing.T) {
	app, _ := staticReadApp(t)

	token := OAuthToken{PreferredUsername: "group1", viaStaticKey: true}
	policy, skip, err := validateLabelPolicy(token, app)
	require.NoError(t, err)
	assert.False(t, skip, "a static-key identity must be enforced")
	require.NotNil(t, policy)
	assert.NotEmpty(t, policy.Rules)
}

// However its labels.yaml entry is written, a static key never bypasses enforcement.
func TestStaticReadKeyNeverClusterWide(t *testing.T) {
	app, _ := staticReadApp(t)

	_, _, err := validateLabelPolicy(OAuthToken{PreferredUsername: "cluster-wide-entry", viaStaticKey: true}, app)
	assert.ErrorIs(t, err, errStaticKeyClusterWide)

	// The same entry via a JWT identity is unaffected.
	_, skip, err := validateLabelPolicy(OAuthToken{PreferredUsername: "cluster-wide-entry"}, app)
	require.NoError(t, err)
	assert.True(t, skip)
}

// End to end on the read router: a static key queries, scoped to its identity's policy.
func TestStaticReadKeyEndToEnd(t *testing.T) {
	app, _ := staticReadApp(t)
	app.WithRoutes()

	r := httptest.NewRequest(http.MethodGet, "/api/v1/query?query=up", nil)
	r.Header.Set("Authorization", "Bearer "+readKey)
	rec := httptest.NewRecorder()
	app.e.ServeHTTP(rec, r)
	assert.Equal(t, http.StatusOK, rec.Code)

	// A label outside the identity's policy is refused.
	r = httptest.NewRequest(http.MethodGet, `/api/v1/query?query=up{tenant_id="not_allowed"}`, nil)
	r.Header.Set("Authorization", "Bearer "+readKey)
	rec = httptest.NewRecorder()
	app.e.ServeHTTP(rec, r)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestStaticWriteKey(t *testing.T) {
	srv, got := fakeReceiver(t, http.StatusOK, "")
	app, tokens := ingestHandlerApp(t, map[string]string{"group1": "app-a"}, srv.URL, func(c *IngestConfig) {
		c.StaticKeys = map[string]string{testKeyHash(writeKey): "app-k"}
	})
	app.Cfg.Auth.AuthScheme = "Bearer"

	t.Run("key pushes as its writer, with its credential stripped", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/v1/metrics", strings.NewReader("x"))
		req.Header.Set("Authorization", "Bearer "+writeKey)
		req.Header.Set(defaultIngestWriterHeader, "someone-else")
		require.Equal(t, http.StatusOK, serveIngest(app, req).Code)
		p := receive(t, got)
		assert.Equal(t, []string{"app-k"}, p.header.Values(defaultIngestWriterHeader))
		assert.Empty(t, p.header.Get("Authorization"))
	})

	t.Run("JWT writers still work alongside keys", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/v1/metrics", strings.NewReader("x"))
		req.Header.Set("Authorization", "Bearer "+tokens["groupTenant"])
		require.Equal(t, http.StatusOK, serveIngest(app, req).Code)
		assert.Equal(t, []string{"app-a"}, receive(t, got).header.Values(defaultIngestWriterHeader))
	})

	t.Run("an unknown key is refused", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/v1/metrics", strings.NewReader("x"))
		req.Header.Set("Authorization", "Bearer not-a-configured-key")
		assert.Equal(t, http.StatusForbidden, serveIngest(app, req).Code)
	})

	t.Run("a read key cannot write", func(t *testing.T) {
		app.Cfg.Auth.StaticKeys = map[string]string{testKeyHash(readKey): "group1"}
		req := httptest.NewRequest(http.MethodPost, "/v1/metrics", strings.NewReader("x"))
		req.Header.Set("Authorization", "Bearer "+readKey)
		assert.Equal(t, http.StatusForbidden, serveIngest(app, req).Code)
	})
}
