package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func genJWKS(username, email string, groups []string, pk *ecdsa.PrivateKey) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"preferred_username": username,
		"email":              email,
		"groups":             groups,
	})
	token.Header["kid"] = "testKid"
	return token.SignedString(pk)
}

// genJWKSWithCustomClaims generates a JWT token with custom claim names
func genJWKSWithCustomClaims(claims map[string]interface{}, pk *ecdsa.PrivateKey) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims(claims))
	token.Header["kid"] = "testKid"
	return token.SignedString(pk)
}

// setupTestMainWithPrivateKey returns app, tokens, and private key for custom claim testing
// setupTestMain initializes test environment without returning the private key
func setupTestMain() (App, map[string]string) {
	app, tokens, _ := setupTestMainWithPrivateKey()
	return app, tokens
}

// setupTestMainWithPrivateKey initializes test environment and returns the private key for custom claims testing
func setupTestMainWithPrivateKey() (App, map[string]string, *ecdsa.PrivateKey) {
	// Generate a new private key.
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Printf("Failed to generate private key: %s\n", err)
		return App{}, nil, nil
	}

	// Encode the private key to PEM format.
	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		fmt.Printf("Failed to marshal private key: %s\n", err)
		return App{}, nil, nil
	}
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	// Encode the public key to PEM format.
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		fmt.Printf("Failed to marshal public key: %s\n", err)
		return App{}, nil, nil
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	// Generate a key pair
	pk, _ := jwt.ParseECPrivateKeyFromPEM(privateKeyPEM)
	pubkey, _ := jwt.ParseECPublicKeyFromPEM(publicKeyPEM)

	jwks := []struct {
		name     string
		Username string
		Email    string
		Groups   []string
	}{
		{
			name:     "noTenant",
			Username: "not-a-user",
			Email:    "test@email.com",
			Groups:   []string{},
		},
		{
			name:     "userTenant",
			Username: "user",
			Email:    "test@email.com",
			Groups:   []string{""},
		},
		{
			name:     "groupTenant",
			Username: "not-a-user",
			Email:    "test@email.com",
			Groups:   []string{"group1"},
		},
		{
			name:     "groupsTenant",
			Username: "not-a-user",
			Email:    "test@email.com",
			Groups:   []string{"group1", "group2"},
		},
		{
			name:     "noGroupsTenant",
			Username: "test-user",
			Email:    "test@email.com",
			Groups:   []string{},
		},
		{
			name:     "userAndGroupTenant",
			Username: "user",
			Email:    "test@email.com",
			Groups:   []string{"group1", "group2"},
		},
		{
			name:     "adminUserToken",
			Username: "admin",
			Email:    "admin-email@example.com",
			Groups:   []string{"admins"},
		},
		{
			name:     "userWithOutProperEmail",
			Username: "not-an-email",
			Email:    "testmail",
			Groups:   []string{"group1"},
		},
	}
	tokens := make(map[string]string, len(jwks))
	for _, jwk := range jwks {
		token, _ := genJWKS(jwk.Username, jwk.Email, jwk.Groups, pk)
		tokens[jwk.name] = token
	}

	// Base64url encoding of the fixed-width coordinates (RFC 7518 6.2.1.2). Bytes returns
	// the uncompressed point 0x04 || X || Y, 32 bytes each on P-256; big.Int.Bytes would
	// drop leading zeros and give a short coordinate for some keys.
	point, err := pubkey.Bytes()
	if err != nil {
		fmt.Printf("Failed to encode public key: %s\n", err)
		return App{}, nil, nil
	}
	x := base64.RawURLEncoding.EncodeToString(point[1:33])
	y := base64.RawURLEncoding.EncodeToString(point[33:65])

	// Set up the JWKS server
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := fmt.Fprintf(w, `{"keys":[{"kty":"EC","kid":"testKid","alg":"ES256","use":"sig","x":"%s","y":"%s","crv":"P-256"}]}`, x, y)
		if err != nil {
			return
		}
	}))
	app := App{}
	app.WithConfig()
	// defer jwksServer.Close()
	app.Cfg().Web.JwksCertURL = jwksServer.URL
	app.WithJWKS()

	// Set up the upstream server
	upstreamServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := fmt.Fprintln(w, "Upstream server response")
		if err != nil {
			return
		}
	}))
	// defer upstreamServer.Close()
	app.Cfg().Thanos.URL = upstreamServer.URL
	app.Cfg().Loki.URL = upstreamServer.URL

	// Create a mock label store with pre-parsed policies (eager parsing)
	parser := NewPolicyParser()
	policyCache := make(map[string]*LabelPolicy)

	// Pre-parse all policies as they would be during loadLabels()
	rawData := map[string]RawLabelData{
		"user": {
			"_rules": []interface{}{
				map[string]interface{}{
					"name":     "tenant_id",
					"operator": "=",
					"values":   []interface{}{"allowed_user", "also_allowed_user"},
				},
			},
		},
		"group1": {
			"_rules": []interface{}{
				map[string]interface{}{
					"name":     "tenant_id",
					"operator": "=",
					"values":   []interface{}{"allowed_group1", "also_allowed_group1"},
				},
			},
		},
		"group2": {
			"_rules": []interface{}{
				map[string]interface{}{
					"name":     "tenant_id",
					"operator": "=",
					"values":   []interface{}{"allowed_group2", "also_allowed_group2"},
				},
			},
		},
		"admins": {
			"_rules": []interface{}{
				map[string]interface{}{
					"name":     "tenant_id",
					"operator": "=",
					"values":   []interface{}{"admin_label"},
				},
			},
		},
	}

	// Parse all policies eagerly
	for key, data := range rawData {
		policy, err := parser.ParseUserPolicy(data, "")
		if err != nil {
			log.Fatal().Err(err).Str("key", key).Msg("Failed to parse policy in test setup")
		}
		cacheKey := "entry:" + key
		policyCache[cacheKey] = policy
	}

	cmh := newTestLabelStore(parser, policyCache)

	app.LabelStore = cmh
	// Set up a mock TLS config for testing (WithTLSConfig() requires system CA files)
	app.TlS = &tls.Config{
		InsecureSkipVerify: true,
	}
	app.WithProxies()
	return app, tokens, pk
}

func Test_reverseProxy(t *testing.T) {
	app, tokens := setupTestMain()
	log.Level(2)

	cases := []struct {
		name             string
		setAuthorization bool
		authorization    string
		expectedStatus   int
		expectedBody     string
		URL              string
	}{
		{
			name:           "Missing_headers",
			URL:            "/api/v1/query_range",
			expectedStatus: http.StatusForbidden,
			expectedBody:   "no Authorization header found\n",
		},
		{
			name:             "Malformed_authorization_header:_B",
			expectedStatus:   http.StatusForbidden,
			setAuthorization: true,
			URL:              "/api/v1/query_range",
			authorization:    "B",
			expectedBody:     "invalid Authorization header\n",
		},
		{
			name:             "Malformed_authorization_header:_Bearer",
			expectedStatus:   http.StatusForbidden,
			setAuthorization: true,
			URL:              "/api/v1/query_range",
			authorization:    "Bearer ",
			expectedBody:     "invalid Authorization header\n",
		},
		{
			name:             "Malformed_authorization_header:_Bearer_skk",
			expectedStatus:   http.StatusForbidden,
			setAuthorization: true,
			URL:              "/api/v1/query_range",
			authorization:    "Bearer " + "skk",
			expectedBody:     "error parsing token\n",
		},
		{
			name:             "Missing_tenant_labels_for_user",
			expectedStatus:   http.StatusForbidden,
			setAuthorization: true,
			URL:              "/api/v1/query_range",
			authorization:    "Bearer " + tokens["noTenant"],
			expectedBody:     "error getting label policy",
		},
		{
			name:             "Valid_token_and_headers_no_query",
			authorization:    "Bearer " + tokens["userTenant"],
			setAuthorization: true,
			URL:              "/api/v1/query_range",
			expectedStatus:   http.StatusOK,
			expectedBody:     "Upstream server response\n",
		},
		{
			name:             "User_belongs_to_multiple_groups_accessing_forbidden_tenant",
			authorization:    "Bearer " + tokens["groupTenant"],
			setAuthorization: true,
			URL:              "/api/v1/query_range?query=up{tenant_id=\"forbidden_tenant\"}",
			expectedStatus:   http.StatusForbidden,
			expectedBody:     "unauthorized tenant_id",
		},
		{
			name:             "Not_a_User_accessing_forbidden_tenant",
			authorization:    "Bearer " + tokens["noTenant"],
			setAuthorization: true,
			URL:              "/api/v1/query_range?query=up{tenant_id=\"forbidden_tenant\"}",
			expectedStatus:   http.StatusForbidden,
			expectedBody:     "error getting label policy",
		},
		{
			name:             "User_belongs_to_no_groups_accessing_forbidden_tenant",
			authorization:    "Bearer " + tokens["noGroupsTenant"],
			setAuthorization: true,
			URL:              "/api/v1/query?query=up{tenant_id=\"forbidden_tenant\"}",
			expectedStatus:   http.StatusForbidden,
			expectedBody:     "error getting label policy",
		},
		{
			name:             "User_belongs_to_multiple_groups_accessing_allowed_tenant",
			authorization:    "Bearer " + tokens["groupTenant"],
			setAuthorization: true,
			URL:              "/api/v1/query?query=up{tenant_id=\"allowed_group1\"}",
			expectedStatus:   http.StatusOK,
			expectedBody:     "Upstream server response\n",
		},
		{
			name:             "User_belongs_to_multiple_groups_accessing_allowed_tenants",
			authorization:    "Bearer " + tokens["groupsTenant"],
			setAuthorization: true,
			URL:              "/api/v1/query?query=up{tenant_id=~\"allowed_group1|also_allowed_group2\"}",
			expectedStatus:   http.StatusOK,
			expectedBody:     "Upstream server response\n",
		},
		{
			name:             "User_belongs_to_multiple_groups_accessing_allowed_tenant",
			authorization:    "Bearer " + tokens["groupsTenant"],
			setAuthorization: true,
			URL:              "/api/v1/query_range?query={tenant_id=\"also_allowed_group1\"} != 1337",
			expectedStatus:   http.StatusOK,
			expectedBody:     "Upstream server response\n",
		},
		{
			name:             "User_belongs_to_multiple_groups_accessing_allowed_tenants",
			authorization:    "Bearer " + tokens["groupsTenant"],
			setAuthorization: true,
			URL:              "/api/v1/query?query={tenant_id=~\"allowed_group1|allowed_group2\"} != 1337",
			expectedStatus:   http.StatusOK,
			expectedBody:     "Upstream server response\n",
		},
		{
			name:             "Loki_query_range_accessing_allowed_tenant",
			authorization:    "Bearer " + tokens["groupsTenant"],
			setAuthorization: true,
			URL:              "/loki/api/v1/query_range?direction=backward&end=1690463973787000000&limit=1000&query=sum by (level) (count_over_time({tenant_id=\"allowed_group1\"} |= `path` |= `label` | json | line_format `{{.message}}` | json | line_format `{{.request}}` | json | line_format `{{.method | printf \"%-4s\"}} {{.path | printf \"%-60s\"}} {{.url | urldecode}}`[1m]))&start=1690377573787000000&step=60000ms",
			expectedStatus:   http.StatusOK,
			expectedBody:     "Upstream server response\n",
		},
		{
			name:             "Loki_index_stats_accessing_allowed_tenant",
			authorization:    "Bearer " + tokens["userTenant"],
			setAuthorization: true,
			URL:              "/loki/api/v1/index/stats?query={tenant_id=\"allowed_user\"}&start=1690377573724000000&end=1690463973724000000",
			expectedStatus:   http.StatusOK,
			expectedBody:     "Upstream server response\n",
		},
		{
			name:             "Loki_query_range_with_forbidden_tenant",
			authorization:    "Bearer " + tokens["userTenant"],
			setAuthorization: true,
			URL:              "/loki/api/v1/query_range?direction=backward&end=1690463973693000000&limit=10&query={tenant_id=\"forbidden_tenant\"} |= `path` |= `label` | json | line_format `{{.message}}` | json | line_format `{{.request}}` | json | line_format `{{.method}} {{.path}} {{.url | urldecode}}`&start=1690377573693000000&step=86400000ms",
			expectedStatus:   http.StatusForbidden,
			expectedBody:     "unauthorized tenant_id",
		},
		//{
		//	name:             "Email_query",
		//	authorization:    "Bearer " + tokens["userWithOutProperEmail"],
		//	setAuthorization: true,
		//	URL:              "/loki/api/v1/query?&query=up",
		//	expectedStatus:   http.StatusOK,
		//	expectedBody:     "Upstream server response\n",
		//},
	}

	app.WithRoutes()

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a request
			req, err := http.NewRequest("GET", tc.URL, nil)
			if err != nil {
				t.Fatal(err)
			}
			// Set headers based on the test case.
			if tc.setAuthorization {
				req.Header.Add("Authorization", tc.authorization)
			}

			// Prepare the response recorder
			rr := httptest.NewRecorder()

			log.Debug().Str("URL", tc.URL).Str("Authorization", tc.authorization).Msg("Request")
			// Call the function
			app.e.ServeHTTP(rr, req)

			// Check the status code
			assert.Equal(t, tc.expectedStatus, rr.Code)

			// Check the response body
			if tc.expectedBody != "" {
				assert.Contains(t, rr.Body.String(), tc.expectedBody)
			}
		})
	}
}

func TestAlertAuth(t *testing.T) {
	app, tokens := setupTestMain()
	app.Cfg().Alert.Enabled = true
	app.Cfg().Alert.TokenHeader = "X-LGTM-Alert-Token"
	app.Cfg().Alert.CertURL = "http://localhost:8080/jwks"

	log.Level(2)

	cases := []struct {
		name             string
		setAuthorization bool
		authorization    string
		expectedStatus   int
		expectedBody     string
		URL              string
	}{
		{
			name:           "Missing_headers",
			URL:            "/api/v1/query_range",
			expectedStatus: http.StatusForbidden,
			expectedBody:   "no Authorization header found\n",
		},
		{
			name:             "Malformed_authorization_header:_B",
			expectedStatus:   http.StatusForbidden,
			setAuthorization: true,
			URL:              "/api/v1/query_range",
			authorization:    "B",
			expectedBody:     "invalid X-LGTM-Alert-Token header\n",
		},
		{
			name:             "Malformed_authorization_header:_Bearer",
			expectedStatus:   http.StatusForbidden,
			setAuthorization: true,
			URL:              "/api/v1/query_range",
			authorization:    "Bearer ",
			expectedBody:     "invalid X-LGTM-Alert-Token header\n",
		},
		{
			name:             "Malformed_authorization_header:_Bearer_skk",
			expectedStatus:   http.StatusForbidden,
			setAuthorization: true,
			URL:              "/api/v1/query_range",
			authorization:    "Bearer skk",
			expectedBody:     "error parsing token\n",
		},
		{
			name:             "Missing_tenant_labels_for_user",
			expectedStatus:   http.StatusForbidden,
			setAuthorization: true,
			URL:              "/api/v1/query_range",
			authorization:    "Bearer " + tokens["noTenant"],
			expectedBody:     "error getting label policy",
		},
		{
			name:             "Valid_token_and_headers,_no_query",
			authorization:    "Bearer " + tokens["userTenant"],
			setAuthorization: true,
			URL:              "/api/v1/query_range",
			expectedStatus:   http.StatusOK,
			expectedBody:     "Upstream server response\n",
		},
		{
			name:             "User_belongs_to_multiple_groups,_accessing_forbidden_tenant",
			authorization:    "Bearer " + tokens["groupTenant"],
			setAuthorization: true,
			URL:              "/api/v1/query_range?query=up{tenant_id=\"forbidden_tenant\"}",
			expectedStatus:   http.StatusForbidden,
			expectedBody:     "unauthorized tenant_id",
		},
		{
			name:             "Not_a_User,_accessing_forbidden_tenant",
			authorization:    "Bearer " + tokens["noTenant"],
			setAuthorization: true,
			URL:              "/api/v1/query_range?query=up{tenant_id=\"forbidden_tenant\"}",
			expectedStatus:   http.StatusForbidden,
			expectedBody:     "error getting label policy",
		},
		{
			name:             "User_belongs_to_no_groups,_accessing_forbidden_tenant",
			authorization:    "Bearer " + tokens["noGroupsTenant"],
			setAuthorization: true,
			URL:              "/api/v1/query?query=up{tenant_id=\"forbidden_tenant\"}",
			expectedStatus:   http.StatusForbidden,
			expectedBody:     "error getting label policy",
		},
		{
			name:             "User_belongs_to_multiple_groups,_accessing_allowed_tenant",
			authorization:    "Bearer " + tokens["groupTenant"],
			setAuthorization: true,
			URL:              "/api/v1/query?query=up{tenant_id=\"allowed_group1\"}",
			expectedStatus:   http.StatusOK,
			expectedBody:     "Upstream server response\n",
		},
		{
			name:             "User_belongs_to_multiple_groups,_accessing_allowed_tenants",
			authorization:    "Bearer " + tokens["groupsTenant"],
			setAuthorization: true,
			URL:              "/api/v1/query?query=up{tenant_id=~\"allowed_group1|also_allowed_group2\"}",
			expectedStatus:   http.StatusOK,
			expectedBody:     "Upstream server response\n",
		},
		{
			name:             "User_belongs_to_multiple_groups,_accessing_allowed_tenant",
			authorization:    "Bearer " + tokens["groupsTenant"],
			setAuthorization: true,
			URL:              "/api/v1/query_range?query={tenant_id=\"also_allowed_group1\"} != 1337",
			expectedStatus:   http.StatusOK,
			expectedBody:     "Upstream server response\n",
		},
		{
			name:             "User_belongs_to_multiple_groups,_accessing_allowed_tenants",
			authorization:    "Bearer " + tokens["groupsTenant"],
			setAuthorization: true,
			URL:              "/api/v1/query?query={tenant_id=~\"allowed_group1|allowed_group2\"} != 1337",
			expectedStatus:   http.StatusOK,
			expectedBody:     "Upstream server response\n",
		},
		{
			name:             "Loki_query_range,_accessing_allowed_tenant",
			authorization:    "Bearer " + tokens["groupsTenant"],
			setAuthorization: true,
			URL:              "/loki/api/v1/query_range?direction=backward&end=1690463973787000000&limit=1000&query=sum by (level) (count_over_time({tenant_id=\"allowed_group1\"} |= `path` |= `label` | json | line_format `{{.message}}` | json | line_format `{{.request}}` | json | line_format `{{.method | printf \"%-4s\"}} {{.path | printf \"%-60s\"}} {{.url | urldecode}}`[1m]))&start=1690377573787000000&step=60000ms",
			expectedStatus:   http.StatusOK,
			expectedBody:     "Upstream server response\n",
		},
		{
			name:             "Loki_index_stats,_accessing_allowed_tenant",
			authorization:    "Bearer " + tokens["userTenant"],
			setAuthorization: true,
			URL:              "/loki/api/v1/index/stats?query={tenant_id=\"allowed_user\"}&start=1690377573724000000&end=1690463973724000000",
			expectedStatus:   http.StatusOK,
			expectedBody:     "Upstream server response\n",
		},
		{
			name:             "Loki_query_range_with_forbidden_tenant",
			authorization:    "Bearer " + tokens["userTenant"],
			setAuthorization: true,
			URL:              "/loki/api/v1/query_range?direction=backward&end=1690463973693000000&limit=10&query={tenant_id=\"forbidden_tenant\"} |= `path` |= `label` | json | line_format `{{.message}}` | json | line_format `{{.request}}` | json | line_format `{{.method}} {{.path}} {{.url | urldecode}}`&start=1690377573693000000&step=86400000ms",
			expectedStatus:   http.StatusForbidden,
			expectedBody:     "unauthorized tenant_id",
		},
	}

	app.WithRoutes()

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a request
			req, err := http.NewRequest("GET", tc.URL, nil)
			if err != nil {
				t.Fatal(err)
			}
			// IMPORTANT: We set the alert token header instead of “Authorization”
			if tc.setAuthorization {
				req.Header.Add(app.Cfg().Alert.TokenHeader, tc.authorization)
			}

			// Prepare the response recorder
			rr := httptest.NewRecorder()

			log.Debug().Str("URL", tc.URL).Str("Authorization", tc.authorization).Msg("Alert-Request")
			// Call the function
			app.e.ServeHTTP(rr, req)

			// Check the status code
			assert.Equal(t, tc.expectedStatus, rr.Code)

			// Check the response body
			if tc.expectedBody != "" {
				assert.Contains(t, rr.Body.String(), tc.expectedBody)
			}
		})
	}
}

func TestIsAdminSkip(t *testing.T) {
	a := assert.New(t)

	app := &App{}
	app.WithConfig()
	app.Cfg().Admin.Bypass = true
	app.Cfg().Admin.Group = "gepardec-run-admins"
	token := &OAuthToken{Groups: []string{"gepardec-run-admins"}}
	a.True(isAdmin(*token, app))

	token.Groups = []string{"user"}
	a.False(isAdmin(*token, app))
}

func TestLogAndWriteError(t *testing.T) {
	a := assert.New(t)

	rw := httptest.NewRecorder()
	logAndWriteError(rw, http.StatusInternalServerError, nil, "test error")
	a.Equal(http.StatusInternalServerError, rw.Code)
	a.Equal("test error\n", rw.Body.String())
}

func TestGetLabelPolicyMerge(t *testing.T) {
	parser := NewPolicyParser()
	policyCache := make(map[string]*LabelPolicy)

	// Pre-parse policies as they would be during loadLabels()
	rawData := map[string]RawLabelData{
		"group1": {
			"_rules": []interface{}{
				map[string]interface{}{
					"name":     "tenant_id",
					"operator": "=",
					"values":   []interface{}{"allowed_group1", "also_allowed_group1"},
				},
			},
		},
		"group2": {
			"_rules": []interface{}{
				map[string]interface{}{
					"name":     "tenant_id",
					"operator": "=",
					"values":   []interface{}{"allowed_group2", "also_allowed_group2"},
				},
			},
		},
	}

	// Parse all policies eagerly
	for key, data := range rawData {
		policy, err := parser.ParseUserPolicy(data, "")
		if err != nil {
			log.Fatal().Err(err).Str("key", key).Msg("Failed to parse policy in test setup")
		}
		cacheKey := "entry:" + key
		policyCache[cacheKey] = policy
	}

	store := newTestLabelStore(parser, policyCache)

	// Simulate user with multiple groups
	identity := UserIdentity{
		Username: "not-a-user",
		Groups:   []string{"group1", "group2"},
	}

	policy, err := store.GetLabelPolicy(identity, "tenant_id")
	if err != nil {
		t.Fatalf("Error getting policy: %v", err)
	}

	t.Logf("Merged Policy: Logic=%s", policy.Logic)
	t.Logf("Rules count: %d", len(policy.Rules))
	for i, rule := range policy.Rules {
		t.Logf("Rule %d: Name=%s, Operator=%s, Values=%v", i, rule.Name, rule.Operator, rule.Values)
	}

	// Verify logic is OR
	if policy.Logic != LogicOR {
		t.Errorf("Expected Logic=OR, got %s", policy.Logic)
	}

	// Verify we have 1 consolidated rule (duplicate label names are merged)
	if len(policy.Rules) != 1 {
		t.Errorf("Expected 1 consolidated rule, got %d", len(policy.Rules))
	}

	// Verify the consolidated rule has correct properties
	if policy.Rules[0].Name != "tenant_id" {
		t.Errorf("Expected rule name 'tenant_id', got '%s'", policy.Rules[0].Name)
	}

	// Operator should be upgraded to regex match for multiple values
	if policy.Rules[0].Operator != OperatorRegexMatch {
		t.Errorf("Expected operator '=~' (consolidated regex), got '%s'", policy.Rules[0].Operator)
	}

	// Build allowed values map
	allowedValues := make(map[string]bool)
	for _, v := range policy.Rules[0].Values {
		allowedValues[v] = true
	}

	t.Logf("Allowed values: %v", allowedValues)

	// Verify all 4 values are allowed in the consolidated rule
	expectedValues := []string{"allowed_group1", "also_allowed_group1", "allowed_group2", "also_allowed_group2"}
	for _, v := range expectedValues {
		if !allowedValues[v] {
			t.Errorf("Expected %s to be allowed", v)
		}
	}

	// Verify values are sorted (deterministic output)
	sortedExpected := []string{"allowed_group1", "allowed_group2", "also_allowed_group1", "also_allowed_group2"}
	for i, expected := range sortedExpected {
		if policy.Rules[0].Values[i] != expected {
			t.Errorf("Expected value[%d]='%s', got '%s'", i, expected, policy.Rules[0].Values[i])
		}
	}
}

// TestProxyInitialization tests that proxies are correctly initialized for configured upstreams
func TestProxyInitialization(t *testing.T) {
	tests := []struct {
		name         string
		lokiURL      string
		thanosURL    string
		tempoURL     string
		expectLoki   bool
		expectThanos bool
		expectTempo  bool
	}{
		{
			name:         "All upstreams configured",
			lokiURL:      "http://loki:3100",
			thanosURL:    "http://thanos:9090",
			tempoURL:     "http://tempo:3200",
			expectLoki:   true,
			expectThanos: true,
			expectTempo:  true,
		},
		{
			name:         "Only Loki configured",
			lokiURL:      "http://loki:3100",
			thanosURL:    "",
			tempoURL:     "",
			expectLoki:   true,
			expectThanos: false,
			expectTempo:  false,
		},
		{
			name:         "Only Thanos configured",
			lokiURL:      "",
			thanosURL:    "http://thanos:9090",
			tempoURL:     "",
			expectLoki:   false,
			expectThanos: true,
			expectTempo:  false,
		},
		{
			name:         "Only Tempo configured",
			lokiURL:      "",
			thanosURL:    "",
			tempoURL:     "http://tempo:3200",
			expectLoki:   false,
			expectThanos: false,
			expectTempo:  true,
		},
		{
			name:         "No upstreams configured",
			lokiURL:      "",
			thanosURL:    "",
			tempoURL:     "",
			expectLoki:   false,
			expectThanos: false,
			expectTempo:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := &App{}
			app.WithConfig()

			// Set URLs
			app.Cfg().Loki.URL = tt.lokiURL
			app.Cfg().Thanos.URL = tt.thanosURL
			app.Cfg().Tempo.URL = tt.tempoURL

			// Mock TLS config
			app.TlS = &tls.Config{InsecureSkipVerify: true}

			// Initialize proxies
			app.WithProxies()

			// Verify proxy initialization
			if tt.expectLoki && app.lokiProxy == nil {
				t.Errorf("Expected Loki proxy to be initialized, got nil")
			}
			if !tt.expectLoki && app.lokiProxy != nil {
				t.Errorf("Expected Loki proxy to be nil, got %v", app.lokiProxy)
			}

			if tt.expectThanos && app.thanosProxy == nil {
				t.Errorf("Expected Thanos proxy to be initialized, got nil")
			}
			if !tt.expectThanos && app.thanosProxy != nil {
				t.Errorf("Expected Thanos proxy to be nil, got %v", app.thanosProxy)
			}

			if tt.expectTempo && app.tempoProxy == nil {
				t.Errorf("Expected Tempo proxy to be initialized, got nil")
			}
			if !tt.expectTempo && app.tempoProxy != nil {
				t.Errorf("Expected Tempo proxy to be nil, got %v", app.tempoProxy)
			}
		})
	}
}

// TestProxyUsesDirectReverseProxy verifies that proxies use direct ReverseProxy instantiation
func TestProxyUsesDirectReverseProxy(t *testing.T) {
	app := &App{}
	app.WithConfig()
	app.Cfg().Loki.URL = "http://loki:3100"
	app.TlS = &tls.Config{InsecureSkipVerify: true}

	app.WithProxies()

	if app.lokiProxy == nil {
		t.Fatal("Loki proxy should be initialized")
	}

	// Verify that proxy has custom Rewrite, ErrorHandler, and Transport
	if app.lokiProxy.Rewrite == nil {
		t.Error("Expected custom Rewrite function, got nil")
	}
	if app.lokiProxy.ErrorHandler == nil {
		t.Error("Expected custom ErrorHandler function, got nil")
	}
	if app.lokiProxy.ModifyResponse == nil {
		t.Error("Expected custom ModifyResponse function, got nil")
	}
	if app.lokiProxy.Transport == nil {
		t.Error("Expected custom Transport, got nil")
	}
}

// TestGetProxyConfigDefaults tests default proxy configuration values
func TestGetProxyConfigDefaults(t *testing.T) {
	cfg := &Config{}

	// Get config with no overrides (should use built-in defaults)
	proxyCfg := cfg.GetProxyConfig(nil)

	assert.Equal(t, 60*time.Second, proxyCfg.RequestTimeout, "RequestTimeout should be 60s")
	assert.Equal(t, 90*time.Second, proxyCfg.IdleConnTimeout, "IdleConnTimeout should be 90s")
	assert.Equal(t, 10*time.Second, proxyCfg.TLSHandshakeTimeout, "TLSHandshakeTimeout should be 10s")
	assert.Equal(t, 500, proxyCfg.MaxIdleConns, "MaxIdleConns should be 500")
	assert.Equal(t, 100, proxyCfg.MaxIdleConnsPerHost, "MaxIdleConnsPerHost should be 100")
	assert.True(t, proxyCfg.ForceHTTP2, "ForceHTTP2 should be true")
}

// TestGetProxyConfigGlobalOverrides tests global proxy configuration overrides
func TestGetProxyConfigGlobalOverrides(t *testing.T) {
	cfg := &Config{
		Proxy: ProxyConfig{
			RequestTimeout:      120 * time.Second,
			IdleConnTimeout:     180 * time.Second,
			TLSHandshakeTimeout: 20 * time.Second,
			MaxIdleConns:        1000,
			MaxIdleConnsPerHost: 200,
			ForceHTTP2:          true, // Set to true to test global override
		},
	}

	// Get config with global overrides
	proxyCfg := cfg.GetProxyConfig(nil)

	assert.Equal(t, 120*time.Second, proxyCfg.RequestTimeout, "RequestTimeout should use global override")
	assert.Equal(t, 180*time.Second, proxyCfg.IdleConnTimeout, "IdleConnTimeout should use global override")
	assert.Equal(t, 20*time.Second, proxyCfg.TLSHandshakeTimeout, "TLSHandshakeTimeout should use global override")
	assert.Equal(t, 1000, proxyCfg.MaxIdleConns, "MaxIdleConns should use global override")
	assert.Equal(t, 200, proxyCfg.MaxIdleConnsPerHost, "MaxIdleConnsPerHost should use global override")
	assert.True(t, proxyCfg.ForceHTTP2, "ForceHTTP2 should use global override")
}

// TestGetProxyConfigUpstreamOverrides tests upstream-specific configuration overrides
func TestGetProxyConfigUpstreamOverrides(t *testing.T) {
	cfg := &Config{
		Proxy: ProxyConfig{
			RequestTimeout:      60 * time.Second,
			MaxIdleConnsPerHost: 100,
		},
	}

	upstreamCfg := &ProxyConfig{
		RequestTimeout:      300 * time.Second, // Override for slow queries
		MaxIdleConnsPerHost: 50,                // Override for lower volume
	}

	// Get config with upstream-specific overrides
	proxyCfg := cfg.GetProxyConfig(upstreamCfg)

	assert.Equal(t, 300*time.Second, proxyCfg.RequestTimeout, "RequestTimeout should use upstream override")
	assert.Equal(t, 50, proxyCfg.MaxIdleConnsPerHost, "MaxIdleConnsPerHost should use upstream override")
	// Other values should still use built-in or global defaults
	assert.Equal(t, 90*time.Second, proxyCfg.IdleConnTimeout, "IdleConnTimeout should use built-in default")
}

// TestGetProxyConfigPrecedence tests configuration precedence: upstream > global > built-in
func TestGetProxyConfigPrecedence(t *testing.T) {
	cfg := &Config{
		Proxy: ProxyConfig{
			RequestTimeout:      120 * time.Second, // Global override
			MaxIdleConnsPerHost: 200,               // Global override
		},
	}

	upstreamCfg := &ProxyConfig{
		RequestTimeout: 300 * time.Second, // Upstream override (highest priority)
		// MaxIdleConnsPerHost not set - should use global
	}

	proxyCfg := cfg.GetProxyConfig(upstreamCfg)

	// Upstream override wins
	assert.Equal(t, 300*time.Second, proxyCfg.RequestTimeout, "Upstream override should win")
	// Global override wins over built-in
	assert.Equal(t, 200, proxyCfg.MaxIdleConnsPerHost, "Global override should win over built-in")
	// Built-in default when no overrides
	assert.Equal(t, 90*time.Second, proxyCfg.IdleConnTimeout, "Built-in default should be used")
}

// TestCreateTransport tests HTTP transport creation with proxy configuration
func TestCreateTransport(t *testing.T) {
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

	transport := app.createTransport(proxyCfg, tlsConfig)

	assert.NotNil(t, transport, "Transport should not be nil")
	assert.Equal(t, tlsConfig, transport.TLSClientConfig, "TLS config should match")
	assert.Equal(t, 500, transport.MaxIdleConns, "MaxIdleConns should match")
	assert.Equal(t, 100, transport.MaxIdleConnsPerHost, "MaxIdleConnsPerHost should match")
	assert.Equal(t, 0, transport.MaxConnsPerHost, "MaxConnsPerHost should be 0 (unlimited)")
	assert.Equal(t, 90*time.Second, transport.IdleConnTimeout, "IdleConnTimeout should match")
	assert.Equal(t, 10*time.Second, transport.TLSHandshakeTimeout, "TLSHandshakeTimeout should match")
	assert.False(t, transport.DisableCompression, "DisableCompression should be false")
	assert.True(t, transport.ForceAttemptHTTP2, "ForceAttemptHTTP2 should match")
}

// TestEachUpstreamGetsOwnTransport verifies that each upstream has its own transport instance
func TestEachUpstreamGetsOwnTransport(t *testing.T) {
	app := &App{}
	app.WithConfig()
	app.Cfg().Loki.URL = "http://loki:3100"
	app.Cfg().Thanos.URL = "http://thanos:9090"
	app.Cfg().Tempo.URL = "http://tempo:3200"
	app.TlS = &tls.Config{InsecureSkipVerify: true}

	app.WithProxies()

	if app.lokiProxy == nil || app.thanosProxy == nil || app.tempoProxy == nil {
		t.Fatal("All proxies should be initialized")
	}

	// Get transport instances from each proxy
	lokiTransport := app.lokiProxy.Transport
	thanosTransport := app.thanosProxy.Transport
	tempoTransport := app.tempoProxy.Transport

	// Verify each proxy has its own transport instance (different memory addresses)
	if lokiTransport == thanosTransport {
		t.Error("Loki and Thanos should have separate transport instances")
	}
	if lokiTransport == tempoTransport {
		t.Error("Loki and Tempo should have separate transport instances")
	}
	if thanosTransport == tempoTransport {
		t.Error("Thanos and Tempo should have separate transport instances")
	}
}

// TestBackwardCompatibilityMissingProxyConfig tests that missing proxy config sections work
func TestBackwardCompatibilityMissingProxyConfig(t *testing.T) {
	cfg := &Config{
		// No Proxy section defined
		Loki: LokiConfig{
			URL: "http://loki:3100",
			// No Proxy override defined
		},
	}

	// Should use built-in defaults without errors
	proxyCfg := cfg.GetProxyConfig(cfg.Loki.Proxy)

	assert.Equal(t, 60*time.Second, proxyCfg.RequestTimeout, "Should use built-in defaults")
	assert.Equal(t, 100, proxyCfg.MaxIdleConnsPerHost, "Should use built-in defaults")
}
