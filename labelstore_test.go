package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
)

// TestFileLabelStoreLoadLabelsPreserveCase tests that case sensitivity is preserved
// when loading labels from YAML files
func TestFileLabelStoreLoadLabelsPreserveCase(t *testing.T) {
	tests := []struct {
		name           string
		yamlContent    string
		expectedKeys   []string
		unexpectedKeys []string
		description    string
	}{
		{
			name: "mixed case username",
			yamlContent: `
GrafanaAdmin:
  _logic: AND
  _rules:
    - name: '#cluster-wide'
      operator: =
      values: ["true"]
`,
			expectedKeys:   []string{"GrafanaAdmin"},
			unexpectedKeys: []string{"grafanaadmin", "GRAFANAADMIN"},
			description:    "GrafanaAdmin should preserve exact case, not be lowercased to grafanaadmin",
		},
		{
			name: "email-style username with mixed case",
			yamlContent: `
BiNh.NgUyEn@EnCapital.io:
  _logic: AND
  _rules:
    - name: cluster
      operator: =
      values: ["prod"]
`,
			expectedKeys:   []string{"BiNh.NgUyEn@EnCapital.io"},
			unexpectedKeys: []string{"binh.nguyen@encapital.io"},
			description:    "Email-style usernames should preserve original case",
		},
		{
			name: "multiple mixed case groups",
			yamlContent: `
BackendTeam:
  _logic: AND
  _rules:
    - name: namespace
      operator: =
      values: ["prod"]

FrontendTeam:
  _logic: OR
  _rules:
    - name: namespace
      operator: =
      values: ["staging"]

admin-group:
  _logic: AND
  _rules:
    - name: '#cluster-wide'
      operator: =
      values: ["true"]
`,
			expectedKeys:   []string{"BackendTeam", "FrontendTeam", "admin-group"},
			unexpectedKeys: []string{"backendteam", "frontendteam", "ADMIN-GROUP"},
			description:    "All group names should preserve their exact case",
		},
		{
			name: "uppercase and lowercase variations",
			yamlContent: `
ALLCAPS:
  _logic: AND
  _rules:
    - name: env
      operator: =
      values: ["prod"]

lowercase:
  _logic: AND
  _rules:
    - name: env
      operator: =
      values: ["dev"]

MixedCase:
  _logic: AND
  _rules:
    - name: env
      operator: =
      values: ["staging"]
`,
			expectedKeys:   []string{"ALLCAPS", "lowercase", "MixedCase"},
			unexpectedKeys: []string{"allcaps", "LOWERCASE", "mixedcase"},
			description:    "All case variations should be preserved exactly",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary directory and file
			tmpDir := t.TempDir()
			yamlFile := filepath.Join(tmpDir, "labels.yaml")
			err := os.WriteFile(yamlFile, []byte(tt.yamlContent), 0644)
			if err != nil {
				t.Fatalf("Failed to write test YAML file: %v", err)
			}

			// Create FileLabelStore and load labels
			store := &FileLabelStore{}
			v := viper.NewWithOptions(viper.KeyDelimiter("::"))
			err = store.loadLabels(v, []string{tmpDir})
			if err != nil {
				t.Fatalf("Failed to load labels: %v", err)
			}

			// Verify expected keys are present in parsed policy cache
			for _, expectedKey := range tt.expectedKeys {
				cacheKey := "entry:" + expectedKey
				if _, ok := store.policyCache[cacheKey]; !ok {
					t.Errorf("Expected key %q not found in policyCache. Available keys: %v", expectedKey, mapPolicyCacheKeys(store.policyCache))
				}
			}

			// Verify unexpected keys are not present (i.e., case was lowercased)
			for _, unexpectedKey := range tt.unexpectedKeys {
				cacheKey := "entry:" + unexpectedKey
				if _, ok := store.policyCache[cacheKey]; ok {
					t.Errorf("Unexpected key %q found in policyCache (case was incorrectly modified). %s", unexpectedKey, tt.description)
				}
			}
		})
	}
}

// TestFileLabelStoreMultipleUsersAndGroupsPreserveCase tests that case sensitivity
// is preserved when loading YAML with multiple users and groups of varying case
func TestFileLabelStoreMultipleUsersAndGroupsPreserveCase(t *testing.T) {
	yamlContent := `
GrafanaAdmin:
  _logic: AND
  _rules:
    - name: '#cluster-wide'
      operator: =
      values: ["true"]

BackendTeam:
  _logic: AND
  _rules:
    - name: namespace
      operator: =
      values: ["prod"]

FrontendTeam:
  _logic: OR
  _rules:
    - name: namespace
      operator: =
      values: ["staging", "dev"]

john.doe@example.com:
  _logic: AND
  _rules:
    - name: env
      operator: =
      values: ["sandbox"]
`

	tmpDir := t.TempDir()
	yamlFile := filepath.Join(tmpDir, "labels.yaml")
	err := os.WriteFile(yamlFile, []byte(yamlContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write test YAML file: %v", err)
	}

	store := &FileLabelStore{}
	v := viper.NewWithOptions(viper.KeyDelimiter("::"))
	err = store.loadLabels(v, []string{tmpDir})
	if err != nil {
		t.Fatalf("Failed to load labels: %v", err)
	}

	// Verify all keys are present with correct case (main goal of the fix)
	expectedKeys := map[string]bool{
		"GrafanaAdmin":         true,
		"BackendTeam":          true,
		"FrontendTeam":         true,
		"john.doe@example.com": true,
	}

	for key := range expectedKeys {
		cacheKey := "entry:" + key
		if _, ok := store.policyCache[cacheKey]; !ok {
			t.Errorf("Expected key %q not found with correct case. Available keys: %v. "+
				"This indicates case sensitivity was not preserved from YAML file.", key, mapPolicyCacheKeys(store.policyCache))
		}
	}

	// Verify lowercased variations are NOT present (would happen with old Viper behavior)
	unexpectedLowercaseKeys := []string{
		"grafanaadmin",
		"backendteam",
		"frontendteam",
		"john.doe@EXAMPLE.COM", // Different case
	}

	for _, key := range unexpectedLowercaseKeys {
		cacheKey := "entry:" + key
		if _, ok := store.policyCache[cacheKey]; ok {
			t.Errorf("Unexpected key %q found in policyCache. Case was incorrectly modified "+
				"(old Viper behavior that we fixed).", key)
		}
	}
}

// TestFileLabelStoreDirectYAMLParsing tests that direct YAML parsing preserves case
// correctly. This tests the new implementation that reads YAML files directly instead
// of using Viper, which normalizes all keys to lowercase.
func TestFileLabelStoreDirectYAMLParsing(t *testing.T) {
	yamlContent := `
testUser123:
  _logic: AND
  _rules:
    - name: namespace
      operator: =
      values: ["test"]

TestUser456:
  _logic: AND
  _rules:
    - name: namespace
      operator: =
      values: ["test"]

TESTUSER789:
  _logic: AND
  _rules:
    - name: namespace
      operator: =
      values: ["test"]
`

	tmpDir := t.TempDir()
	yamlFile := filepath.Join(tmpDir, "labels.yaml")
	err := os.WriteFile(yamlFile, []byte(yamlContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write test YAML file: %v", err)
	}

	// Test with direct YAML parsing (current implementation)
	store := &FileLabelStore{}
	v := viper.NewWithOptions(viper.KeyDelimiter("::"))
	err = store.loadLabels(v, []string{tmpDir})
	if err != nil {
		t.Fatalf("Failed to load labels: %v", err)
	}

	// Verify all variations are present with correct case in parsed policy cache
	if _, ok := store.policyCache["entry:testUser123"]; !ok {
		t.Error("Expected key 'testUser123' not found in direct YAML parsing result")
	}
	if _, ok := store.policyCache["entry:TestUser456"]; !ok {
		t.Error("Expected key 'TestUser456' not found in direct YAML parsing result")
	}
	if _, ok := store.policyCache["entry:TESTUSER789"]; !ok {
		t.Error("Expected key 'TESTUSER789' not found in direct YAML parsing result")
	}

	// Verify that lowercased versions are NOT present (which would happen with Viper)
	if _, ok := store.policyCache["entry:testuser456"]; ok {
		t.Error("Unexpected lowercased key 'testuser456' found (indicates case was modified by Viper)")
	}
	if _, ok := store.policyCache["entry:testuser789"]; ok {
		t.Error("Unexpected lowercased key 'testuser789' found (indicates case was modified by Viper)")
	}
}

// Helper function to get policy cache keys for debugging
func mapPolicyCacheKeys(m map[string]*LabelPolicy) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// TestConsolidateDuplicateLabels_SingleLabel tests consolidation with single duplicate label
func TestConsolidateDuplicateLabels_SingleLabel(t *testing.T) {
	store := &FileLabelStore{}

	// Input: Two rules with same label "environment" but different values
	rules := []LabelRule{
		{Name: "environment", Operator: OperatorEquals, Values: []string{"production"}},
		{Name: "environment", Operator: OperatorEquals, Values: []string{"uat"}},
	}

	result := store.consolidateDuplicateLabels(rules)

	// Should consolidate to single rule with both values
	if len(result) != 1 {
		t.Errorf("Expected 1 consolidated rule, got %d", len(result))
	}

	if result[0].Name != "environment" {
		t.Errorf("Expected label name 'environment', got '%s'", result[0].Name)
	}

	if result[0].Operator != OperatorRegexMatch {
		t.Errorf("Expected operator '=~', got '%s'", result[0].Operator)
	}

	expectedValues := []string{"production", "uat"}
	if len(result[0].Values) != len(expectedValues) {
		t.Errorf("Expected %d values, got %d", len(expectedValues), len(result[0].Values))
	}

	for i, expected := range expectedValues {
		if result[0].Values[i] != expected {
			t.Errorf("Expected value[%d] = '%s', got '%s'", i, expected, result[0].Values[i])
		}
	}
}

// TestConsolidateDuplicateLabels_MultipleLabels tests consolidation with multiple duplicate labels
func TestConsolidateDuplicateLabels_MultipleLabels(t *testing.T) {
	store := &FileLabelStore{}

	// Input: Multiple rules with duplicate "environment" and "cluster" labels
	rules := []LabelRule{
		{Name: "environment", Operator: OperatorEquals, Values: []string{"production"}},
		{Name: "cluster", Operator: OperatorEquals, Values: []string{"prod-argocd", "prod-backoffice"}},
		{Name: "environment", Operator: OperatorEquals, Values: []string{"uat"}},
		{Name: "cluster", Operator: OperatorEquals, Values: []string{"uat-allinone", "uat-l1-k8s"}},
	}

	result := store.consolidateDuplicateLabels(rules)

	// Should consolidate to 2 rules (not 4)
	if len(result) != 2 {
		t.Errorf("Expected 2 consolidated rules, got %d", len(result))
	}

	// Find environment and cluster rules
	var envRule, clusterRule *LabelRule
	for i := range result {
		switch result[i].Name {
		case "cluster":
			clusterRule = &result[i]
		case "environment":
			envRule = &result[i]
		}
	}

	// Verify environment rule
	if envRule == nil {
		t.Fatal("Environment rule not found")
	}
	if envRule.Operator != OperatorRegexMatch {
		t.Errorf("Expected environment operator '=~', got '%s'", envRule.Operator)
	}
	expectedEnvValues := []string{"production", "uat"}
	if len(envRule.Values) != len(expectedEnvValues) {
		t.Errorf("Expected %d environment values, got %d", len(expectedEnvValues), len(envRule.Values))
	}

	// Verify cluster rule
	if clusterRule == nil {
		t.Fatal("Cluster rule not found")
	}
	if clusterRule.Operator != OperatorRegexMatch {
		t.Errorf("Expected cluster operator '=~', got '%s'", clusterRule.Operator)
	}
	expectedClusterValues := []string{"prod-argocd", "prod-backoffice", "uat-allinone", "uat-l1-k8s"}
	if len(clusterRule.Values) != len(expectedClusterValues) {
		t.Errorf("Expected %d cluster values, got %d", len(expectedClusterValues), len(clusterRule.Values))
	}

	// Verify values are sorted
	for i, expected := range expectedClusterValues {
		if clusterRule.Values[i] != expected {
			t.Errorf("Expected cluster value[%d] = '%s', got '%s'", i, expected, clusterRule.Values[i])
		}
	}
}

// TestConsolidateDuplicateLabels_OperatorConflict tests operator conflict resolution
func TestConsolidateDuplicateLabels_OperatorConflict(t *testing.T) {
	store := &FileLabelStore{}

	// Input: Rules with positive (=) and negative (!=) operators
	rules := []LabelRule{
		{Name: "environment", Operator: OperatorEquals, Values: []string{"production"}},
		{Name: "environment", Operator: OperatorNotEquals, Values: []string{"test"}},
	}

	result := store.consolidateDuplicateLabels(rules)

	// Should prioritize positive match operator
	if len(result) != 1 {
		t.Errorf("Expected 1 consolidated rule, got %d", len(result))
	}

	// Positive match should win in OR logic
	if result[0].Operator != OperatorRegexMatch {
		t.Errorf("Expected operator '=~' (positive match wins), got '%s'", result[0].Operator)
	}

	// Should include both values
	expectedValues := []string{"production", "test"}
	if len(result[0].Values) != len(expectedValues) {
		t.Errorf("Expected %d values, got %d", len(expectedValues), len(result[0].Values))
	}
}

// TestConsolidateDuplicateLabels_NoDuplication tests that rules without duplication are unchanged
func TestConsolidateDuplicateLabels_NoDuplication(t *testing.T) {
	store := &FileLabelStore{}

	// Input: Rules with distinct labels (no duplication)
	rules := []LabelRule{
		{Name: "environment", Operator: OperatorEquals, Values: []string{"prod"}},
		{Name: "cluster", Operator: OperatorEquals, Values: []string{"prod-k8s"}},
		{Name: "team", Operator: OperatorEquals, Values: []string{"backend"}},
	}

	result := store.consolidateDuplicateLabels(rules)

	// Should return all rules unchanged
	if len(result) != 3 {
		t.Errorf("Expected 3 rules (no consolidation), got %d", len(result))
	}

	// Verify all original rules are present (order may change due to sorting)
	labelMap := make(map[string]LabelRule)
	for _, rule := range result {
		labelMap[rule.Name] = rule
	}

	if rule, ok := labelMap["environment"]; !ok {
		t.Error("Environment rule missing")
	} else if rule.Operator != OperatorEquals {
		t.Errorf("Environment operator changed from '=' to '%s'", rule.Operator)
	}

	if rule, ok := labelMap["cluster"]; !ok {
		t.Error("Cluster rule missing")
	} else if rule.Operator != OperatorEquals {
		t.Errorf("Cluster operator changed from '=' to '%s'", rule.Operator)
	}

	if rule, ok := labelMap["team"]; !ok {
		t.Error("Team rule missing")
	} else if rule.Operator != OperatorEquals {
		t.Errorf("Team operator changed from '=' to '%s'", rule.Operator)
	}
}

// TestConsolidateDuplicateLabels_RegexAndExactMatch tests mixing regex and exact match operators
func TestConsolidateDuplicateLabels_RegexAndExactMatch(t *testing.T) {
	store := &FileLabelStore{}

	// Input: Rules with regex (=~) and exact (=) operators for same label
	rules := []LabelRule{
		{Name: "namespace", Operator: OperatorRegexMatch, Values: []string{"prod-.*"}},
		{Name: "namespace", Operator: OperatorEquals, Values: []string{"uat-app"}},
	}

	result := store.consolidateDuplicateLabels(rules)

	// Should use regex match operator
	if len(result) != 1 {
		t.Errorf("Expected 1 consolidated rule, got %d", len(result))
	}

	if result[0].Operator != OperatorRegexMatch {
		t.Errorf("Expected operator '=~' (regex wins), got '%s'", result[0].Operator)
	}

	// Should include both values
	expectedValues := []string{"prod-.*", "uat-app"}
	if len(result[0].Values) != len(expectedValues) {
		t.Errorf("Expected %d values, got %d", len(expectedValues), len(result[0].Values))
	}
}

// TestConsolidateDuplicateLabels_ThreeGroups tests consolidation across three groups
func TestConsolidateDuplicateLabels_ThreeGroups(t *testing.T) {
	store := &FileLabelStore{}

	// Input: Three rules with same label from different groups
	rules := []LabelRule{
		{Name: "environment", Operator: OperatorEquals, Values: []string{"production"}},
		{Name: "environment", Operator: OperatorEquals, Values: []string{"uat"}},
		{Name: "environment", Operator: OperatorEquals, Values: []string{"dev"}},
	}

	result := store.consolidateDuplicateLabels(rules)

	// Should consolidate to single rule with all three values
	if len(result) != 1 {
		t.Errorf("Expected 1 consolidated rule, got %d", len(result))
	}

	// Values should be sorted alphabetically
	expectedValues := []string{"dev", "production", "uat"}
	if len(result[0].Values) != len(expectedValues) {
		t.Errorf("Expected %d values, got %d", len(expectedValues), len(result[0].Values))
	}

	for i, expected := range expectedValues {
		if result[0].Values[i] != expected {
			t.Errorf("Expected value[%d] = '%s', got '%s'", i, expected, result[0].Values[i])
		}
	}
}

// TestConsolidateDuplicateLabels_DuplicateValues tests deduplication of overlapping values
func TestConsolidateDuplicateLabels_DuplicateValues(t *testing.T) {
	store := &FileLabelStore{}

	// Input: Rules with overlapping values
	rules := []LabelRule{
		{Name: "cluster", Operator: OperatorEquals, Values: []string{"cluster1", "cluster2"}},
		{Name: "cluster", Operator: OperatorEquals, Values: []string{"cluster2", "cluster3"}},
	}

	result := store.consolidateDuplicateLabels(rules)

	// Should deduplicate cluster2
	if len(result) != 1 {
		t.Errorf("Expected 1 consolidated rule, got %d", len(result))
	}

	expectedValues := []string{"cluster1", "cluster2", "cluster3"}
	if len(result[0].Values) != len(expectedValues) {
		t.Errorf("Expected %d values (deduplicated), got %d", len(expectedValues), len(result[0].Values))
	}

	for i, expected := range expectedValues {
		if result[0].Values[i] != expected {
			t.Errorf("Expected value[%d] = '%s', got '%s'", i, expected, result[0].Values[i])
		}
	}
}

// TestFileLabelStore_MultiGroup_ValueConsolidation tests end-to-end multi-group scenario
func TestFileLabelStore_MultiGroup_ValueConsolidation(t *testing.T) {
	yamlContent := `
GrafanaPROD:
  _logic: AND
  _rules:
    - name: environment
      operator: =
      values: ["production"]
    - name: cluster
      operator: =
      values: ["prod-argocd", "prod-backoffice"]

GrafanaUAT:
  _logic: AND
  _rules:
    - name: environment
      operator: =
      values: ["uat"]
    - name: cluster
      operator: =
      values: ["uat-allinone", "uat-l1-k8s"]
`

	tmpDir := t.TempDir()
	yamlFile := filepath.Join(tmpDir, "labels.yaml")
	err := os.WriteFile(yamlFile, []byte(yamlContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write test YAML file: %v", err)
	}

	store := &FileLabelStore{}
	v := viper.NewWithOptions(viper.KeyDelimiter("::"))
	err = store.loadLabels(v, []string{tmpDir})
	if err != nil {
		t.Fatalf("Failed to load labels: %v", err)
	}

	// Simulate user belonging to both groups
	identity := UserIdentity{
		Username: "testuser",
		Groups:   []string{"GrafanaPROD", "GrafanaUAT"},
	}

	policy, err := store.GetLabelPolicy(identity, "namespace")
	if err != nil {
		t.Fatalf("Failed to get label policy: %v", err)
	}

	// Should have exactly 2 rules (environment and cluster), not 4
	if len(policy.Rules) != 2 {
		t.Errorf("Expected 2 consolidated rules, got %d", len(policy.Rules))
	}

	// Find rules by name
	var envRule, clusterRule *LabelRule
	for i := range policy.Rules {
		switch policy.Rules[i].Name {
		case "environment":
			envRule = &policy.Rules[i]
		case "cluster":
			clusterRule = &policy.Rules[i]
		}
	}

	// Verify environment rule
	if envRule == nil {
		t.Fatal("Environment rule not found after consolidation")
	}
	if envRule.Operator != OperatorRegexMatch {
		t.Errorf("Expected environment operator '=~', got '%s'", envRule.Operator)
	}
	expectedEnv := []string{"production", "uat"}
	if len(envRule.Values) != 2 {
		t.Errorf("Expected 2 environment values, got %d", len(envRule.Values))
	}
	for i, expected := range expectedEnv {
		if envRule.Values[i] != expected {
			t.Errorf("Expected environment value[%d] = '%s', got '%s'", i, expected, envRule.Values[i])
		}
	}

	// Verify cluster rule
	if clusterRule == nil {
		t.Fatal("Cluster rule not found after consolidation")
	}
	if clusterRule.Operator != OperatorRegexMatch {
		t.Errorf("Expected cluster operator '=~', got '%s'", clusterRule.Operator)
	}
	expectedCluster := []string{"prod-argocd", "prod-backoffice", "uat-allinone", "uat-l1-k8s"}
	if len(clusterRule.Values) != 4 {
		t.Errorf("Expected 4 cluster values, got %d", len(clusterRule.Values))
	}
	for i, expected := range expectedCluster {
		if clusterRule.Values[i] != expected {
			t.Errorf("Expected cluster value[%d] = '%s', got '%s'", i, expected, clusterRule.Values[i])
		}
	}
}
