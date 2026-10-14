package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/fsnotify/fsnotify"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

// Labelstore defines the interface for retrieving tenant labels based on user identity.
// Implementations are responsible for connecting to their backend and mapping
// user identities to allowed tenant labels.
//
// This interface is authentication-agnostic and focuses purely on the authorization concern
// of mapping user identities to tenant labels.
type Labelstore interface {
	// Connect establishes a connection with the label store using provided configuration.
	// The configuration contains label store-specific settings like file paths or database URLs.
	//
	// Returns error if connection fails or configuration is invalid.
	Connect(config LabelStoreConfig) error

	// GetLabelPolicy retrieves the complete label policy for the given user identity.
	// This method supports multi-label enforcement with flexible operators and logic.
	//
	// Parameters:
	//   - identity: User identity containing username and group memberships
	//   - defaultLabel: Default label name to use for policy rules
	//
	// Returns:
	//   - *LabelPolicy: Complete policy with rules, logic, and override settings
	//   - error: Error if policy cannot be retrieved or is invalid
	//
	// Behavior:
	//   - Returns nil error and policy with cluster-wide access for #cluster-wide users
	//   - Returns policy with merged rules from user and group memberships
	//   - Returns error if user has no labels configured
	GetLabelPolicy(identity UserIdentity, defaultLabel string) (*LabelPolicy, error)
}

// WithLabelStore initializes and connects to the file-based label store.
// It assigns the connected LabelStore to the App instance and returns it.
// If an error occurs during the connection, it logs a fatal error.
func (a *App) WithLabelStore() *App {
	if a.ingestOnly() {
		log.Info().Msg("Ingest-only: no label store")
		return a
	}
	a.LabelStore = &FileLabelStore{}
	err := a.LabelStore.Connect(a.Cfg.LabelStore)
	if err != nil {
		log.Fatal().Err(err).Msg("Error connecting to labelstore")
	}
	return a
}

// FileLabelStore provides file-based label store with eager policy parsing.
// All policies are parsed and validated during initialization/reload,
// eliminating on-demand parsing overhead and ensuring fail-fast validation.
type FileLabelStore struct {
	parser      *PolicyParser           // Parser for converting raw YAML to policies
	policyCache map[string]*LabelPolicy // Cache of eagerly-parsed policies (user:username, group:groupname)
}

func (c *FileLabelStore) Connect(config LabelStoreConfig) error {
	// Initialize parser and cache
	c.parser = NewPolicyParser()
	c.policyCache = make(map[string]*LabelPolicy)

	v := viper.NewWithOptions(viper.KeyDelimiter("::"))
	v.SetConfigName("labels")
	v.SetConfigType("yaml")

	// Use configuration paths instead of hardcoded values
	for _, path := range config.ConfigPaths {
		v.AddConfigPath(path)
	}

	err := v.MergeInConfig()
	if err != nil {
		return err
	}

	// Load raw data for extended format support
	// We pass the config paths and viper instance to loadLabels
	err = c.loadLabels(v, config.ConfigPaths)
	if err != nil {
		log.Fatal().Err(err).Msg("Error while loading label configuration")
		return err
	}

	// Watch for configuration changes
	v.OnConfigChange(func(e fsnotify.Event) {
		log.Info().Str("file", e.Name).Msg("Config file changed")
		err = v.MergeInConfig()
		if err != nil {
			log.Fatal().Err(err).Msg("Error while reloading config file")
		}
		err = c.loadLabels(v, config.ConfigPaths)
		if err != nil {
			log.Fatal().Err(err).Msg("Error while reloading label configuration")
		}
	})
	v.WatchConfig()

	log.Debug().Msg("Label store connected")
	return nil
}

// loadLabels loads label configuration from viper (extended format only)
// loadLabels loads label configuration from YAML file with case preservation
// We read the YAML file directly instead of using Viper to parse it, because Viper
// normalizes all keys to lowercase by design. Direct YAML parsing preserves the
// original case of usernames and groups from the YAML file.
func (c *FileLabelStore) loadLabels(v *viper.Viper, configPaths []string) error {
	var yamlContent []byte
	var err error
	var filePath string

	// Find and read the labels.yaml file from config paths
	for _, path := range configPaths {
		candidate := filepath.Join(path, "labels.yaml")
		if _, err := os.Stat(candidate); err == nil {
			filePath = candidate
			yamlContent, err = os.ReadFile(candidate)
			if err == nil {
				break
			}
		}
	}

	if len(yamlContent) == 0 {
		return fmt.Errorf("labels.yaml file not found in configured paths: %v", configPaths)
	}

	// Parse YAML directly to preserve case sensitivity
	// Using gopkg.in/yaml.v3 which preserves key case unlike Viper
	var rawData map[string]RawLabelData
	err = yaml.Unmarshal(yamlContent, &rawData)
	if err != nil {
		return fmt.Errorf("error unmarshalling YAML from %s: %w", filePath, err)
	}

	// Validate format at startup - detect simple format early
	simpleFormatCount := 0
	for key, data := range rawData {
		if _, hasRules := data["_rules"]; !hasRules {
			// Skip cluster-wide entries
			if _, hasClusterWide := data["#cluster-wide"]; hasClusterWide {
				continue
			}
			// Check if this looks like simple format
			if len(data) > 0 {
				simpleFormatCount++
				log.Error().
					Str("entry", key).
					Msg("DEPRECATED FORMAT: Simple label format detected - migration required before v0.12.0+")
			}
		}
	}

	// Fail fast on startup if simple format is detected
	if simpleFormatCount > 0 {
		return fmt.Errorf("DEPRECATED FORMAT: %d entries in simple format detected\n\n"+
			"The simple label format is no longer supported in v0.12.0+\n"+
			"All entries must use the extended format with _rules key.\n\n"+
			"Migration Required:\n"+
			"  1. Run pre-upgrade check: ./scripts/pre-upgrade-check.sh\n"+
			"  2. Use migration tool: cd cmd/migrate-labels && go build && ./migrate-labels -input ../../configs/labels.yaml\n\n"+
			"See cmd/migrate-labels/README.md for detailed instructions", simpleFormatCount)
	}

	// Clear policy cache on reload - prepare for eager parsing
	c.policyCache = make(map[string]*LabelPolicy)

	// Eager parsing: Parse all policies during initialization
	// This provides fail-fast validation and eliminates on-demand parsing overhead
	var parseErrors []string
	parsedCount := 0

	for key, data := range rawData {
		// Parse policy using the default label (will be provided per-request, so use empty string for now)
		// Note: defaultLabel is set during GetLabelPolicy, but for eager parsing we need a placeholder
		policy, err := c.parser.ParseUserPolicy(data, "")
		if err != nil {
			parseErrors = append(parseErrors, fmt.Sprintf("entry '%s': %v", key, err))
			continue
		}

		// Store parsed policy with simple cache key format
		// Use prefixes to distinguish users from groups
		cacheKey := "entry:" + key
		c.policyCache[cacheKey] = policy
		parsedCount++
	}

	// Fail fast if any policy failed to parse
	if len(parseErrors) > 0 {
		return fmt.Errorf("INVALID POLICY CONFIGURATION: %d entries failed to parse:\n%s\n\n"+
			"All policies must be valid before the proxy can start.\n"+
			"Fix the configuration errors listed above and restart.",
			len(parseErrors), strings.Join(parseErrors, "\n"))
	}

	log.Debug().Int("parsedCount", parsedCount).Msg("Labels loaded and parsed eagerly")
	return nil
}

// GetLabelPolicy retrieves the label policy for a user/group identity.
// All policies are pre-parsed during initialization, so this method only
// performs cache lookup and merging for the specific user+groups combination.
func (c *FileLabelStore) GetLabelPolicy(identity UserIdentity, defaultLabel string) (*LabelPolicy, error) {
	username := identity.Username
	groups := identity.Groups

	// Check cache for merged policy (user + specific group combination)
	// Merged policies are cached per unique user+groups combination for performance
	mergedCacheKey := "merged:" + username + ":" + strings.Join(groups, ",")
	if cached, ok := c.policyCache[mergedCacheKey]; ok {
		return cached, nil
	}

	// Collect pre-parsed policies from cache (user + groups)
	// All policies were eagerly parsed during loadLabels()
	var policies []*LabelPolicy

	// Look up user policy
	userCacheKey := "entry:" + username
	if userPolicy, ok := c.policyCache[userCacheKey]; ok {
		policies = append(policies, userPolicy)
	}

	// Look up group policies
	for _, group := range groups {
		groupCacheKey := "entry:" + group
		if groupPolicy, ok := c.policyCache[groupCacheKey]; ok {
			policies = append(policies, groupPolicy)
		}
	}

	if len(policies) == 0 {
		return nil, fmt.Errorf("no policy found for user %s", username)
	}

	// Merge policies for this specific user+groups combination
	mergedPolicy := c.mergePolicies(policies)

	// Check for cluster-wide access
	if mergedPolicy.HasClusterWideAccess() {
		mergedPolicy = &LabelPolicy{
			Rules: []LabelRule{{Name: "#cluster-wide", Operator: OperatorEquals, Values: []string{"true"}}},
			Logic: LogicAND,
		}
	}

	// Cache the merged policy for this user+groups combination
	c.policyCache[mergedCacheKey] = mergedPolicy

	return mergedPolicy, nil
}

// mergePolicies combines multiple policies into a single policy.
// Rules are merged with OR logic by default (user can access if any policy allows).
// When merging policies from multiple groups, duplicate label names are consolidated
// by combining their values using regex OR operators (e.g., environment=~"prod|uat").
func (c *FileLabelStore) mergePolicies(policies []*LabelPolicy) *LabelPolicy {
	if len(policies) == 0 {
		return &LabelPolicy{Rules: []LabelRule{}, Logic: LogicAND}
	}

	if len(policies) == 1 {
		return policies[0]
	}

	// Merge all rules from all policies
	merged := &LabelPolicy{
		Rules: []LabelRule{},
		Logic: LogicOR, // Multiple policies are combined with OR (more permissive)
	}

	for _, policy := range policies {
		if policy.Override {
			// If a policy has Override=true, it replaces all previous policies
			merged.Rules = policy.Rules
			merged.Logic = policy.Logic
			continue
		}
		merged.Rules = append(merged.Rules, policy.Rules...)
	}

	// Deduplicate exact duplicate rules (same name, operator, values)
	merged.Rules = c.deduplicateRules(merged.Rules)

	// Consolidate rules with duplicate label names by merging their values
	// This fixes invalid query generation for multi-group users
	merged.Rules = c.consolidateDuplicateLabels(merged.Rules)

	return merged
}

// deduplicateRules removes duplicate rules from a slice
func (c *FileLabelStore) deduplicateRules(rules []LabelRule) []LabelRule {
	seen := make(map[string]bool)
	result := []LabelRule{}

	for _, rule := range rules {
		// Create a unique key for the rule
		key := fmt.Sprintf("%s|%s|%v", rule.Name, rule.Operator, rule.Values)
		if !seen[key] {
			seen[key] = true
			result = append(result, rule)
		}
	}

	return result
}

// consolidateDuplicateLabels deduplicates rules with the same label name by consolidating
// their values using regex OR operators. This fixes invalid query generation when users
// belong to multiple groups with conflicting label rules.
//
// Algorithm:
//  1. Group rules by label name
//  2. For each group with duplicates, merge values into a single rule
//  3. Upgrade operators to regex when needed (= → =~, != → !~)
//  4. Sort and deduplicate values for deterministic output
//
// Example:
//
//	Input:  [{name: "environment", op: "=", values: ["prod"]},
//	         {name: "environment", op: "=", values: ["uat"]}]
//	Output: [{name: "environment", op: "=~", values: ["prod", "uat"]}]
func (c *FileLabelStore) consolidateDuplicateLabels(rules []LabelRule) []LabelRule {
	if len(rules) <= 1 {
		return rules
	}

	// Group rules by label name
	labelGroups := make(map[string][]LabelRule)
	for _, rule := range rules {
		labelGroups[rule.Name] = append(labelGroups[rule.Name], rule)
	}

	// Consolidate each group
	var result []LabelRule
	for labelName, group := range labelGroups {
		if len(group) == 1 {
			// No duplication, keep original rule
			result = append(result, group[0])
		} else {
			// Multiple rules for same label - consolidate values
			consolidated := c.mergeRuleGroup(labelName, group)
			if consolidated != nil {
				result = append(result, *consolidated)

				// Log consolidation for debugging
				log.Debug().
					Str("label", labelName).
					Int("original_rules", len(group)).
					Int("consolidated_values", len(consolidated.Values)).
					Str("operator", consolidated.Operator).
					Msg("Consolidated duplicate label rules")
			}
		}
	}

	// Sort result by label name for deterministic output
	sort.Slice(result, func(i, j int) bool {
		return result[i].Name < result[j].Name
	})

	return result
}

// mergeRuleGroup consolidates multiple rules with the same label name into a single rule.
// It collects all unique values, detects operator conflicts, and chooses an appropriate
// final operator for OR logic.
//
// Operator Resolution:
//   - Positive matches (=, =~) take priority over negative matches (!=, !~)
//   - If any rule uses regex (=~, !~), the result uses regex
//   - Conflicts between positive and negative operators log a warning
//
// Returns nil if the group is empty.
func (c *FileLabelStore) mergeRuleGroup(labelName string, group []LabelRule) *LabelRule {
	if len(group) == 0 {
		return nil
	}

	if len(group) == 1 {
		return &group[0]
	}

	// Collect all unique values
	valueSet := make(map[string]bool)
	var allValues []string

	// Track operator types
	hasPositiveMatch := false // = or =~
	hasNegativeMatch := false // != or !~
	hasRegexOperator := false // =~ or !~

	for _, rule := range group {
		// Track operator types
		switch rule.Operator {
		case OperatorEquals, OperatorRegexMatch:
			hasPositiveMatch = true
			if rule.Operator == OperatorRegexMatch {
				hasRegexOperator = true
			}
		case OperatorNotEquals, OperatorRegexNoMatch:
			hasNegativeMatch = true
			if rule.Operator == OperatorRegexNoMatch {
				hasRegexOperator = true
			}
		}

		// Collect values
		for _, value := range rule.Values {
			if !valueSet[value] {
				valueSet[value] = true
				allValues = append(allValues, value)
			}
		}
	}

	// Detect operator conflicts
	if hasPositiveMatch && hasNegativeMatch {
		log.Warn().
			Str("label", labelName).
			Msg("Conflicting operators detected (positive + negative) - using positive match for OR logic")
	}

	// Choose final operator based on OR logic (permissive)
	// Priority: positive match > negative match, regex > exact
	var finalOperator string
	if hasPositiveMatch {
		// Positive match wins in OR logic
		if hasRegexOperator || len(allValues) > 1 {
			finalOperator = OperatorRegexMatch // Use =~ for multiple values or existing regex
		} else {
			finalOperator = OperatorEquals // Single value, exact match
		}
	} else {
		// Only negative matches
		if hasRegexOperator || len(allValues) > 1 {
			finalOperator = OperatorRegexNoMatch // Use !~ for multiple values or existing regex
		} else {
			finalOperator = OperatorNotEquals // Single value, exact not-equal
		}
	}

	// Sort values for deterministic output
	sort.Strings(allValues)

	return &LabelRule{
		Name:     labelName,
		Operator: finalOperator,
		Values:   allValues,
	}
}
