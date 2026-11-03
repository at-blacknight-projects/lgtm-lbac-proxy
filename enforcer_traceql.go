package main

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/grafana/tempo/pkg/traceql"
	"github.com/rs/zerolog/log"
)

// TraceQLEnforcer manipulates and enforces tenant isolation on TraceQL queries.
type TraceQLEnforcer struct{}

// Enforce modifies a TraceQL query string to enforce multi-label access policy.
// It handles multiple label rules with different operators (=, !=, =~, !~) and logic (AND/OR).
// If the input query is empty, constructs a new query from the policy.
// If the input query is non-empty, validates existing attributes and injects policy filters.
// Returns the modified query or an error if parsing, validation, or modification fails.
func (TraceQLEnforcer) Enforce(query string, policy LabelPolicy) (string, error) {
	log.Trace().Str("function", "enforce").Str("query", query).Msg("input")

	// Validate policy first
	if err := policy.Validate(); err != nil {
		return "", fmt.Errorf("invalid label policy: %w", err)
	}

	// Handle empty query or just braces
	if query == "" || strings.TrimSpace(query) == "{}" {
		query = buildPolicyQuery(policy)
		log.Trace().Str("function", "enforce").Str("query", query).Msg("enforcing empty query")
		return query, nil
	}

	log.Trace().Str("function", "enforce").Str("query", query).Msg("enforcing")

	// Parse query to validate syntax
	ast, err := traceql.Parse(query)
	if err != nil {
		return "", fmt.Errorf("invalid TraceQL syntax: %w", err)
	}

	// Check if it's a no-op query (e.g., "{ true }")
	if ast.IsNoop() {
		query = buildPolicyQuery(policy)
		log.Trace().Str("function", "enforce").Str("query", query).Msg("enforcing noop query")
		return query, nil
	}

	// Get serialized version for manipulation
	serialized := ast.String()

	// Validate existing attributes against policy
	if err := validatePolicyAttributes(serialized, policy); err != nil {
		return "", err
	}

	// Check if query already contains all policy attributes
	hasPolicyAttributes := checkPolicyAttributes(serialized, policy)
	if hasPolicyAttributes {
		log.Trace().Str("function", "enforce").Str("query", serialized).Msg("enforced (already has policy attributes)")
		return serialized, nil
	}

	// Inject policy filter if not present
	filter := buildPolicyFilter(policy)
	modified := injectFilter(serialized, filter)

	// Validate modified query by re-parsing
	_, err = traceql.Parse(modified)
	if err != nil {
		return "", fmt.Errorf("failed to inject policy filter: %w", err)
	}

	log.Trace().Str("function", "enforce").Str("query", modified).Msg("enforced")
	return modified, nil
}

// buildPolicyQuery constructs a minimal TraceQL query from a LabelPolicy.
// Examples:
// - Single rule: { resource.namespace = "prod" }
// - Multiple rules (AND): { resource.namespace = "prod" && resource.team = "backend" }
// - Multiple values: { resource.namespace =~ "prod|staging" }
func buildPolicyQuery(policy LabelPolicy) string {
	filter := buildPolicyFilter(policy)
	return fmt.Sprintf("{ %s }", filter)
}

// buildPolicyFilter creates a filter expression from a LabelPolicy without enclosing braces.
// Handles different operators (=, !=, =~, !~) and logic (AND/OR).
// Examples:
// - resource.namespace = "prod"
// - resource.namespace =~ "prod|staging"
// - resource.namespace = "prod" && resource.team = "backend"
// - resource.namespace = "prod" || resource.team = "backend"
func buildPolicyFilter(policy LabelPolicy) string {
	var filters []string

	for _, rule := range policy.Rules {
		filter := buildRuleFilter(rule)
		filters = append(filters, filter)
	}

	// Combine filters with logic operator
	logicOp := " && "
	if policy.Logic == LogicOR {
		logicOp = " || "
	}

	return strings.Join(filters, logicOp)
}

// buildRuleFilter creates a filter expression for a single LabelRule.
// Handles different operators and multiple values.
// Examples:
// - resource.namespace = "prod"
// - resource.namespace != "test"
// - resource.namespace =~ "prod|staging"
// - resource.team !~ "external|guest"
func buildRuleFilter(rule LabelRule) string {
	operator := rule.Operator

	// For multiple values with = or !=, convert to regex
	if len(rule.Values) > 1 {
		operator = multiValueOperator(operator)
	}

	// Build value expression
	var valueExpr string
	if operator == OperatorRegexMatch || operator == OperatorRegexNoMatch {
		// For regex operators with multiple values, join with |
		if len(rule.Values) > 1 {
			// Escape regex special characters in values
			escapedValues := make([]string, len(rule.Values))
			for i, v := range rule.Values {
				escapedValues[i] = escapeRegexChars(v)
			}
			valueExpr = fmt.Sprintf(`"%s"`, strings.Join(escapedValues, "|"))
		} else {
			// Single value, use as-is (user-provided regex pattern)
			valueExpr = fmt.Sprintf(`"%s"`, rule.Values[0])
		}
	} else {
		// For = and !=, use single value without escaping
		valueExpr = fmt.Sprintf(`"%s"`, rule.Values[0])
	}

	return fmt.Sprintf("%s%s%s", rule.Name, operator, valueExpr)
}

// validatePolicyAttributes validates that any existing policy attributes in the query
// match the allowed values in the policy. Returns error if unauthorized values are found.
func validatePolicyAttributes(query string, policy LabelPolicy) error {
	// Build a map of label name to ALL allowed values across all rules
	// This handles OR logic where multiple rules may allow different values for the same label
	allowedValuesMap := make(map[string]map[string]bool)
	for _, rule := range policy.Rules {
		if _, exists := allowedValuesMap[rule.Name]; !exists {
			allowedValuesMap[rule.Name] = make(map[string]bool)
		}
		for _, v := range rule.Values {
			allowedValuesMap[rule.Name][v] = true
		}
	}

	// Check each label name in the policy
	for labelName, allowedValues := range allowedValuesMap {
		// Pattern to match attribute with value
		// Matches: resource.namespace = "value" or resource.namespace =~ "value1|value2"
		pattern := fmt.Sprintf(`%s\s*=~?\s*[\x60"]([^"\x60]+)[\x60"]`, regexp.QuoteMeta(labelName))
		re := regexp.MustCompile(pattern)

		matches := re.FindAllStringSubmatch(query, -1)
		if len(matches) == 0 {
			// Attribute not found in query, will be injected
			continue
		}

		// Validate all found attribute values
		for _, match := range matches {
			if len(match) < 2 {
				continue
			}
			value := match[1]

			// Split by pipe for regex patterns
			queryValues := strings.Split(value, "|")
			for _, queryValue := range queryValues {
				queryValue = strings.TrimSpace(queryValue)
				if _, ok := allowedValues[queryValue]; !ok {
					return fmt.Errorf("unauthorized %s: %s", labelName, queryValue)
				}
			}
		}
	}

	return nil
}

// checkPolicyAttributes checks if the query already contains all policy attributes.
// Returns true if all attributes from the policy are present in the query.
func checkPolicyAttributes(query string, policy LabelPolicy) bool {
	for _, rule := range policy.Rules {
		// Pattern to match attribute
		pattern := fmt.Sprintf(`%s\s*[=!]=?~?\s*[\x60"]`, regexp.QuoteMeta(rule.Name))
		re := regexp.MustCompile(pattern)

		if !re.MatchString(query) {
			// Attribute not found
			return false
		}
	}

	// All attributes found
	return true
}

// injectFilter injects a policy filter into an existing TraceQL query.
// The filter is combined with the existing query using the AND operator.
func injectFilter(query string, filter string) string {
	trimmed := strings.TrimSpace(query)

	// Handle { true } case (result of empty query parsing)
	if trimmed == "{ true }" {
		return fmt.Sprintf("{ %s }", filter)
	}

	// Remove outer braces, inject filter with AND, add braces back
	if strings.HasPrefix(trimmed, "{") && strings.HasSuffix(trimmed, "}") {
		inner := strings.TrimSpace(trimmed[1 : len(trimmed)-1])
		if inner == "" || inner == "true" {
			return fmt.Sprintf("{ %s }", filter)
		}
		return fmt.Sprintf("{ %s && %s }", filter, inner)
	}

	return query
}

// escapeRegexChars escapes special regex characters in a string to prevent regex injection.
// Escapes: . * + ? [ ] ( ) | ^ $ \
func escapeRegexChars(s string) string {
	// Must escape backslash first to avoid double-escaping
	escaped := strings.ReplaceAll(s, `\`, `\\`)

	// Then escape other special characters
	replacements := map[string]string{
		".": `\.`,
		"*": `\*`,
		"+": `\+`,
		"?": `\?`,
		"[": `\[`,
		"]": `\]`,
		"(": `\(`,
		")": `\)`,
		"|": `\|`,
		"^": `\^`,
		"$": `\$`,
	}
	for char, replacement := range replacements {
		escaped = strings.ReplaceAll(escaped, char, replacement)
	}
	return escaped
}
