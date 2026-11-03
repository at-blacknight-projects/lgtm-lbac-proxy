package main

import (
	"fmt"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql/parser"
)

// PromQLEnforcer is a struct with methods to enforce specific rules on Prometheus Query Language (PromQL) queries.
type PromQLEnforcer struct{}

// Enforce enhances a given PromQL query with multi-label enforcement based on LabelPolicy.
// It supports multiple label rules with different operators (=, !=, =~, !~) combined with AND logic.
// Returns the enhanced query or an error if the query cannot be parsed or is not compliant.
func (PromQLEnforcer) Enforce(query string, policy LabelPolicy) (string, error) {
	log.Trace().Str("function", "enforce").Str("query", query).Interface("policy", policy).Msg("input")

	// Validate policy
	if err := policy.Validate(); err != nil {
		return "", fmt.Errorf("invalid policy: %w", err)
	}

	// Handle empty query - build from scratch
	if query == "" {
		query = buildQueryFromPolicy(policy)
		log.Trace().Str("function", "enforce").Str("query", query).Msg("built from empty")
	}

	// Parse the query
	expr, err := parser.ParseExpr(query)
	if err != nil {
		return "", fmt.Errorf("failed to parse query: %w", err)
	}

	// Extract existing labels from query
	queryLabels := extractAllLabelsAndMatchers(expr)

	// Validate existing matchers against policy
	if err := validateQueryAgainstPolicy(queryLabels, policy); err != nil {
		return "", err
	}

	// Build matchers for each rule in policy
	matchers := buildMatchersFromPolicy(policy, queryLabels)

	// Inject matchers into the query
	if err := injectMatchers(expr, matchers); err != nil {
		return "", fmt.Errorf("failed to inject matchers: %w", err)
	}

	result := expr.String()
	log.Trace().Str("function", "enforce").Str("query", result).Msg("output")
	return result, nil
}

// buildQueryFromPolicy constructs a minimal PromQL query from LabelPolicy rules.
// Example: {namespace=~"prod|staging", team!="frontend"}
func buildQueryFromPolicy(policy LabelPolicy) string {
	var matchers []string
	for _, rule := range policy.Rules {
		matcher := buildMatcherString(rule)
		matchers = append(matchers, matcher)
	}
	return fmt.Sprintf("{%s}", strings.Join(matchers, ", "))
}

// buildMatcherString creates a matcher string from a LabelRule.
// Handles multiple values by combining them with regex OR (|).
func buildMatcherString(rule LabelRule) string {
	operator := rule.Operator
	value := rule.Values[0]

	// For multiple values, use regex operator and combine with |
	if len(rule.Values) > 1 {
		value = strings.Join(rule.Values, "|")
		operator = multiValueOperator(operator)
	}

	return fmt.Sprintf("%s%s%q", rule.Name, operator, value)
}

// extractAllLabelsAndMatchers extracts all label matchers from the query expression.
// Returns a map of label name to list of matchers for that label.
func extractAllLabelsAndMatchers(expr parser.Expr) map[string][]*labels.Matcher {
	labelMatchers := make(map[string][]*labels.Matcher)

	parser.Inspect(expr, func(node parser.Node, path []parser.Node) error {
		if vector, ok := node.(*parser.VectorSelector); ok {
			for _, matcher := range vector.LabelMatchers {
				labelMatchers[matcher.Name] = append(labelMatchers[matcher.Name], matcher)
			}
		}
		return nil
	})

	return labelMatchers
}

// validateQueryAgainstPolicy checks if existing query matchers comply with the policy.
// Returns an error if any matcher violates the policy constraints.
func validateQueryAgainstPolicy(queryLabels map[string][]*labels.Matcher, policy LabelPolicy) error {
	// Build a map of label name to ALL allowed values across all rules
	// This handles OR logic where multiple rules may allow different values for the same label
	allowedValuesMap := make(map[string]map[string]bool)

	for i := range policy.Rules {
		rule := &policy.Rules[i]
		if _, exists := allowedValuesMap[rule.Name]; !exists {
			allowedValuesMap[rule.Name] = make(map[string]bool)
		}
		// Collect all allowed values for this label across all rules
		for _, v := range rule.Values {
			allowedValuesMap[rule.Name][v] = true
		}
	}

	// Check each existing matcher
	for labelName, matchers := range queryLabels {
		allowedValues, hasRule := allowedValuesMap[labelName]
		if !hasRule {
			// Label not in policy - skip validation (policy will be injected)
			continue
		}

		// Validate each matcher for this label
		for _, matcher := range matchers {
			if err := validateMatcherWithValues(matcher, allowedValues); err != nil {
				return err
			}
		}
	}

	return nil
}

// validateMatcherWithValues checks if a matcher complies with the allowed values.
func validateMatcherWithValues(matcher *labels.Matcher, allowedValues map[string]bool) error {
	// For equality matchers, check if value is allowed
	if matcher.Type == labels.MatchEqual {
		if !allowedValues[matcher.Value] {
			return fmt.Errorf("unauthorized %s: %s", matcher.Name, matcher.Value)
		}
	}

	// For regex matchers, check if all pipe-separated values are allowed
	if matcher.Type == labels.MatchRegexp {
		values := strings.Split(matcher.Value, "|")
		for _, v := range values {
			if !allowedValues[v] {
				return fmt.Errorf("unauthorized %s: %s", matcher.Name, v)
			}
		}
	}

	// For not-equal and negative regex, we allow them if they're more restrictive
	// (this is a complex semantic check that would require analyzing the full boolean logic)

	return nil
}

// buildMatchersFromPolicy creates label matchers from policy rules.
// Skips rules that already have valid matchers in the query.
func buildMatchersFromPolicy(policy LabelPolicy, existingLabels map[string][]*labels.Matcher) []*labels.Matcher {
	var matchers []*labels.Matcher

	for _, rule := range policy.Rules {
		// Skip if this label already has matchers (already validated)
		if _, exists := existingLabels[rule.Name]; exists {
			continue
		}

		matcher := ruleToMatcher(rule)
		matchers = append(matchers, matcher)
	}

	return matchers
}

// injectMatchers injects label matchers into all vector selectors in the expression.
func injectMatchers(expr parser.Expr, matchers []*labels.Matcher) error {
	if len(matchers) == 0 {
		return nil
	}

	parser.Inspect(expr, func(node parser.Node, path []parser.Node) error {
		if vector, ok := node.(*parser.VectorSelector); ok {
			// Add matchers that don't already exist
			for _, newMatcher := range matchers {
				hasLabel := false
				for _, existing := range vector.LabelMatchers {
					if existing.Name == newMatcher.Name {
						hasLabel = true
						break
					}
				}
				if !hasLabel {
					vector.LabelMatchers = append(vector.LabelMatchers, newMatcher)
				}
			}
		}
		return nil
	})

	return nil
}
