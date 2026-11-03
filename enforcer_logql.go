package main

import (
	"fmt"
	"strings"

	"github.com/rs/zerolog/log"

	logqlv2 "github.com/observatorium/api/logql/v2"
	"github.com/prometheus/prometheus/model/labels"
)

// LogQLEnforcer manipulates and enforces tenant isolation on LogQL queries.
type LogQLEnforcer struct{}

// Enforce modifies a LogQL query string to enforce multi-label policy.
// Supports multiple label rules with different operators (=, !=, =~, !~).
// Handles AND logic by injecting all rules as separate matchers.
// Returns the modified query or an error if parsing/validation fails.
func (LogQLEnforcer) Enforce(query string, policy LabelPolicy) (string, error) {
	log.Trace().Str("function", "enforce").Str("query", query).Msg("input")

	// Validate policy
	if err := policy.Validate(); err != nil {
		return "", fmt.Errorf("invalid policy: %w", err)
	}

	// Check for cluster-wide access
	if policy.HasClusterWideAccess() {
		return query, nil
	}

	// Handle empty query - build from scratch
	if query == "" {
		return buildLogQLQueryFromPolicy(policy), nil
	}

	// Parse existing query
	expr, err := logqlv2.ParseExpr(query)
	if err != nil {
		return "", err
	}

	errMsg := error(nil)

	// Walk AST and inject matchers
	expr.Walk(func(expr interface{}) {
		switch labelExpression := expr.(type) {
		case *logqlv2.StreamMatcherExpr:
			matchers, err := EnforceMultiLabelMatchers(labelExpression.Matchers(), policy)
			if err != nil {
				errMsg = err
				return
			}
			labelExpression.SetMatchers(matchers)
		default:
			// Do nothing
		}
	})

	if errMsg != nil {
		return "", errMsg
	}

	log.Trace().Str("function", "enforce").Str("query", expr.String()).Msg("enforced")
	return expr.String(), nil
}

// buildLogQLQueryFromPolicy constructs a minimal LogQL query from LabelPolicy.
// Combines multiple values for same label using regex OR.
func buildLogQLQueryFromPolicy(policy LabelPolicy) string {
	var matchers []string

	for _, rule := range policy.Rules {
		operator := rule.Operator
		value := rule.Values[0]

		// Combine multiple values with regex OR
		if len(rule.Values) > 1 {
			value = strings.Join(rule.Values, "|")
			operator = multiValueOperator(operator)
		}

		matchers = append(matchers, fmt.Sprintf("%s%s\"%s\"", rule.Name, operator, value))
	}

	return fmt.Sprintf("{%s}", strings.Join(matchers, ", "))
}

// EnforceMultiLabelMatchers enforces multi-label policy on existing matchers.
// Validates existing matchers against policy rules and injects missing ones.
// Returns error if query contains unauthorized label values.
func EnforceMultiLabelMatchers(queryMatches []*labels.Matcher, policy LabelPolicy) ([]*labels.Matcher, error) {
	// Track which rules have been found in the query
	foundRules := make(map[string]bool)

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

	// Validate existing matchers against policy
	for _, queryMatcher := range queryMatches {
		if allowedValues, hasRule := allowedValuesMap[queryMatcher.Name]; hasRule {
			foundRules[queryMatcher.Name] = true

			// Validate the matcher's values against all allowed values
			if err := validateMatcherAgainstAllowedValues(queryMatcher, allowedValues); err != nil {
				return nil, err
			}
		}
	}

	// Inject missing rules
	for _, rule := range policy.Rules {
		if !foundRules[rule.Name] {
			matcher := ruleToMatcher(rule)
			queryMatches = append(queryMatches, matcher)
		}
	}

	return queryMatches, nil
}

// validateMatcherAgainstAllowedValues checks if a matcher's values are in the allowed set.
func validateMatcherAgainstAllowedValues(matcher *labels.Matcher, allowedValues map[string]bool) error {
	// Extract values from matcher (handle regex patterns with |)
	matcherValues := strings.Split(matcher.Value, "|")

	// Check if all matcher values are allowed
	for _, matcherValue := range matcherValues {
		if !allowedValues[matcherValue] {
			return fmt.Errorf("unauthorized %s: %s", matcher.Name, matcherValue)
		}
	}

	return nil
}
