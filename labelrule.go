package main

import (
	"fmt"
	"regexp"
)

// Operator constants for label matching
const (
	OperatorEquals       = "="   // Exact match
	OperatorNotEquals    = "!="  // Not equal
	OperatorRegexMatch   = "=~"  // Regex match
	OperatorRegexNoMatch = "!~"  // Negative regex match
)

// multiValueOperator returns the operator to use when a rule's values are joined into
// one alternation: = and != become their regex forms, and the regex operators are
// returned unchanged. The PromQL, LogQL and TraceQL enforcers and ruleToMatcher all
// build multi-value matchers this way.
func multiValueOperator(operator string) string {
	switch operator {
	case OperatorEquals:
		return OperatorRegexMatch
	case OperatorNotEquals:
		return OperatorRegexNoMatch
	}
	return operator
}

// Logic constants for combining multiple rules
const (
	LogicAND = "AND" // All rules must match (default)
	LogicOR  = "OR"  // Any rule can match
)

// LabelRule represents a single label matching rule.
// It defines a label name, an operator, and one or more values to match against.
type LabelRule struct {
	Name     string   `yaml:"name"`     // Label name (e.g., "namespace", "team")
	Operator string   `yaml:"operator"` // Operator: "=", "!=", "=~", "!~"
	Values   []string `yaml:"values"`   // Values to match
}

// LabelPolicy represents the complete access policy for a user or group.
// It contains multiple label rules and defines how they should be combined.
type LabelPolicy struct {
	Rules    []LabelRule `yaml:"rules"`    // Multiple label rules
	Logic    string      `yaml:"logic"`    // Combination logic: "AND" or "OR" (default: AND)
	Override bool        `yaml:"override"` // If true, completely replaces default rules
}

// Validate checks if the LabelRule is valid.
// Returns an error if the rule has invalid operator, empty name, or no values.
func (r *LabelRule) Validate() error {
	if r.Name == "" {
		return fmt.Errorf("label rule name cannot be empty")
	}

	switch r.Operator {
	case OperatorEquals, OperatorNotEquals, OperatorRegexMatch, OperatorRegexNoMatch:
		// Valid operator
	default:
		return fmt.Errorf("invalid operator %q: must be one of =, !=, =~, !~", r.Operator)
	}

	if len(r.Values) == 0 {
		return fmt.Errorf("label rule must have at least one value")
	}

	// Validate regex patterns for regex operators
	if r.Operator == OperatorRegexMatch || r.Operator == OperatorRegexNoMatch {
		for _, value := range r.Values {
			if _, err := regexp.Compile(value); err != nil {
				return fmt.Errorf("invalid regex pattern %q: %w", value, err)
			}
		}
	}

	return nil
}

// Validate checks if the LabelPolicy is valid.
// Returns an error if any rule is invalid or logic is incorrect.
func (p *LabelPolicy) Validate() error {
	if len(p.Rules) == 0 {
		return fmt.Errorf("label policy must have at least one rule")
	}

	// Validate logic
	if p.Logic == "" {
		p.Logic = LogicAND // Default to AND
	}
	if p.Logic != LogicAND && p.Logic != LogicOR {
		return fmt.Errorf("invalid logic %q: must be AND or OR", p.Logic)
	}

	// Validate each rule
	for i, rule := range p.Rules {
		if err := rule.Validate(); err != nil {
			return fmt.Errorf("rule %d: %w", i, err)
		}
	}

	return nil
}

// HasClusterWideAccess checks if the policy grants cluster-wide access.
// This is determined by checking if any rule has the special #cluster-wide label.
func (p *LabelPolicy) HasClusterWideAccess() bool {
	for _, rule := range p.Rules {
		if rule.Name == "#cluster-wide" {
			return true
		}
	}
	return false
}
