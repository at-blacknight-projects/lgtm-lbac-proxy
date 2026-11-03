package main

import (
	"strings"
	"testing"
)

func TestPromQLEnforcer_Enforce(t *testing.T) {
	tests := []struct {
		name    string
		query   string
		policy  LabelPolicy
		want    string
		wantErr bool
		errMsg  string
	}{
		// Empty query tests
		{
			name:  "empty query with single rule",
			query: "",
			policy: LabelPolicy{
				Rules: []LabelRule{
					{Name: "namespace", Operator: "=", Values: []string{"prod"}},
				},
				Logic: LogicAND,
			},
			want:    `{namespace="prod"}`,
			wantErr: false,
		},
		{
			name:  "empty query with multiple values",
			query: "",
			policy: LabelPolicy{
				Rules: []LabelRule{
					{Name: "namespace", Operator: "=", Values: []string{"prod", "staging"}},
				},
				Logic: LogicAND,
			},
			want:    `{namespace=~"prod|staging"}`,
			wantErr: false,
		},
		{
			name:  "empty query with multiple rules",
			query: "",
			policy: LabelPolicy{
				Rules: []LabelRule{
					{Name: "namespace", Operator: "=~", Values: []string{"prod", "staging"}},
					{Name: "team", Operator: "!=", Values: []string{"frontend"}},
				},
				Logic: LogicAND,
			},
			want:    `{namespace=~"prod|staging", team!="frontend"}`,
			wantErr: false,
		},

		// Simple query injection tests
		{
			name:  "simple query with single label injection",
			query: "up",
			policy: LabelPolicy{
				Rules: []LabelRule{
					{Name: "namespace", Operator: "=", Values: []string{"prod"}},
				},
				Logic: LogicAND,
			},
			want:    `up{namespace="prod"}`,
			wantErr: false,
		},
		{
			name:  "simple query with multiple label injection",
			query: "up",
			policy: LabelPolicy{
				Rules: []LabelRule{
					{Name: "namespace", Operator: "=~", Values: []string{"prod", "staging"}},
					{Name: "team", Operator: "=", Values: []string{"backend"}},
				},
				Logic: LogicAND,
			},
			want:    `up{namespace=~"prod|staging", team="backend"}`,
			wantErr: false,
		},

		// Complex query tests
		{
			name:  "rate function with label injection",
			query: "rate(http_requests_total[5m])",
			policy: LabelPolicy{
				Rules: []LabelRule{
					{Name: "namespace", Operator: "=~", Values: []string{"prod", "staging"}},
					{Name: "team", Operator: "!=", Values: []string{"frontend"}},
				},
				Logic: LogicAND,
			},
			want:    `rate(http_requests_total{namespace=~"prod|staging", team!="frontend"}[5m])`,
			wantErr: false,
		},
		{
			name:  "aggregation with label injection",
			query: "sum(rate(http_requests_total[5m])) by (status)",
			policy: LabelPolicy{
				Rules: []LabelRule{
					{Name: "namespace", Operator: "=", Values: []string{"prod"}},
				},
				Logic: LogicAND,
			},
			want:    `sum(rate(http_requests_total{namespace="prod"}[5m])) by (status)`,
			wantErr: false,
		},

		// Operator tests
		{
			name:  "not equals operator",
			query: "up",
			policy: LabelPolicy{
				Rules: []LabelRule{
					{Name: "namespace", Operator: "!=", Values: []string{"test"}},
				},
				Logic: LogicAND,
			},
			want:    `up{namespace!="test"}`,
			wantErr: false,
		},
		{
			name:  "regex match operator",
			query: "up",
			policy: LabelPolicy{
				Rules: []LabelRule{
					{Name: "namespace", Operator: "=~", Values: []string{"prod.*"}},
				},
				Logic: LogicAND,
			},
			want:    `up{namespace=~"prod.*"}`,
			wantErr: false,
		},
		{
			name:  "negative regex operator",
			query: "up",
			policy: LabelPolicy{
				Rules: []LabelRule{
					{Name: "namespace", Operator: "!~", Values: []string{"test.*"}},
				},
				Logic: LogicAND,
			},
			want:    `up{namespace!~"test.*"}`,
			wantErr: false,
		},
		{
			name:  "multiple values with not equals",
			query: "up",
			policy: LabelPolicy{
				Rules: []LabelRule{
					{Name: "namespace", Operator: "!=", Values: []string{"test", "dev"}},
				},
				Logic: LogicAND,
			},
			want:    `up{namespace!~"test|dev"}`,
			wantErr: false,
		},

		// Validation tests - authorized queries
		{
			name:  "existing label matches policy",
			query: `up{namespace="prod"}`,
			policy: LabelPolicy{
				Rules: []LabelRule{
					{Name: "namespace", Operator: "=", Values: []string{"prod", "staging"}},
				},
				Logic: LogicAND,
			},
			want:    `up{namespace="prod"}`,
			wantErr: false,
		},
		{
			name:  "existing regex label matches policy",
			query: `up{namespace=~"prod|staging"}`,
			policy: LabelPolicy{
				Rules: []LabelRule{
					{Name: "namespace", Operator: "=", Values: []string{"prod", "staging"}},
				},
				Logic: LogicAND,
			},
			want:    `up{namespace=~"prod|staging"}`,
			wantErr: false,
		},
		{
			name:  "query with multiple existing labels",
			query: `http_requests_total{namespace="prod", status="200"}`,
			policy: LabelPolicy{
				Rules: []LabelRule{
					{Name: "namespace", Operator: "=", Values: []string{"prod"}},
					{Name: "team", Operator: "=", Values: []string{"backend"}},
				},
				Logic: LogicAND,
			},
			want:    `http_requests_total{namespace="prod", status="200", team="backend"}`,
			wantErr: false,
		},

		// Validation tests - unauthorized queries
		{
			name:  "unauthorized namespace value",
			query: `up{namespace="unauthorized"}`,
			policy: LabelPolicy{
				Rules: []LabelRule{
					{Name: "namespace", Operator: "=", Values: []string{"prod", "staging"}},
				},
				Logic: LogicAND,
			},
			wantErr: true,
			errMsg:  "unauthorized namespace: unauthorized",
		},
		{
			name:  "unauthorized value in regex",
			query: `up{namespace=~"prod|unauthorized"}`,
			policy: LabelPolicy{
				Rules: []LabelRule{
					{Name: "namespace", Operator: "=", Values: []string{"prod", "staging"}},
				},
				Logic: LogicAND,
			},
			wantErr: true,
			errMsg:  "unauthorized namespace: unauthorized",
		},

		// Complex multi-label scenarios
		{
			name:  "multiple rules with different operators",
			query: "http_requests_total",
			policy: LabelPolicy{
				Rules: []LabelRule{
					{Name: "namespace", Operator: "=~", Values: []string{"prod", "staging"}},
					{Name: "team", Operator: "!=", Values: []string{"test"}},
					{Name: "environment", Operator: "=", Values: []string{"production"}},
				},
				Logic: LogicAND,
			},
			want:    `http_requests_total{namespace=~"prod|staging", team!="test", environment="production"}`,
			wantErr: false,
		},
		{
			name:  "partial existing labels",
			query: `http_requests_total{status="200"}`,
			policy: LabelPolicy{
				Rules: []LabelRule{
					{Name: "namespace", Operator: "=", Values: []string{"prod"}},
					{Name: "team", Operator: "=", Values: []string{"backend"}},
				},
				Logic: LogicAND,
			},
			want:    `http_requests_total{status="200", namespace="prod", team="backend"}`,
			wantErr: false,
		},

		// Edge cases
		{
			name:  "query with __name__ selector",
			query: `{__name__="up"}`,
			policy: LabelPolicy{
				Rules: []LabelRule{
					{Name: "namespace", Operator: "=", Values: []string{"prod"}},
				},
				Logic: LogicAND,
			},
			want:    `{__name__="up", namespace="prod"}`,
			wantErr: false,
		},
		{
			name:  "binary operation",
			query: `up / on(instance) process_cpu_seconds_total`,
			policy: LabelPolicy{
				Rules: []LabelRule{
					{Name: "namespace", Operator: "=", Values: []string{"prod"}},
				},
				Logic: LogicAND,
			},
			want:    `up{namespace="prod"} / on (instance) process_cpu_seconds_total{namespace="prod"}`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enforcer := PromQLEnforcer{}
			got, err := enforcer.Enforce(tt.query, tt.policy)

			if tt.wantErr {
				if err == nil {
					t.Errorf("EnforceMulti() expected error but got nil")
					return
				}
				if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("EnforceMulti() error = %v, want error containing %v", err, tt.errMsg)
				}
				return
			}

			if err != nil {
				t.Errorf("EnforceMulti() unexpected error = %v", err)
				return
			}

			// Parse both got and want to compare semantically
			// This handles differences in label ordering and whitespace
			gotExpr, err := promqlParser.ParseExpr(got)
			if err != nil {
				t.Errorf("EnforceMulti() produced invalid query: %v", err)
				return
			}
			wantExpr, err := promqlParser.ParseExpr(tt.want)
			if err != nil {
				t.Errorf("Test case has invalid expected query: %v", err)
				return
			}

			// Compare by normalizing both to string (parser normalizes formatting)
			if gotExpr.String() != wantExpr.String() {
				t.Errorf("EnforceMulti() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPromQLEnforcer_EnforceMulti_InvalidPolicy(t *testing.T) {
	tests := []struct {
		name   string
		policy LabelPolicy
	}{
		{
			name: "empty rules",
			policy: LabelPolicy{
				Rules: []LabelRule{},
			},
		},
		{
			name: "invalid operator",
			policy: LabelPolicy{
				Rules: []LabelRule{
					{Name: "namespace", Operator: "==", Values: []string{"prod"}},
				},
			},
		},
		{
			name: "empty label name",
			policy: LabelPolicy{
				Rules: []LabelRule{
					{Name: "", Operator: "=", Values: []string{"prod"}},
				},
			},
		},
		{
			name: "no values",
			policy: LabelPolicy{
				Rules: []LabelRule{
					{Name: "namespace", Operator: "=", Values: []string{}},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enforcer := PromQLEnforcer{}
			_, err := enforcer.Enforce("up", tt.policy)
			if err == nil {
				t.Errorf("EnforceMulti() expected validation error but got nil")
			}
		})
	}
}
