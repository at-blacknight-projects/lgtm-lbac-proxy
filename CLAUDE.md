<!-- OPENSPEC:START -->
# OpenSpec Instructions

These instructions are for AI assistants working in this project.

Always open `@/openspec/AGENTS.md` when the request:
- Mentions planning or proposals (words like proposal, spec, change, plan)
- Introduces new capabilities, breaking changes, architecture shifts, or big performance/security work
- Sounds ambiguous and you need the authoritative spec before coding

Use `@/openspec/AGENTS.md` to learn:
- How to create and apply change proposals
- Spec format and conventions
- Project structure and guidelines

Keep this managed block so 'openspec update' can refresh the instructions.

<!-- OPENSPEC:END -->

# LGTM LBAC Proxy

Multi-tenancy Label-Based Access Control authorization proxy for LGTM stack (Loki, Grafana, Tempo, Mimir/Prometheus)

## Quick Start

```bash
# Build and run
go build -o lgtm-lbac-proxy .
go run .

# Test (REQUIRED before commit)
go test -v ./...
go test -v -coverprofile=coverage.out ./...
go test -bench=. -benchmem -run=^$
```

**Performance requirement**: All operations <5ms

## Common Tasks

| Task | Command/Location |
|------|------------------|
| Add new user | Edit `configs/labels.yaml` (extended format) |
| Change tenant label | Edit `thanos/loki/tempo.tenant_label` in `configs/config.yaml` |
| Debug auth issues | Check JWT claims extraction in `auth.go` |
| Add custom label store | Create in `contrib/labelstores/` |
| Migrate old labels | Run `cmd/migrate-labels` tool |
| Tune performance | Edit `proxy` section per upstream in `configs/config.yaml` |

## Architecture

**Request Flow**: `Auth → Label Validation → Query Enforcement → Proxy`

```
┌─────────────┐     ┌──────────────┐     ┌───────────────┐     ┌──────────┐
│ JWT Token   │────▶│ Label Store  │────▶│ Query         │────▶│ Upstream │
│ (auth.go)   │     │ (labelstore) │     │ Enforcer      │     │ (routes) │
└─────────────┘     └──────────────┘     └───────────────┘     └──────────┘
                    Eager parsing at     PromQL/LogQL/TraceQL   Loki/Thanos
                    startup/reload       Inject restrictions    /Tempo
                    Multi-label policy   Cache merged policies
```

**Key Design Principles**:
- **Eager Parsing**: All policies parsed and validated at startup/reload (fail-fast)
- **Zero First-Request Overhead**: Pre-parsed policies eliminate on-demand parsing latency
- **Memory Efficient**: Single storage of parsed policies (~50% memory reduction)
- **Cache Strategy**: Individual policies cached, merged per-request for specific user+groups

**Servers**: `:8080` (proxy) | `:8081` (metrics) | optional mTLS port | optional ingest TLS port (`ingest.port`; with `ingest.only`, only metrics + ingest run)

## File Organization

| Component | Files | Purpose |
|-----------|-------|---------|
| **Core** | `main.go`, `config.go` | App initialization, config with hot-reload |
| **Auth** | `auth.go` | JWT+JWKS validation, extract username/email/groups |
| **Static keys** | `statickeys.go` | Optional hashed long-lived keys: `auth.static_keys` (read, → identity, never admin or cluster-wide) and `ingest.static_keys` (write, → writer id); checked before JWT, separate maps |
| **Labels** | `labelstore.go`, `labelrule.go`, `policyparser.go` | Eager parsing at startup, extended format, rules with operators (=, !=, =~, !~), AND/OR logic, fail-fast validation |
| **Enforcers** | `enforcer_promql.go`, `enforcer_logql.go`, `enforcer_traceql.go` | Parse → validate → inject labels → return modified query |
| **Routing** | `routes.go` | HTTP endpoints, orchestrate auth→validate→enforce→proxy |
| **Ingest** | `ingest.go` | Optional OTLP write gateway: own TLS listener and router, JWT-only, group→writer id, forwards with a writer header; `ingest.only` runs it alone |
| **Tests** | `*_test.go` (76+ tests), `*_bench_test.go` | Unit tests, integration tests, performance benchmarks |
| **Config** | `configs/config.yaml`, `configs/labels.yaml` | Main config, user/group label mappings (extended only) |

## Configuration

### Main Config (`configs/config.yaml`)

```yaml
# Authentication (new in v0.14.0 - recommended)
auth:
  jwks_cert_url: "https://oauth.example.com/.well-known/jwks.json"  # REQUIRED
  auth_header: "Authorization"   # Header name for JWT
  auth_scheme: "Bearer"          # Authentication scheme/prefix (set "" for raw token)
  claims:
    username: "preferred_username"  # JWT claim for username (configurable)
    email: "email"                   # JWT claim for email (configurable)
    groups: "groups"                 # JWT claim for groups (configurable)

# Legacy web config (deprecated - move auth fields to auth section above)
web:
  proxy_port: 8080
  metrics_port: 8081
  # DEPRECATED: jwks_cert_url (use auth.jwks_cert_url)
  # DEPRECATED: oauth_group_name (use auth.claims.groups)

thanos:
  url: "http://thanos:9090"
  tenant_label: "namespace"      # Label to enforce
  proxy:                         # Optional per-upstream tuning
    request_timeout: 60s
    max_idle_conns_per_host: 100

loki:
  url: "http://loki:3100"
  tenant_label: "namespace"
  proxy:
    request_timeout: 120s        # Longer for log queries
    max_idle_conns_per_host: 150

tempo:
  url: "http://tempo:3200"
  tenant_label: "resource.namespace"
  proxy:
    request_timeout: 300s        # Very long for trace searches
    max_idle_conns_per_host: 50

admin:
  bypass: true                   # Enable admin bypass
  group: "admins"                # Admin group name

# Global proxy defaults (optional)
proxy:
  request_timeout: 60s
  max_idle_conns_per_host: 100
  max_idle_conns: 500
  idle_conn_timeout: 90s
```

`auth.auth_scheme` controls how the proxy parses tokens. Configure it with the exact prefix your identity provider emits (for example `Token`, `JWT`, or set it to an empty string to accept raw tokens without a prefix).

### OAuth Provider Configuration

Different OAuth providers use different JWT claim names. Configure them in `auth.claims`:

| Provider | Username Claim | Email Claim | Groups Claim |
|----------|---------------|-------------|--------------|
| **Keycloak** | `preferred_username` | `email` | `groups` |
| **Azure AD** | `unique_name` or `upn` | `email` or `upn` | `roles` |
| **Auth0** | `nickname` or `name` | `email` | `https://domain.com/groups` |
| **Google** | `email` or `sub` | `email` | `hd` (domain) |
| **Okta** | `preferred_username` | `email` | `groups` |

**Examples**: See `configs/examples/` for provider-specific configurations.

### Labels Config (`configs/labels.yaml`)

Extended format only (v0.12.0+). Use `cmd/migrate-labels` to convert old format.

```yaml
# Single-label: namespace only
user1:
  _rules:
    - name: namespace
      operator: "="           # Operators: =, !=, =~, !~
      values: ["prod", "staging"]
  _logic: AND                 # AND (default) or OR

# Multi-label: namespace AND team
user2:
  _rules:
    - name: namespace
      operator: "="
      values: ["prod"]
    - name: team
      operator: "=~"
      values: ["backend.*"]
  _logic: AND

# Admin: cluster-wide access
admin-group:
  _rules:
    - name: '#cluster-wide'
      operator: "="
      values: ["true"]
  _logic: AND
```

**Local dev**: Set `dev.enabled: true` and `web.service_account_token` in config

## Testing

```bash
# Run all tests
go test -v ./...

# Specific test
go test -v -run TestPromQLEnforcer ./...

# Coverage
go test -v -coverprofile=coverage.out ./...
go tool cover -html=coverage.out

# Benchmarks
go test -bench=. -benchmem -run=^$
```

**Test Coverage** (76+ tests):
- `enforcer_*_test.go` - 67 enforcer test cases (PromQL: 28, LogQL: 18, TraceQL: 21)
- `auth_test.go`, `labelrule_test.go`, `policyparser_test.go` - Core logic
- `main_test.go` - 9 integration + proxy tests
- `*_bench_test.go` - Performance benchmarks

**Performance Targets**:
- Parsing: ~1.9 µs/op
- PromQL: ~5-10 µs/op (single), ~15-25 µs/op (multi-label)
- LogQL: ~8-15 µs/op
- TraceQL: ~10-20 µs/op
- Proxy: 0.26 ns/op field access, ~3 ns/op config merge

## Query Enforcement

All enforcers use `Enforce()` method with multi-label policy support.

**Single-label** (namespace only):
```promql
# Policy: namespace=~"prod|staging"
Input:  rate(http_requests_total[5m])
Output: rate(http_requests_total{namespace=~"prod|staging"}[5m])
```

**Multi-label** (namespace AND team):
```promql
# Policy: namespace="prod" AND team=~"backend.*"
Input:  rate(http_requests_total[5m])
Output: rate(http_requests_total{namespace="prod", team=~"backend.*"}[5m])
```

```logql
# Policy: namespace="prod" AND environment!="test"
Input:  {job="app"}
Output: {job="app", namespace="prod", environment!="test"}
```

```traceql
# Policy: resource.namespace="prod" AND resource.team="backend"
Input:  { span.http.status_code = 500 }
Output: { resource.namespace="prod" && resource.team="backend" && span.http.status_code = 500 }
```

**Empty queries**: Construct minimal query: `{namespace=~"ns1|ns2"}` or `{ resource.namespace="ns1" }`

**Unauthorized labels**: Return HTTP 403

## Proxy Performance

**Design**: Pre-created `httputil.ReverseProxy` per upstream at startup (zero runtime overhead)

**Key Metrics**:
- Throughput: 1000-2000 req/s
- Connection reuse: >95% under steady load
- Proxy field access: 0.26 ns/op (direct struct field)
- Initialization: ~400 µs one-time startup

**Connection Pooling** (per upstream):
- MaxIdleConnsPerHost: 100 (default)
- MaxIdleConns: 500 total across upstreams
- IdleConnTimeout: 90s
- HTTP/2: Enabled (multiplexing + compression)

**Configuration Precedence**: `upstream-specific > global > built-in defaults`

## Code Patterns

**Error Handling**: Handler errors → HTTP 403 + log. Critical errors (config/JWKS) → `log.Fatal()`

**TLS**:
- System CAs: `/etc/ssl/ca/ca-certificates.crt`
- Additional: `web.trusted_root_ca_path`
- mTLS: `thanos.cert/key`, `loki.cert/key`
- Dev only: `web.tls_verify_skip: true` (insecure)

**Actor Header**: `loki.actor_header` or `thanos.actor_header` → inject base64 username for fair usage tracking

**TraceQL Strategy**: Parse (validate) → string manipulation (inject) → re-parse (verify). Required due to lack of AST constructors.

## Dependencies

| Library | Purpose |
|---------|---------|
| `MicahParks/keyfunc/v3` | JWKS key management with auto-refresh |
| `prometheus-community/prom-label-proxy` | PromQL label injection |
| `observatorium/api` | LogQL parsing |
| `grafana/tempo/pkg/traceql` | TraceQL parsing and validation |
| `gorilla/mux` | HTTP routing |
| `spf13/viper` | Config management with hot-reload |
| `rs/zerolog` | Structured logging |
| `golang-jwt/jwt/v5` | JWT parsing and validation |

## API Routes

| Service | Endpoints |
|---------|-----------|
| **Loki** | `/loki/api/v1/query`, `/loki/api/v1/query_range`, `/loki/api/v1/labels`, etc. |
| **Thanos/Prometheus** | `/api/v1/query`, `/api/v1/query_range`, `/api/v1/series`, etc. |
| **Tempo** | `/api/echo`, `/api/search`, `/api/v2/search`, `/api/traces/{traceID}`, `/api/metrics/*` |
| **Ingest** (separate listener, `ingest.port`) | `POST /v1/metrics`, `POST /v1/logs`, `POST /v1/traces` (per configured signal), `GET /healthz` |

All read routes: `auth → validate labels → enforce query → proxy to upstream`

Ingest routes: `JWT (getToken, never getIdentity) → resolve writer from groups → cap body → overwrite writer header, drop credentials → stream body unchanged to the signal's upstream`. The write router (`a.w`) and read router (`a.e`) are separate, so neither listener can serve the other's routes. The upstream must be reachable only through the gateway, since it trusts the writer header.
