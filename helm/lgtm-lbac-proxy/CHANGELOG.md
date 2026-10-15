# Helm Chart Changelog

All notable changes to the LGTM LBAC Proxy Helm chart will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0-alpha.11] - 2026-10-15

### Added

- **`auth.staticKeys`** and **`ingest.staticKeys`** (read and write static keys; hashes
  only), rendered only when set. Without them the rendered output is unchanged.

## [0.2.0-alpha.10] - 2026-10-14

### Added

- **`ingest` values** for the OTLP write gateway, off by default:
  - **Base:** `ingest.enabled` renders the ingest config, container and ClusterIP ports,
    and mounts `ingest.serverSecretName` at `/etc/secrets/ingest/`.
  - **`ingest.serverCertificate`** optionally creates a cert-manager Certificate for it.
  - **`ingest.loadBalancer`** adds a LoadBalancer Service exposing only the ingest port,
    with optional `loadBalancerIP`, `externalTrafficPolicy` and annotations.
  - **`ingest.only`** makes the release a write gateway alone. It drops the `http` and
    `mtls` ports, the labels ConfigMap and mount, the client-cert mounts and Certificate,
    the mTLS LoadBalancer, and the `cluster-monitoring-view` binding. Install it as a
    second release with its own `nameOverride`.

### Changed

- With `ingest` disabled, the rendered output is unchanged.

## [1.12.5] - 2025-11-04

### Changed

- **Service Type Configuration**: Service type is now configurable via `service.type` in `values.yaml`
  - Enables deployment as LoadBalancer, NodePort, or other Kubernetes service types
  - Previously hardcoded to ClusterIP only
  - Default remains ClusterIP for backward compatibility

- **AppVersion**: Updated to 0.15.6 to match proxy release with Helm chart enhancements

## [1.12.4] - 2025-11-04

### Added

- **Service Enable/Disable Parameters**: New `enabled` flags for Thanos, Loki, and Tempo services
  - `thanos.enabled: true/false` - Control Thanos proxy (default: true)
  - `loki.enabled: true/false` - Control Loki proxy (default: true)
  - `tempo.enabled: true/false` - Control Tempo proxy (default: true)
  - When disabled, URLs are set to empty string to prevent routing to that service

### Changed

- **ConfigMap Template**: Updated to conditionally render service URLs based on `enabled` flag
  - Thanos URL: `{{ if .Values.thanos.enabled }}{{ .Values.thanos.url }}{{ else }}""{{ end }}`
  - Loki URL: `{{ if .Values.loki.enabled }}{{ .Values.loki.url }}{{ else }}""{{ end }}`
  - Tempo URL: `{{ if .Values.tempo.enabled }}{{ .Values.tempo.url }}{{ else }}""{{ end }}`

### Usage

Disable individual services:
```bash
helm install lgtm-lbac-proxy ./helm/lgtm-lbac-proxy \
  --set thanos.enabled=false \
  --set loki.enabled=false
```

Or disable all services except one:
```bash
helm install lgtm-lbac-proxy ./helm/lgtm-lbac-proxy \
  --set thanos.enabled=true \
  --set loki.enabled=false \
  --set tempo.enabled=false
```

## [1.12.3] - 2025-11-03

### Changed

- **AppVersion**: Updated to 0.15.5 to match proxy release with eager parsing optimization
- **Chart Version**: Bumped to 1.12.3 (patch release)
- **Performance**: Zero first-request overhead with pre-parsed label policies at startup

## [1.12.2] - 2025-11-03

### Removed

- **Deprecated `log_tokens` Configuration**: Removed from Helm chart templates and values
  - Simplified ConfigMap by removing `log.log_tokens: false`
  - Use standard log level instead: `level: -1` for trace/debug logging

### Changed

- **AppVersion**: Updated to 0.15.2 to match proxy release with simplified logging
- **Chart Version**: Bumped to 1.12.2 (patch release)
- **Log Level Comment**: Enhanced Helm values comment to clarify trace level behavior
  - Added explanation: `level: -1 - trace (logs all headers and body, exposes sensitive data)`
- **Values Structure**: Restructured configuration paths (flattened hierarchy from proxy.* to root-level keys)
  - Removed deprecated `tenantLabel` fields
  - Added labels section for LBAC policy configuration

### Migration

**Log Configuration Update**:
```yaml
# Old (deprecated - still works but removed from Helm)
log:
  level: 0
  log_tokens: true

# New (use trace level instead)
log:
  level: -1  # Trace level for debugging
```

## [1.12.1] - 2025-11-03

### Changed

- **AppVersion**: Updated to 0.15.1 to match proxy release
- **Chart Version**: Bumped to 1.12.1 (patch release)
- **Removed**: `tenantLabel` fields from Thanos, Loki, and Tempo configuration
- **Template Refactoring**: Updated reference paths in configmaps and deployment templates

## [1.12.0] - 2025-11-03

### Added

- 🔐 **Configurable Authentication Scheme**: New `proxy.auth.authScheme` value passed to `auth.auth_scheme`
  - Supports alternative prefixes such as `Token`, `JWT`, or empty string for raw tokens
  - Included in generated ConfigMap and documented in chart README/values

### Changed

- **AppVersion**: Updated to 0.15.0 to match proxy release with configurable auth scheme
- **Chart Version**: Bumped to 1.12.0
- **Values/README**: Added documentation and defaults for `authScheme`, keeping comments aligned with examples

## [1.11.0] - 2025-11-02

### Added

- ✨ **Configurable JWT Claims**: New `proxy.auth` section for OAuth provider flexibility
  - `proxy.auth.claims.username`: Configurable JWT claim for username (default: `preferred_username`)
  - `proxy.auth.claims.email`: Configurable JWT claim for email (default: `email`)
  - `proxy.auth.claims.groups`: Configurable JWT claim for groups (default: `groups`)
  - `proxy.auth.jwksCertUrl`: JWKS certificate URL (moved from `proxy.web`)
  - `proxy.auth.authHeader`: Authorization header name (default: `Authorization`)
  - Provider examples in values comments: Keycloak, Azure AD, Auth0, Google

- 🔄 **Automatic Configuration Migration**: Backward compatible template logic
  - Automatically maps legacy `proxy.web.jwksCertUrl` to `proxy.auth.jwksCertUrl`
  - Automatically maps legacy `proxy.web.oauthGroupName` to `proxy.auth.claims.groups`
  - Falls back to legacy fields if `proxy.auth` section is not present
  - Zero breaking changes for existing deployments

### Changed

- **AppVersion**: Updated to 0.14.0 (from 0.10.0)
- **Chart Version**: Bumped to 1.11.0 (from 1.10.0)
- **ConfigMap Template**: Enhanced to support both new `auth` and legacy `web` configuration formats

### Deprecated

- `proxy.web.jwksCertUrl`: Use `proxy.auth.jwksCertUrl` instead
- `proxy.web.oauthGroupName`: Use `proxy.auth.claims.groups` instead

### Migration

**Backward Compatibility**: Existing Helm values continue to work without any changes. The chart automatically generates the correct configuration format.

**Recommended Values Migration**:
```yaml
# Old format (still supported, deprecated)
proxy:
  web:
    jwksCertUrl: "https://oauth.example.com/certs"
    oauthGroupName: "groups"

# New format (recommended)
proxy:
  auth:
    jwksCertUrl: "https://oauth.example.com/certs"
    authHeader: "Authorization"
    claims:
      username: "preferred_username"  # Keycloak, Okta
      # username: "unique_name"       # Azure AD
      # username: "nickname"          # Auth0
      email: "email"
      groups: "groups"
```

## [1.10.0] - 2025-11-02

### Added

- ✨ **Multi-Label Enforcement Support**: Chart now supports flexible multi-label enforcement
  - Updated `appVersion` to 0.10.0
  - Chart description updated to reflect multi-label enforcement capability
  - Full backward compatibility with existing simple format labels

- 🔄 **Migration Job Template**: New Kubernetes Job for automated label format migration
  - Template: `templates/migration-job.yaml`
  - Configurable via `migration` section in values.yaml
  - Supports dry-run mode for safe preview before migration
  - Automatic label format conversion from simple to extended format
  - Configuration options:
    ```yaml
    migration:
      enabled: false          # Enable migration job
      dryRun: true           # Preview only (no actual changes)
      defaultLabel: namespace # Default label name for conversion
      image:
        repository: ghcr.io/binhnguyenduc/lgtm-lbac-proxy
        tag: "0.10.0"
        pullPolicy: IfNotPresent
      resources:
        limits:
          cpu: 100m
          memory: 128Mi
        requests:
          cpu: 50m
          memory: 64Mi
    ```

- 📚 **Comprehensive Documentation**: New upgrade guide and examples
  - Added `UPGRADE.md` with detailed migration instructions
  - Three migration options documented: no migration, manual, automated
  - Configuration examples for simple, extended, and mixed formats
  - Troubleshooting guide for common migration issues
  - Performance impact analysis
  - Rollback procedures

### Changed

- 📦 **App Version**: Updated to 0.10.0 (from 0.9.1)
  - Includes flexible multi-label enforcement system
  - Includes extended label format support with backward compatibility
  - Includes performance optimizations (<15µs overhead for multi-label)
  - See [main CHANGELOG](../../CHANGELOG.md#unreleased---v0100) for full application changes

- 📝 **values.yaml**: Added migration configuration section
  - New `migration` block for controlling migration job
  - Migration job disabled by default (opt-in)
  - Examples added for extended label format configuration

### Features Enabled by 0.10.0

**Extended Label Format**:
Users can now define complex multi-label policies in their labels ConfigMap:

```yaml
# labels.yaml - Extended format
user1:
  _rules:
    - name: namespace
      operator: "="
      values: ["prod", "staging"]
    - name: team
      operator: "=~"
      values: ["backend.*"]
  _logic: AND

# Simple format still works (backward compatible)
user2:
  namespace: prod

# Mixed format supported
user3:
  namespace: dev
  _rules:
    - name: environment
      operator: "!="
      values: ["production"]
```

**Supported Operators**:
- `=` - Equals
- `!=` - Not equals
- `=~` - Regex match
- `!~` - Regex not match

**Logic Modes**:
- `AND` - All rules must match (default)
- `OR` - Any rule can match

### Migration

**No Action Required**:
- Existing deployments continue to work without changes
- Simple format labels are fully supported
- No configuration updates needed

**To Adopt Multi-Label Enforcement**:

**Option 1: No Migration** (Recommended for simple use cases)
```bash
# Just upgrade - existing labels work as-is
helm upgrade lgtm-lbac-proxy ./helm/lgtm-lbac-proxy \
  --namespace monitoring
```

**Option 2: Manual Migration**
Edit your labels ConfigMap to use extended format for specific users.

**Option 3: Automated Migration**
```bash
# Step 1: Preview migration (dry-run)
helm upgrade lgtm-lbac-proxy ./helm/lgtm-lbac-proxy \
  --set migration.enabled=true \
  --set migration.dryRun=true \
  --set migration.defaultLabel=namespace \
  --namespace monitoring

# Check migration job logs
kubectl logs -n monitoring job/lgtm-lbac-proxy-migrate-labels

# Step 2: Apply migration
helm upgrade lgtm-lbac-proxy ./helm/lgtm-lbac-proxy \
  --set migration.enabled=true \
  --set migration.dryRun=false \
  --set migration.defaultLabel=namespace \
  --namespace monitoring

# Step 3: Disable migration job
helm upgrade lgtm-lbac-proxy ./helm/lgtm-lbac-proxy \
  --set migration.enabled=false \
  --namespace monitoring
```

### Performance

Multi-label enforcement adds minimal overhead:
- Policy parsing: ~1.9 µs per request
- Multi-label enforcement: ~15-25 µs per query
- Total overhead: <0.03ms (well under performance requirements)

### Benefits

1. **Fine-Grained Access Control**: Combine multiple labels for precise policies
2. **Flexibility**: Different users can have different label types (namespace, team, environment)
3. **Advanced Matching**: Support regex patterns and negative conditions
4. **Zero Risk Migration**: Full backward compatibility with existing deployments
5. **Future-Proof**: Foundation for more complex authorization rules

### Links

- [Application CHANGELOG](../../CHANGELOG.md#unreleased---v0100)
- [Upgrade Guide](./UPGRADE.md)
- [Migration Tool Documentation](../../cmd/migrate-labels/README.md)

---

## [1.9.0] - 2025-11-02

### Added
- ✨ **Label Store Configuration**: Added user-configurable label store settings
  - New `proxy.labelStore.configPaths` configuration in values.yaml
  - ConfigMap template now includes `labelstore.config_paths` section
  - Allows users to customize paths where labels.yaml files are searched
  - Default paths: `["/etc/config/labels/", "./configs"]`
  - Example configuration:
    ```yaml
    proxy:
      labelStore:
        configPaths:
          - /etc/config/labels/
          - ./configs
    ```

### Changed
- 📦 **App Version**: Updated to 0.9.1 (from 0.7.0)
  - Includes architecture refactoring (FileLabelStore rename, interface cleanup)
  - Includes configuration system improvements
  - See [main CHANGELOG](../../CHANGELOG.md) for full application changes

### Removed
- 🗑️ **Obsolete Configuration**: Removed `labelStoreKind` configuration
  - Field was already obsolete since v0.9.0 (file-based label store only)
  - Removed from values.yaml (was `proxy.web.labelStoreKind`)
  - Removed from configmaps.yaml template (was `web.label_store_kind`)
  - Removed from README documentation
  - No impact: configuration was unused and had no effect

### Fixed
- 📚 **Documentation**: Clarified label store configuration in README
  - Added `jwksCertUrl` to web configuration example
  - Removed references to removed `labelStoreKind` field
  - Improved clarity around file-based label storage

### Migration Notes

**No Breaking Changes**: This release maintains full backward compatibility.

**Configuration Cleanup**:
- If your `values.yaml` contains `proxy.web.labelStoreKind: configmap`, you can safely remove it
- The field is ignored and has no effect since v0.9.0

**Label Store Paths**:
- Default behavior unchanged: searches `/etc/config/labels/` and `./configs`
- New: Can now customize paths via `proxy.labelStore.configPaths` if needed
- Example use case: Custom ConfigMap mount locations, additional search paths

**Recommended Actions**:
```bash
# 1. Review your values.yaml for obsolete configuration
helm get values lgtm-lbac-proxy > current-values.yaml

# 2. Remove obsolete labelStoreKind if present (optional cleanup)
# Edit current-values.yaml and remove:
#   proxy:
#     web:
#       labelStoreKind: configmap  # Remove this line

# 3. Upgrade to v1.9.0
helm upgrade lgtm-lbac-proxy ./helm/lgtm-lbac-proxy \
  -f current-values.yaml \
  --namespace observability
```

---

## [1.8.0] - 2025-01-01

### Added
- ✨ **Tempo Support**: Full Grafana Tempo integration with TraceQL enforcement
  - Added `proxy.tempo` configuration section
  - Added `tls.tempo` for mTLS support
  - Added Tempo volume mounts and secrets handling
  - Added Tempo configuration to ConfigMap generation
- ✨ **Horizontal Pod Autoscaler**: Added HPA template for auto-scaling
  - Configurable via `autoscaling.enabled`
  - Supports CPU and memory-based scaling
  - Min/max replicas configuration
  - Custom behavior configuration support
- 🔒 **Security Hardening**: Comprehensive pod security improvements
  - Pod security context with non-root user (65534)
  - Container security context with dropped capabilities
  - seccomp profile (RuntimeDefault)
  - `allowPrivilegeEscalation: false`
  - Applied to both proxy and collector containers

### Changed
- ⚡ **Resource Management**: Improved resource requests and limits
  - Proxy: Increased requests (50m CPU, 64Mi memory) and added limits (200m CPU, 128Mi memory)
  - Collector: Added CPU limit (50m)
  - Resources now always applied (not conditional on probe configuration)
- 📈 **Revision History**: Increased `revisionHistoryLimit` from 1 to 3 for easier rollbacks
- 🏷️ **Naming Standardization**: Complete naming consistency
  - Changed all `gp-multena` references to `lgtm-lbac-proxy`
  - Container name: `multena-proxy` → `proxy`
  - Volume names simplified: `multena-config` → `config`, `multena-labels` → `labels`
  - TLS volume names: `multena-loki-tls-secret` → `loki-tls-secret`
- 🌐 **Default URLs**: Updated to vanilla Kubernetes conventions
  - Thanos: `openshift-monitoring` → `monitoring` namespace
  - Loki: `openshift-logging` → `logging` namespace
  - Tempo: Added `tracing` namespace default

### Removed
- 🗑️ **OpenShift Support**: Removed OpenShift-specific features
  - Removed `openshift` flag from values.yaml
  - Removed OpenShift service CA volume mounts
  - Removed OpenShift-specific ConfigMap dependencies
  - Chart now targets vanilla Kubernetes only
- 🗑️ **RBAC Collector**: Removed automatic RBAC collection
  - Removed `collector` configuration section
  - Removed `templates/rbac-collector/` directory
  - Removed collector deployment, service, and RBAC resources
  - Users must manually create labels ConfigMap
- 🗑️ **MySQL Label Store**: Removed MySQL database support
  - Removed `proxy.db` configuration section
  - Removed `templates/external-secrets.yaml`
  - Removed MySQL volume mounts and secrets
  - Removed DB-related helper functions
  - Chart now uses ConfigMap-only for label storage
- 🗑️ **Grafana Operator Datasources**: Removed GrafanaDatasource CRD support
  - Removed `GrafanaOperatorDatasources` configuration
  - Removed `templates/system-datasources.yaml`
  - Removed automatic datasource provisioning
- 🗑️ **Kyverno TLS Copy**: Removed Kyverno-based secret copying
  - Removed `tls.copy` configuration section
  - Removed `templates/tls-copy.yaml`
  - Users must manually create TLS secrets in namespace

### Fixed
- 🐛 **Resource Definition Bug**: Fixed resources block placement
  - Resources were incorrectly inside readiness probe conditional
  - Now properly placed at container level
  - Resources always applied regardless of probe configuration

### Infrastructure
- 📦 **Simplified Chart**: Reduced template count
  - Before: 13 templates (including subdirectories)
  - After: 7 core templates
  - Removed external dependencies (Kyverno, External Secrets Operator, Grafana Operator)
- 🎯 **Focused Scope**: Chart now focused on core proxy functionality
  - No platform-specific features
  - No external operator dependencies
  - Pure Kubernetes compatibility

### Migration Notes

**Breaking Changes:**
- **Label Store**: MySQL label store no longer supported. Migrate to ConfigMap-based labels.
- **RBAC Collector**: Automatic label collection removed. Create labels ConfigMap manually.
- **OpenShift**: OpenShift-specific features removed. Use vanilla Kubernetes configuration.
- **External Operators**: Kyverno, External Secrets, and Grafana Operator support removed.

**Configuration Changes:**
```yaml
# Removed configurations:
openshift: true                    # No longer supported
collector.enabled: true            # Removed
proxy.db.*                         # Removed (MySQL)
GrafanaOperatorDatasources.*       # Removed
tls.copy.*                         # Removed (Kyverno)

# New configurations:
proxy.tempo.*                      # Added (Tempo support)
tls.tempo.*                        # Added (Tempo TLS)
autoscaling.*                      # Added (HPA support)
```

**Volume Name Changes:**
```yaml
# Old → New
multena-config           → config
multena-labels           → labels
multena-loki-tls-secret  → loki-tls-secret
multena-thanos-tls-secret → thanos-tls-secret
# New
tempo-tls-secret         → (new for Tempo)
```

**Migration Steps:**
1. Backup current Helm values: `helm get values lgtm-lbac-proxy > backup.yaml`
2. Create labels ConfigMap manually (no longer auto-created by collector)
3. Remove unsupported configuration keys from values
4. Update volume references if using custom configurations
5. Apply upgrade: `helm upgrade lgtm-lbac-proxy ./helm/lgtm-lbac-proxy -f new-values.yaml`

### Acknowledgments

This release represents a major refactoring focused on:
- **Production readiness**: Better security, resources, and scaling
- **Simplicity**: Removed external dependencies and platform-specific features
- **LGTM completeness**: Added Tempo support for full observability stack coverage
- **Maintainability**: Standardized naming and reduced complexity

---

## [1.7.0 and earlier] - Historical

For changes in version 1.7.0 and earlier, see the [multena-proxy](https://github.com/gepaplexx/multena-proxy) upstream project history.

This chart is based on the original multena-proxy Helm chart (v1.7.0) with significant modifications for LGTM stack focus.

**Note**: Version 1.7.0 was the last release of the original multena-proxy chart. This project continues from that baseline as version 1.8.0 with LGTM-focused enhancements.

[1.9.0]: https://github.com/binhnguyenduc/lgtm-lbac-proxy/releases/tag/helm-chart-1.9.0
[1.8.0]: https://github.com/binhnguyenduc/lgtm-lbac-proxy/releases/tag/v1.8.0
