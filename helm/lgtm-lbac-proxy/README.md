# LGTM LBAC Proxy Helm Chart

Helm chart for deploying LGTM LBAC Proxy on Kubernetes.

## Overview

This Helm chart deploys the LGTM LBAC Proxy, providing Label-Based Access Control for the complete LGTM observability stack (Loki, Grafana, Tempo, Mimir/Prometheus).

**Chart Version**: 1.12.0
**App Version**: 0.15.0
**Kubernetes**: >= 1.19

## Features

- ✅ **Complete LGTM Stack Support**: Metrics (Prometheus/Thanos/Mimir), Logs (Loki), Traces (Tempo)
- ✅ **Production Ready**: Resource limits, security contexts, health probes, HPA support
- ✅ **Security Hardened**: Pod security standards, non-root execution, dropped capabilities
- ✅ **Vanilla Kubernetes**: No platform-specific dependencies (OpenShift, etc.)
- ✅ **ConfigMap Labels**: Simple, Kubernetes-native label storage
- ✅ **mTLS Support**: Optional mutual TLS for upstream connections
- ✅ **Monitoring**: ServiceMonitor for Prometheus metrics collection

## Quick Start

### Prerequisites

- Kubernetes cluster (>= 1.19)
- Helm 3.x
- Valid OAuth/OIDC provider with JWKS endpoint

### Installation

```bash
# Add the chart repository
helm repo add lgtm-lbac-proxy https://at-blacknight-projects.github.io/helm-charts/
helm repo update

# Install the chart. Current releases are pre-releases (0.2.0-alpha.N), which
# helm skips unless you pass --devel or an explicit --version.
helm install lgtm-lbac-proxy lgtm-lbac-proxy/lgtm-lbac-proxy --devel \
  --namespace observability \
  --create-namespace \
  --set proxy.web.jwksCertUrl=https://your-oauth.com/certs \
  --set proxy.thanos.url=https://thanos-querier.monitoring.svc:9091 \
  --set proxy.loki.url=https://loki-query-frontend.logging.svc:3100 \
  --set proxy.tempo.url=https://tempo-query-frontend.tracing.svc:3200
```

### Local Installation

```bash
# Install from local chart directory
helm install lgtm-lbac-proxy ./helm/lgtm-lbac-proxy \
  --namespace observability \
  --create-namespace \
  -f custom-values.yaml
```

## Configuration

### Required Configuration

```yaml
proxy:
  web:
    jwksCertUrl: "https://your-oauth-provider.com/certs"  # Required: OAuth JWKS endpoint

  thanos:
    url: "https://thanos-querier.monitoring.svc:9091"     # Required: Prometheus/Thanos endpoint

  loki:
    url: "https://loki-query-frontend.logging.svc:3100"  # Required: Loki endpoint

  tempo:
    url: "https://tempo-query-frontend.tracing.svc:3200" # Required: Tempo endpoint
```

### Complete Configuration Options

#### Proxy Configuration

```yaml
proxy:
  log:
    level: 1  # 0=debug, 1=info, 2=warn, 3=error, -1=trace

  admin:
    bypass: false          # Enable admin bypass for cluster-wide access
    group: admin-group     # Admin group name

  auth:
    jwksCertUrl: https://oauth.example.com/certs
    authHeader: "Authorization"
    authScheme: "Bearer"   # Set to "" when upstream sends raw tokens
    claims:
      username: "preferred_username"
      email: "email"
      groups: "groups"

  thanos:
    url: https://thanos-querier.monitoring.svc:9091
    tenantLabel: namespace
    actorHeader: ""        # Optional: Actor header for fair usage tracking
    headers: {}            # Optional: Additional headers

  loki:
    url: https://loki-query-frontend.logging.svc:3100
    tenantLabel: kubernetes_namespace_name
    actorHeader: X-Loki-Actor-Path
    headers:
      X-Scope-OrgID: application

  tempo:
    url: https://tempo-query-frontend.tracing.svc:3200
    tenantLabel: resource.namespace
    actorHeader: ""
    headers: {}

  alert:
    enabled: false         # Enable alerting support
    tokenHeader: X-Alert-Token
    certUrl: https://your-oauth.com/certs
    cert: ""               # Optional: Local JWKS cert

  web:
    oauthGroupName: groups     # JWT claim for groups
    jwksCertUrl: https://your-oauth.com/certs
    tlsVerifySkip: false       # Skip TLS verification (insecure!)

  podSecurityContext:
    runAsNonRoot: true
    runAsUser: 65534
    fsGroup: 65534
    seccompProfile:
      type: RuntimeDefault

  securityContext:
    allowPrivilegeEscalation: false
    readOnlyRootFilesystem: false
    capabilities:
      drop: [ALL]

  topologySpreadConstraints: []
```

#### Scaling Configuration

```yaml
replicas: 1

autoscaling:
  enabled: false
  minReplicas: 2
  maxReplicas: 10
  targetCPUUtilizationPercentage: 80
  targetMemoryUtilizationPercentage: 80
  behavior: {}
```

#### Resource Configuration

```yaml
resources:
  requests:
    cpu: 50m
    memory: 64Mi
  limits:
    cpu: 200m
    memory: 128Mi
```

#### TLS Configuration

```yaml
tls:
  loki:
    enabled: true
    secretName: loki-query-frontend-http
    cert: tls.crt
    key: tls.key

  thanos:
    enabled: false
    secretName: thanos-querier-tls
    cert: tls.crt
    key: tls.key

  tempo:
    enabled: false
    secretName: tempo-query-frontend-tls
    cert: tls.crt
    key: tls.key
```

#### Probe Configuration

```yaml
probes:
  readinessProbe:
    enabled: true
    initialDelaySeconds: 1
    periodSeconds: 5
    timeoutSeconds: 10

  livenessProbe:
    enabled: true
    initialDelaySeconds: 1
    periodSeconds: 10
    timeoutSeconds: 10
```

### Label Configuration

Create a ConfigMap with user/group label mappings:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: lgtm-lbac-proxy-labels
  namespace: observability
data:
  labels.yaml: |
    # User-specific labels
    alice@example.com:
      prod: true
      staging: true

    bob@example.com:
      dev: true

    # Group-based labels
    engineering-team:
      prod: true
      staging: true
      dev: true

    # Admin access (cluster-wide)
    admin-group:
      '#cluster-wide': true
```

Apply the ConfigMap:

```bash
kubectl apply -f labels-configmap.yaml
```

## Deployment Examples

### Minimal Production Setup

```yaml
# minimal-values.yaml
proxy:
  web:
    jwksCertUrl: https://oauth.example.com/certs

  thanos:
    url: https://thanos-querier.monitoring.svc:9091

  loki:
    url: https://loki-query-frontend.logging.svc:3100

  tempo:
    url: https://tempo-query-frontend.tracing.svc:3200

replicas: 2

resources:
  requests:
    cpu: 100m
    memory: 128Mi
  limits:
    cpu: 500m
    memory: 256Mi
```

```bash
helm install lgtm-lbac-proxy ./helm/lgtm-lbac-proxy \
  -f minimal-values.yaml \
  --namespace observability
```

### High Availability Setup

```yaml
# ha-values.yaml
replicas: 3

autoscaling:
  enabled: true
  minReplicas: 3
  maxReplicas: 10
  targetCPUUtilizationPercentage: 70
  targetMemoryUtilizationPercentage: 80

proxy:
  topologySpreadConstraints:
    - maxSkew: 1
      topologyKey: topology.kubernetes.io/zone
      whenUnsatisfiable: DoNotSchedule
    - maxSkew: 1
      topologyKey: kubernetes.io/hostname
      whenUnsatisfiable: ScheduleAnyway

resources:
  requests:
    cpu: 100m
    memory: 128Mi
  limits:
    cpu: 500m
    memory: 256Mi

tls:
  loki:
    enabled: true
  thanos:
    enabled: true
  tempo:
    enabled: true
```

### Development Setup

```yaml
# dev-values.yaml
replicas: 1

proxy:
  log:
    level: 0  # Debug mode

  web:
    tlsVerifySkip: true  # Development only!

  admin:
    bypass: true
    group: developers

resources:
  requests:
    cpu: 10m
    memory: 32Mi
  limits:
    cpu: 100m
    memory: 64Mi
```

## Grafana Integration

Configure Grafana datasources to use the proxy:

### Prometheus/Thanos Datasource

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: grafana-datasource-prometheus
data:
  prometheus.yaml: |
    apiVersion: 1
    datasources:
      - name: Prometheus (via LGTM Proxy)
        type: prometheus
        url: http://lgtm-lbac-proxy:8080
        access: proxy
        isDefault: true
        jsonData:
          httpMethod: POST
          oauthPassThru: true
```

### Loki Datasource

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: grafana-datasource-loki
data:
  loki.yaml: |
    apiVersion: 1
    datasources:
      - name: Loki (via LGTM Proxy)
        type: loki
        url: http://lgtm-lbac-proxy:8080/loki/api/v1
        access: proxy
        jsonData:
          httpMethod: POST
          oauthPassThru: true
```

### Tempo Datasource

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: grafana-datasource-tempo
data:
  tempo.yaml: |
    apiVersion: 1
    datasources:
      - name: Tempo (via LGTM Proxy)
        type: tempo
        url: http://lgtm-lbac-proxy:8080/tempo/api
        access: proxy
        jsonData:
          httpMethod: GET
          oauthPassThru: true
```

## Monitoring

The chart includes a ServiceMonitor for Prometheus Operator:

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: lgtm-lbac-proxy
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: lgtm-lbac-proxy
  endpoints:
    - port: lgtm-lbac-proxy-metrics
      interval: 15s
      path: /metrics
```

## Upgrading

### From 1.7.0 and earlier to 1.8.0+

Version 1.8.0 includes significant improvements and breaking changes from the original chart.

```bash
# Backup current configuration
helm get values lgtm-lbac-proxy > backup-values.yaml

# Upgrade to latest version
helm upgrade lgtm-lbac-proxy ./helm/lgtm-lbac-proxy \
  -f backup-values.yaml \
  --namespace observability
```

See [CHANGELOG.md](CHANGELOG.md) for detailed changes.

## Troubleshooting

### Check Proxy Logs

```bash
kubectl logs -n observability -l app.kubernetes.io/name=lgtm-lbac-proxy -f
```

### Verify Configuration

```bash
# Check ConfigMaps
kubectl get configmap -n observability lgtm-lbac-proxy-config -o yaml
kubectl get configmap -n observability lgtm-lbac-proxy-labels -o yaml

# Check Service
kubectl get svc -n observability lgtm-lbac-proxy

# Check Endpoints
kubectl get endpoints -n observability lgtm-lbac-proxy
```

### Test Authentication

```bash
# Get a valid JWT token from your OAuth provider
TOKEN="your-jwt-token"

# Test Prometheus query
curl -H "Authorization: Bearer $TOKEN" \
  http://lgtm-lbac-proxy:8080/api/v1/query?query=up

# Test Loki query
curl -H "Authorization: Bearer $TOKEN" \
  http://lgtm-lbac-proxy:8080/loki/api/v1/query?query={app="test"}

# Test Tempo query
curl -H "Authorization: Bearer $TOKEN" \
  http://lgtm-lbac-proxy:8080/tempo/api/search?q={resource.namespace="prod"}
```

### Common Issues

**403 Forbidden - No Labels Found**
- Ensure labels ConfigMap exists and contains mappings for your users/groups
- Check JWT token contains correct `preferred_username` or group claims
- Verify `oauth_group_name` matches your JWT group claim

**503 Service Unavailable**
- Check upstream URLs are correct and reachable
- Verify TLS configuration if using mTLS
- Check network policies allow egress to upstream services

**Certificate Validation Errors**
- Ensure TLS secrets exist and contain valid certificates
- Verify CA certificates are properly configured
- Check `tlsVerifySkip` setting (only for development)

## Uninstallation

```bash
# Uninstall the release
helm uninstall lgtm-lbac-proxy --namespace observability

# Optionally delete the namespace
kubectl delete namespace observability
```

## Support

- **Documentation**: [GitHub Repository](https://github.com/at-blacknight-projects/lgtm-lbac-proxy)
- **Issues**: [GitHub Issues](https://github.com/at-blacknight-projects/lgtm-lbac-proxy/issues)

## License

GNU Affero General Public License v3.0 - see [LICENSE](../../LICENSE) for details.
