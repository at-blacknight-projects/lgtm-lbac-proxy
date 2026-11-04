# Upgrade Guide

## 🚨 Upgrading to v0.12.0 (Breaking Change)

**IMPORTANT**: Version 0.12.0 removes support for the simple label format. You **MUST** migrate to the extended format before upgrading.

### Prerequisites

Before upgrading to v0.12.0:

1. **Backup your labels ConfigMap**:
   ```bash
   kubectl get configmap lgtm-lbac-proxy-labels -n monitoring -o yaml > labels-backup.yaml
   ```

2. **Check current format** - If your `labels.yaml` looks like this, you MUST migrate:
   ```yaml
   # ❌ Simple format (NO LONGER SUPPORTED in v0.12.0)
   user1:
     namespace1: true
     namespace2: true
   ```

3. **Target format** - All labels must use extended format:
   ```yaml
   # ✅ Extended format (REQUIRED in v0.12.0+)
   user1:
     _rules:
       - name: namespace
         operator: "="
         values: ["namespace1", "namespace2"]
     _logic: AND
   ```

### Migration Steps

#### Step 1: Install Migration Tool

```bash
# Go 1.26+
go install github.com/at-blacknight-projects/lgtm-lbac-proxy/cmd/migrate-labels@latest
```

#### Step 2: Export Current Labels

```bash
# Export from ConfigMap
kubectl get configmap lgtm-lbac-proxy-labels -n monitoring \
  -o jsonpath='{.data.labels\.yaml}' > labels-current.yaml
```

#### Step 3: Convert to Extended Format

```bash
# Preview conversion (dry-run)
migrate-labels -input labels-current.yaml -dry-run -tenant-label namespace

# Convert to extended format
migrate-labels -input labels-current.yaml \
  -output labels-extended.yaml \
  -tenant-label namespace

# Verify the output
cat labels-extended.yaml
```

#### Step 4: Test in Non-Production

Deploy the new format to a test environment first:

```bash
# Create test ConfigMap
kubectl create configmap lgtm-lbac-proxy-labels-test \
  --from-file=labels.yaml=./labels-extended.yaml \
  --namespace monitoring \
  --dry-run=client -o yaml | kubectl apply -f -

# Test queries
curl -H "Authorization: Bearer $TOKEN" \
  http://proxy:8080/api/v1/query?query=up
```

#### Step 5: Deploy to Production

```bash
# Update production ConfigMap
kubectl create configmap lgtm-lbac-proxy-labels \
  --from-file=labels.yaml=./labels-extended.yaml \
  --namespace monitoring \
  --dry-run=client -o yaml | kubectl apply -f -

# Restart proxy to reload labels
kubectl rollout restart deployment/lgtm-lbac-proxy -n monitoring
```

#### Step 6: Upgrade Helm Release

```bash
helm upgrade lgtm-lbac-proxy ./helm/lgtm-lbac-proxy \
  --namespace monitoring \
  --values your-values.yaml \
  --version 0.12.0
```

### Rollback Procedure

If you encounter issues after upgrading:

```bash
# 1. Restore original labels ConfigMap
kubectl apply -f labels-backup.yaml

# 2. Downgrade to previous version
helm rollback lgtm-lbac-proxy -n monitoring

# 3. Restart pods
kubectl rollout restart deployment/lgtm-lbac-proxy -n monitoring
```

### Troubleshooting

**Error: "invalid label format" or "missing _rules key"**
- Check that all users have `_rules` and `_logic` keys
- Validate YAML syntax with: `migrate-labels -input labels.yaml -validate`

**Error: Queries return 403 after upgrade**
- Verify label names are correct (case-sensitive)
- Check operator syntax uses quotes: `operator: "="`
- Ensure values are arrays: `values: ["namespace1", "namespace2"]`

**Need help?**
- See [Migration Guide](../../README.md#migration-from-simple-format-v011-and-earlier)
- Open issue: https://github.com/at-blacknight-projects/lgtm-lbac-proxy/issues

---

## Upgrading to Multi-Label Enforcement (v0.10.0)

Starting from version 0.10.0, the proxy supports flexible multi-label enforcement with both simple and extended label formats.

### Backward Compatibility

✅ **No breaking changes** - Existing simple format labels continue to work without modification.

The proxy automatically detects the label format:
- Simple format: Uses `tenant_label` from config as the label name
- Extended format: Uses label rules defined in `_rules`

### Migration Options

You have three options for adopting the new multi-label format:

#### Option 1: No Migration (Recommended for Simple Use Cases)

If you only need single-label enforcement, **no action required**. Your existing labels will continue to work.

```yaml
# This continues to work as-is
user1:
  namespace1: true
  namespace2: true
```

#### Option 2: Manual Migration

Convert specific users to extended format manually:

```yaml
# Before (simple format)
user1:
  prod: true
  staging: true

# After (extended format with multi-label)
user1:
  _rules:
    - name: namespace
      operator: "="
      values: ["prod", "staging"]
    - name: team
      operator: "="
      values: ["backend"]
  _logic: AND
```

#### Option 3: Automated Migration with Helm Job

Use the built-in migration job for bulk conversion.

##### Step 1: Enable Dry-Run Migration

Update your `values.yaml`:

```yaml
migration:
  enabled: true      # Enable migration job
  dryRun: true       # Preview only
  defaultLabel: namespace  # Your tenant label name
```

Deploy the upgrade:

```bash
helm upgrade lgtm-lbac-proxy ./helm/lgtm-lbac-proxy \
  --namespace monitoring \
  --values your-values.yaml
```

Check the migration job logs:

```bash
kubectl logs -n monitoring job/lgtm-lbac-proxy-migrate-labels
```

##### Step 2: Review and Apply

If the preview looks correct, apply the migration:

```yaml
migration:
  enabled: true
  dryRun: false      # Actually perform migration
  defaultLabel: namespace
```

Re-run the upgrade:

```bash
helm upgrade lgtm-lbac-proxy ./helm/lgtm-lbac-proxy \
  --namespace monitoring \
  --values your-values.yaml
```

Follow the instructions in the job logs to update your ConfigMap.

##### Step 3: Disable Migration Job

After successful migration, disable the job:

```yaml
migration:
  enabled: false
```

### Using the Standalone Migration Tool

For local or manual migrations, use the standalone CLI tool:

```bash
# Build the tool
go build -o migrate-labels ./cmd/migrate-labels

# Validate current labels
migrate-labels -input labels.yaml -validate

# Preview conversion
migrate-labels -input labels.yaml -dry-run

# Convert to extended format
migrate-labels -input labels.yaml -output labels-extended.yaml
```

See [cmd/migrate-labels/README.md](../../cmd/migrate-labels/README.md) for full documentation.

### Extended Format Features

The extended format enables:

**Multiple Labels Per User**
```yaml
user1:
  _rules:
    - name: namespace
      operator: "="
      values: ["prod"]
    - name: team
      operator: "="
      values: ["backend", "platform"]
  _logic: AND  # Both conditions must match
```

**Different Operators**
```yaml
user2:
  _rules:
    - name: namespace
      operator: "=~"        # Regex match
      values: ["prod-.*"]
    - name: environment
      operator: "!="        # Not equals
      values: ["development"]
```

**Supported Operators:**
- `=` - Equals
- `!=` - Not equals
- `=~` - Regex match
- `!~` - Regex not match

**Logic Modes:**
- `AND` - All rules must match (default)
- `OR` - Any rule must match

### Rollback

If you encounter issues after migration:

1. Restore your original labels ConfigMap from backup
2. Restart the proxy pods
3. The proxy will automatically revert to simple format processing

### Validation

After migration, validate that your queries work correctly:

```bash
# Test a query with the new labels
curl -H "Authorization: Bearer $TOKEN" \
  http://proxy:8080/api/v1/query?query=up
```

Check the proxy logs for enforcement decisions:

```bash
kubectl logs -n monitoring deployment/lgtm-lbac-proxy | grep -i policy
```

### Performance

The multi-label enforcement has minimal performance impact:
- Policy caching reduces parsing overhead
- Enforcement latency: < 2ms additional (tested with 5 labels)
- Memory increase: ~10MB per 1000 users with complex policies

### Troubleshooting

**Issue: Migration job fails**

Check job logs:
```bash
kubectl logs -n monitoring job/lgtm-lbac-proxy-migrate-labels
```

Common causes:
- Migration tool not included in image
- Labels ConfigMap not mounted
- Invalid YAML in existing labels

**Issue: Queries return 403 after migration**

1. Check user has required labels in new format
2. Verify label names match (case-sensitive)
3. Check operator syntax (use quotes: `operator: "="`)
4. Validate YAML structure with migration tool

**Issue: Some users still using old format**

The proxy supports mixed formats. You can migrate users incrementally:
- Migrated users: Use extended format with multi-label
- Other users: Continue with simple format

### Support

For issues or questions:
- GitHub Issues: https://github.com/at-blacknight-projects/lgtm-lbac-proxy/issues
- Documentation: See [README.md](../../README.md)
