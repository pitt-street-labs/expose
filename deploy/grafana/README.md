# EXPOSE Grafana Dashboards

Tenant-aware observability dashboards for the EXPOSE EASI platform.

## Dashboards

| File | UID | Purpose |
|------|-----|---------|
| `expose-overview.json` | `expose-overview` | Operator overview — active runs, collector health, dispatch latency, tenant activity |
| `expose-tenant.json` | `expose-tenant` | Per-tenant drill-in — runs, entity growth, attribution distribution, collector detail |

The overview dashboard links to the tenant detail dashboard via clickable tenant IDs
in the Tenant Activity table. The tenant dashboard links back to the overview.

## Prerequisites

### Data Source: Prometheus

These dashboards query a **Prometheus** data source that receives EXPOSE OTel
metrics via an OTLP receiver (e.g., the OpenTelemetry Collector's
`otlpreceiver` writing to Prometheus remote-write, or Prometheus's native OTLP
ingestion endpoint added in v2.47+).

The EXPOSE engine emits metrics via OpenTelemetry with these instrument names:

| OTel Instrument Name | Prometheus Metric Name | Type |
|---|---|---|
| `expose.collector.dispatch.duration` | `expose_collector_dispatch_duration_milliseconds_*` | Histogram |
| `expose.collector.dispatch.count` | `expose_collector_dispatch_count_total` | Counter |
| `expose.observations.emitted` | `expose_observations_emitted_total` | Counter |
| `expose.run.duration` | `expose_run_duration_milliseconds_*` | Histogram |
| `expose.runs.active` | `expose_runs_active` | UpDownCounter (gauge) |

Key label dimensions: `tenant_id`, `collector_id`, `status`, `run_id`,
`state`, `attribution_status`.

## Importing Dashboards

### Option 1: Grafana UI Import

1. Open Grafana and navigate to **Dashboards > New > Import**.
2. Click **Upload dashboard JSON file** and select one of the JSON files.
3. On the import screen, select your Prometheus data source from the
   **Prometheus** dropdown (mapped to `DS_PROMETHEUS`).
4. Click **Import**.
5. Repeat for the second dashboard.

### Option 2: Provisioning (GitOps / Helm)

Add a provisioning config to Grafana's `provisioning/dashboards/` directory:

```yaml
# /etc/grafana/provisioning/dashboards/expose.yaml
apiVersion: 1
providers:
  - name: expose
    orgId: 1
    folder: EXPOSE
    type: file
    disableDeletion: false
    updateIntervalSeconds: 30
    allowUiUpdates: true
    options:
      path: /var/lib/grafana/dashboards/expose
      foldersFromFilesStructure: false
```

Then place the JSON files in `/var/lib/grafana/dashboards/expose/`. Grafana
will auto-discover and load them.

When provisioning, replace the `${DS_PROMETHEUS}` placeholder in the JSON with
your actual Prometheus data source UID, or configure a default Prometheus data
source so the dashboards pick it up automatically.

### Option 3: Helm Chart Integration

If deploying via the EXPOSE Helm chart, the dashboards can be mounted as a
ConfigMap. Add to your Helm values:

```yaml
grafana:
  dashboardProviders:
    dashboardproviders.yaml:
      apiVersion: 1
      providers:
        - name: expose
          orgId: 1
          folder: EXPOSE
          type: file
          disableDeletion: false
          options:
            path: /var/lib/grafana/dashboards/expose

  dashboardsConfigMaps:
    expose: expose-grafana-dashboards
```

## Dashboard Variable Configuration

### expose-tenant.json

This dashboard uses a template variable `$tenant_id` that auto-populates from
the `tenant_id` label on `expose_run_duration_milliseconds_count` metrics:

- **Variable name:** `tenant_id`
- **Type:** Query
- **Data source:** Prometheus
- **Query:** `label_values(expose_run_duration_milliseconds_count{tenant_id!=""}, tenant_id)`
- **Refresh:** On time range change
- **Sort:** Alphabetical (asc)

The variable appears as a dropdown at the top of the dashboard. Select a tenant
to filter all panels. You can also navigate directly via URL:

```
/d/expose-tenant/expose-tenant-detail?var-tenant_id=<uuid>
```

### expose-overview.json

No template variables. Shows aggregate data across all tenants.

## Alert Rules to Consider

These dashboards do not include embedded alert rules (Grafana 11+ unified
alerting is configured separately). Recommended alert rules to create:

| Alert | Condition | Severity | Notes |
|-------|-----------|----------|-------|
| **High Active Runs** | `expose_runs_active > 10` for 5m | Warning | Possible backlog or stuck runs |
| **Collector Failure Rate** | Success rate < 80% over 15m per collector | Critical | Collector may be broken or target unreachable |
| **Dispatch Latency Spike** | p95 dispatch latency > 10s for 10m | Warning | Network issues or rate limiting |
| **Run Duration Anomaly** | p95 run duration > 5min for 15m | Warning | Possible hung or slow pipeline stage |
| **Zero Observations** | No observations emitted for a tenant in 24h (when runs > 0) | Info | Collectors running but producing nothing |
| **Stale Tenant** | No runs for a tenant in 7d | Info | Tenant may be inactive or misconfigured |

Example Grafana alerting rule (YAML provisioning format):

```yaml
# /etc/grafana/provisioning/alerting/expose-alerts.yaml
apiVersion: 1
groups:
  - orgId: 1
    name: expose-pipeline
    folder: EXPOSE
    interval: 1m
    rules:
      - uid: expose-collector-failure
        title: Collector Failure Rate High
        condition: C
        data:
          - refId: A
            relativeTimeRange:
              from: 900
              to: 0
            datasourceUid: <prometheus-uid>
            model:
              expr: >-
                sum by (collector_id) (increase(expose_collector_dispatch_count_total{status="success"}[15m]))
                / sum by (collector_id) (increase(expose_collector_dispatch_count_total[15m]))
              instant: true
              refId: A
          - refId: C
            relativeTimeRange:
              from: 900
              to: 0
            datasourceUid: __expr__
            model:
              type: threshold
              expression: A
              conditions:
                - evaluator:
                    type: lt
                    params: [0.8]
        for: 5m
        labels:
          severity: critical
          team: platform
        annotations:
          summary: "Collector {{ $labels.collector_id }} failure rate above 20%"
```
