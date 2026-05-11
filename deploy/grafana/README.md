# EXPOSE Grafana Dashboards

Tenant-aware observability dashboards for the EXPOSE EASI platform.

## Dashboards

| File | UID | Purpose |
|------|-----|---------|
| `expose-overview.json` | `expose-overview` | Operator overview — active runs, run success rate, collector health, dispatch latency, LLM cost, attribution distribution, tenant activity |
| `expose-tenant.json` | `expose-tenant` | Per-tenant drill-in — runs, entity growth, attribution rate, LLM spend, top findings, collector performance, run history |

The overview dashboard links to the tenant detail dashboard via clickable tenant IDs
in the Tenant Activity table. The tenant dashboard links back to the overview.

## Panel Inventory

### expose-overview.json

| Row | Panel | Type | Query Summary |
|-----|-------|------|---------------|
| Pipeline Status | Active Runs | Stat | `expose_runs_active` gauge |
| Pipeline Status | Total Runs (24h/7d/30d) | Stat | `increase(expose_run_duration_milliseconds_count[24h/7d/30d])` |
| Pipeline Status | Run Success Rate | Gauge | `state="completed"` count / total count over `$__range` |
| Pipeline Status | Observations (24h) | Stat | `increase(expose_observations_emitted_total[24h])` |
| Pipeline Status | Entities Discovered (by Type) | Stat | `increase(expose_observations_emitted_total)` grouped by `entity_type` |
| Collector Health | Collector Success Rate | Bar Gauge | `status="success"` dispatches / total dispatches per `collector_id` |
| Collector Health | Collector Health Table | Table | 4 queries: success rate, avg duration, total dispatches, observations per `collector_id` |
| Run Duration & Observations | Run Duration Trend (p50/p95/p99) | Time Series | `histogram_quantile` on `expose_run_duration_milliseconds_bucket` |
| Run Duration & Observations | Observations per Collector (Stacked) | Time Series (stacked bars) | `increase(expose_observations_emitted_total)` by `collector_id` over 5m |
| LLM Cost & Attribution | LLM Cost per Tenant | Bar Chart | `increase(expose_llm_cost_usd_total)` by `tenant_id` |
| LLM Cost & Attribution | Attribution Distribution | Pie Chart | `increase(expose_observations_emitted_total)` by `attribution_status` |
| Dispatch Latency & Tenant Activity | Dispatch Latency | Heatmap | `expose_collector_dispatch_duration_milliseconds_bucket` |
| Dispatch Latency & Tenant Activity | Tenant Activity (24h) | Table | `increase(expose_run_duration_milliseconds_count)` by `tenant_id`, with drill-in links |

### expose-tenant.json

| Row | Panel | Type | Query Summary |
|-----|-------|------|---------------|
| Tenant Summary | Runs (24h) | Stat | `increase(expose_run_duration_milliseconds_count{tenant_id=...}[24h])` |
| Tenant Summary | Observations (24h) | Stat | `increase(expose_observations_emitted_total{tenant_id=...}[24h])` |
| Tenant Summary | Avg Dispatch Latency | Stat | `rate(sum/count)` on dispatch duration histogram |
| Tenant Summary | Collector Success Rate | Stat | `status="success"` dispatches / total dispatches |
| Tenant Summary | Attribution Rate (>= 0.75) | Gauge | `confirmed` observations / total attributed observations |
| Entity Growth & Attribution | Entity Growth | Time Series (stacked) | `increase(expose_observations_emitted_total)` by `collector_id` over 5m |
| Entity Growth & Attribution | Attribution Distribution | Pie Chart | `increase(expose_observations_emitted_total)` by `attribution_status` |
| LLM Spend & Top Findings | LLM Spend over Time | Time Series | `increase(expose_llm_cost_usd_total)` by `llm_provider` over 5m |
| LLM Spend & Top Findings | Top Findings (by Lead Score) | Table | `topk(25, expose_entity_lead_score{tenant_id=...})` |
| Collector Detail | Collector Performance | Table | 5 queries: successes, failures, avg latency, p95 latency, observations per `collector_id` |
| Recent Runs | Run History | Table | 3 queries: duration, observations, LLM cost per `run_id` with state coloring |

## Prerequisites

### Data Source: Prometheus

These dashboards query a **Prometheus** data source that receives EXPOSE OTel
metrics via an OTLP receiver (e.g., the OpenTelemetry Collector's
`otlpreceiver` writing to Prometheus remote-write, or Prometheus's native OTLP
ingestion endpoint added in v2.47+).

The EXPOSE engine emits metrics via OpenTelemetry with these instrument names:

| OTel Instrument Name | Prometheus Metric Name | Type | Status |
|---|---|---|---|
| `expose.collector.dispatch.duration` | `expose_collector_dispatch_duration_milliseconds_*` | Histogram | Implemented |
| `expose.collector.dispatch.count` | `expose_collector_dispatch_count_total` | Counter | Implemented |
| `expose.observations.emitted` | `expose_observations_emitted_total` | Counter | Implemented |
| `expose.run.duration` | `expose_run_duration_milliseconds_*` | Histogram | Implemented |
| `expose.runs.active` | `expose_runs_active` | UpDownCounter (gauge) | Implemented |
| `expose.llm.cost.usd` | `expose_llm_cost_usd_total` | Counter | Planned (Sprint 5+) |
| `expose.entity.lead.score` | `expose_entity_lead_score` | Gauge | Planned (Sprint 5+) |

Key label dimensions: `tenant_id`, `collector_id`, `status`, `run_id`,
`state`, `attribution_status`, `entity_type`, `llm_provider`,
`canonical_identifier`.

### Planned Metrics (Sprint 5+)

The following metrics are referenced in dashboard queries but not yet emitted
by the engine. Panels using these will show "No data" until the metrics are
instrumented:

- **`expose_llm_cost_usd_total`** -- Counter tracking cumulative LLM API
  spend in USD. Labels: `tenant_id`, `run_id`, `llm_provider`. Used by the
  overview LLM Cost per Tenant bar chart and the tenant LLM Spend time series.

- **`expose_entity_lead_score`** -- Gauge representing the current lead score
  (0.0--1.0) for each entity. Labels: `tenant_id`, `entity_type`,
  `canonical_identifier`, `attribution_status`. Used by the tenant Top
  Findings table.

When instrumenting these metrics, follow the existing pattern in
`src/expose/observability/metrics.py` and add corresponding entries to
`_create_instruments()`.

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

No template variables. Shows aggregate data across all tenants. The time range
picker controls the window for `$__range`-based queries (attribution
distribution, LLM cost, entities by type). Fixed-window panels (24h/7d/30d
totals) use hardcoded ranges independent of the picker.

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
| **LLM Cost Ceiling** | `expose_llm_cost_usd_total` rate > $5/hr per tenant | Warning | Tenant approaching cost ceiling |
| **Low Attribution Rate** | Attribution rate < 50% over 24h per tenant | Info | Most findings lack confirmed attribution |
| **Run Success Rate Drop** | Run success rate < 90% over 1h | Critical | Pipeline failures affecting multiple runs |

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
