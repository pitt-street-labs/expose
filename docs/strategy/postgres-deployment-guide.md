# EXPOSE -- PostgreSQL Production Deployment Guide

**Status:** Advisory -- not locked. Open for revision in subsequent sessions.
**Date:** 2026-05-10
**Author context:** AI-assisted guide derived from the implemented data layer (`src/expose/db/models.py`, `src/expose/db/engine.py`, `alembic/` migrations) and the Helm chart skeleton (`deploy/helm-chart/`). Addresses Gitea issue #2 (Postgres production deployment documentation).
**Public name:** EXPOSE / **Internal codename:** FF6K

This guide is for operators deploying EXPOSE's PostgreSQL dependency. It covers connection configuration, sizing, backup, migration procedures, monitoring, and security. It does **not** alter the locked specification or ADRs.

---

## 1. Development vs Production

| Environment | Postgres source | Acceptable? |
|-------------|-----------------|-------------|
| Dev / lab / CI | In-cluster via Helm subchart (`bitnami/postgresql`) or Docker Compose sidecar | Yes -- testing and local iteration only |
| Production | Managed service (RDS, Cloud SQL, Azure Database for PostgreSQL) or self-managed HA cluster | **Required** |

**In-cluster Postgres is not production-grade.** It lacks automated failover, PITR, and managed backup. The Helm chart enforces this convention: `postgres.enabled: false` by default. Set it to `true` only for dev/lab.

For Docker Compose local development:

```yaml
services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: expose
      POSTGRES_USER: expose
      POSTGRES_PASSWORD: localdev
    ports:
      - "5432:5432"
```

---

## 2. Connection Configuration

### 2.1 Environment variables

EXPOSE reads database configuration from `EXPOSE_DB_*` environment variables (12-factor, per ADR-003). The `DatabaseSettings` class in `src/expose/db/engine.py` handles construction:

| Variable | Default | Description |
|----------|---------|-------------|
| `EXPOSE_DB_HOST` | `localhost` | Postgres hostname or IP |
| `EXPOSE_DB_PORT` | `5432` | Postgres port |
| `EXPOSE_DB_DATABASE` | `expose` | Database name |
| `EXPOSE_DB_USER` | `expose` | Database user |
| `EXPOSE_DB_PASSWORD` | (empty) | Database password (`SecretStr` -- never logged) |
| `EXPOSE_DB_SSLMODE` | `prefer` | TLS mode: `disable`, `prefer`, `require`, `verify-ca`, `verify-full` |
| `EXPOSE_DB_POOL_SIZE` | `10` | SQLAlchemy connection pool size |
| `EXPOSE_DB_MAX_OVERFLOW` | `20` | Max connections above `pool_size` |
| `EXPOSE_DB_POOL_PRE_PING` | `true` | Validate connections before use |
| `EXPOSE_DB_ECHO` | `false` | Log all SQL (never enable in production) |

The engine constructs the asyncpg DSN internally:

```
postgresql+asyncpg://{user}:{password}@{host}:{port}/{database}
```

### 2.2 Kubernetes Secret injection

In the Helm chart, credentials come from a Kubernetes Secret referenced by `postgres.existingSecret`. The Secret must contain two keys:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: expose-postgres-credentials
type: Opaque
stringData:
  user: expose
  password: <strong-random-password>
```

The Helm deployment injects these as `EXPOSE_DB_USER` and `EXPOSE_DB_PASSWORD` via `secretKeyRef`. Host, port, database, and sslmode are set directly in `values.yaml`:

```yaml
postgres:
  enabled: false
  host: "expose-db.cxxxxxx.us-east-1.rds.amazonaws.com"
  port: 5432
  database: "expose"
  existingSecret: "expose-postgres-credentials"
  sslmode: "require"
```

### 2.3 TLS requirements

| Environment | Minimum | Recommended `sslmode` |
|-------------|---------|----------------------|
| Dev / lab | None | `prefer` |
| Production (managed) | TLS 1.2 | `require` (managed services handle CA validation) |
| Production (self-managed) | TLS 1.2 | `verify-full` (pin the CA certificate) |
| FedRAMP / FIPS (per ADR-010) | TLS 1.2 with FIPS-approved ciphers | `verify-full` |

For `verify-ca` or `verify-full`, provide the CA certificate path via asyncpg's `ssl` connect argument. This requires extending `connect_args` in `engine.py` (tracked as a future hardening item).

### 2.4 Connection pool tuning

The pool is managed by SQLAlchemy's async engine over asyncpg. Total maximum connections from a single EXPOSE process:

```
max_connections = pool_size + max_overflow = 10 + 20 = 30 (default)
```

Tuning guidance:

| Deployment pattern | `pool_size` | `max_overflow` | Rationale |
|-------------------|-------------|----------------|-----------|
| Single control-plane replica | 10 | 20 | Default; sufficient for typical single-tenant |
| Multiple replicas (3+) | 5 | 10 | Reduce per-replica share; total = replicas x (pool_size + max_overflow) |
| Worker processes (collectors) | 3 | 5 | Workers are write-light; most work is HTTP collection |
| High-throughput multi-tenant | 15 | 30 | Monitor `pg_stat_activity` and increase Postgres `max_connections` accordingly |

Ensure the Postgres server's `max_connections` exceeds the sum of all pool maximums across all replicas plus a reserve for maintenance connections (`pg_dump`, Alembic, monitoring). A safe formula:

```
pg max_connections >= (replicas * (pool_size + max_overflow)) + 20
```

---

## 3. PostgreSQL Version and Extensions

### 3.1 Version requirements

| Requirement | Version |
|-------------|---------|
| **Minimum** | PostgreSQL 14 |
| **Recommended** | PostgreSQL 16+ |
| **Tested in CI** | PostgreSQL 16 (testcontainers) |

PostgreSQL 14 is the floor because the schema uses `JSONB` server defaults, `TIMESTAMPTZ`, and `UUID` primary keys. While `gen_random_uuid()` is built-in from PG 13+, PG 14 is the minimum that receives upstream security patches through the EXPOSE v1 support window.

### 3.2 Required extensions

| Extension | Purpose | Availability |
|-----------|---------|--------------|
| `uuid-ossp` | `uuid_generate_v4()` (fallback; application generates UUIDs via Python) | Built-in on all major managed services |
| `pg_trgm` | Future trigram-based text search on `canonical_identifier` | Built-in; enable when search features land |

No exotic extensions (PostGIS, pgvector, Apache AGE) are required for v1. The ADR-002 roadmap notes Apache AGE as a future parallel access path on the same database -- that is a Phase 3+ concern and does not affect initial deployment.

### 3.3 Database initialization

After provisioning the Postgres instance, create the database and user:

```sql
CREATE USER expose WITH PASSWORD '<password>';
CREATE DATABASE expose OWNER expose;
\c expose
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";
```

Then run the Alembic migration (see section 6).

---

## 4. Sizing Guidance

| Scale tier | Tenants | Entities | Relationships | Postgres spec | Storage | Notes |
|-----------|---------|----------|---------------|--------------|---------|-------|
| **Small** (lab, pilot) | 1-3 | ~100K | ~500K | 2 vCPU / 8 GB RAM | 100 GB SSD (gp3) | Single instance; daily `pg_dump` |
| **Medium** (single org) | 4-10 | ~1M | ~5M | 4 vCPU / 16 GB RAM + read replica | 500 GB SSD (gp3) | Read replica for reporting/API reads |
| **Large** (multi-tenant, federal) | 10+ | ~10M+ | ~50M+ | Managed HA (Multi-AZ) | 1 TB+ provisioned IOPS (io2) | Automated failover, PITR, encryption at rest |

### Storage growth estimators

Average row sizes based on the schema:

| Table | Avg row size | Notes |
|-------|-------------|-------|
| `entities` | ~800 bytes | JSONB `properties` is the variable factor |
| `relationships` | ~400 bytes | Provenance metadata is compact |
| `runs` | ~300 bytes | One row per pipeline execution |
| `tenants` | ~500 bytes | Negligible count |

For 1M entities with 5x relationship fan-out: ~800 MB entities + ~2 GB relationships + indexes ~ **5 GB total**. Budget 3-5x for index overhead, MVCC bloat, and WAL.

### Key Postgres parameters to tune

| Parameter | Small | Medium | Large |
|-----------|-------|--------|-------|
| `shared_buffers` | 2 GB | 4 GB | 8-16 GB (25% of RAM) |
| `effective_cache_size` | 6 GB | 12 GB | 48+ GB (75% of RAM) |
| `work_mem` | 16 MB | 32 MB | 64 MB |
| `maintenance_work_mem` | 256 MB | 512 MB | 1 GB |
| `max_connections` | 100 | 200 | 400 |
| `random_page_cost` | 1.1 (SSD) | 1.1 | 1.1 |
| `wal_level` | `replica` | `replica` | `logical` (if CDC needed) |

Managed services (RDS, Cloud SQL) handle most of these automatically. Only tune explicitly for self-managed deployments.

---

## 5. Backup and Recovery

### 5.1 Managed Postgres (recommended)

| Capability | Configuration |
|------------|---------------|
| Automated snapshots | Daily, retain 7-30 days (provider default) |
| Point-in-time recovery (PITR) | Enable WAL archiving; recovery window = retention period |
| Encryption at rest | Enable with KMS key (required for FedRAMP per ADR-010) |
| Cross-region replica | Optional; for DR in multi-region deployments |

### 5.2 Self-managed Postgres

| Capability | Implementation |
|------------|----------------|
| Base backup | `pg_basebackup` daily to object storage (S3/MinIO) |
| WAL archiving | `archive_mode = on`, `archive_command` shipping to object storage |
| Logical backup | `pg_dump --format=custom` daily as a defense-in-depth layer |
| PITR | Restore base backup + replay WAL to target timestamp |
| Encryption at rest | LUKS or dm-crypt on the data volume |

### 5.3 Backup verification

Run a monthly restore-to-staging test:

1. Restore the latest base backup to a staging Postgres instance
2. Apply WAL replay to verify PITR works to within the last 5 minutes
3. Run `alembic current` to confirm schema version matches production
4. Run the EXPOSE health check endpoint against the restored database
5. Record the test result and restore duration

Automate this in CI or a scheduled job. An untested backup is not a backup.

### 5.4 Retention policy

The EXPOSE retention pruner (`src/expose/maintenance/`) handles application-level data retention (incidental data per ADR and issue #31). Database-level backup retention is orthogonal:

| Backup type | Retention |
|-------------|-----------|
| Daily snapshots | 30 days |
| Weekly snapshots | 90 days |
| Monthly snapshots | 1 year |
| WAL segments | Match snapshot retention window |

---

## 6. Schema Migration Procedure

### 6.1 Standard deployment

Run Alembic as part of the deployment pipeline, **before** starting application pods:

```bash
# From the application container or an init container:
alembic upgrade head
```

The `alembic.ini` leaves `sqlalchemy.url` empty -- the connection URL is built at runtime from `EXPOSE_DB_*` environment variables via `env.py`. Ensure the migration runner has the same env vars as the application.

### 6.2 Helm deployment pattern

Use a Kubernetes Job or init container to run migrations before the main deployment rolls out:

```yaml
initContainers:
  - name: migrate
    image: {{ include "expose.image" . }}
    command: ["alembic", "upgrade", "head"]
    env:
      # Same EXPOSE_DB_* variables as the main container
```

### 6.3 Checking current version

```bash
alembic current   # Shows applied revision(s)
alembic history   # Shows full migration chain
```

As of the initial schema, the current head is `0001_initial_schema` (tenants, entities, relationships, runs).

### 6.4 Rollback

Every migration has a `downgrade()` path. To roll back one revision:

```bash
alembic downgrade -1
```

To roll back to a specific revision:

```bash
alembic downgrade <revision_id>
```

**Caution:** Downgrades that drop tables or columns are destructive. Always verify the downgrade path in staging before executing in production.

### 6.5 Major Postgres version upgrades

For major version upgrades (e.g., PG 15 to PG 16):

1. Provision the new Postgres version (blue instance)
2. Restore a backup or use logical replication to sync data
3. Run `alembic current` on the new instance to confirm schema compatibility
4. Run the EXPOSE test suite against the new instance
5. Switch traffic (update `EXPOSE_DB_HOST` / DNS)
6. Decommission the old instance after validation

Managed services typically handle major version upgrades with minimal downtime. Follow the provider's upgrade procedure and test with EXPOSE beforehand.

---

## 7. Monitoring

### 7.1 Key metrics

| Metric | Source | Alert threshold |
|--------|--------|-----------------|
| Active connections | `pg_stat_activity` | > 80% of `max_connections` |
| Query latency p95 | `pg_stat_statements` or OTel | > 200 ms |
| Cache hit ratio | `pg_stat_database` (`blks_hit / (blks_hit + blks_read)`) | < 95% |
| Dead tuples | `pg_stat_user_tables` (`n_dead_tup`) | > 10% of `n_live_tup` (autovacuum lagging) |
| WAL lag (replicas) | `pg_stat_replication` (`replay_lag`) | > 30 seconds |
| Disk usage | OS / cloud metrics | > 80% of provisioned storage |
| Transaction wraparound | `age(datfrozenxid)` | > 1 billion (vacuum urgently needed) |
| Long-running queries | `pg_stat_activity` (`state = 'active'`, `query_start`) | > 60 seconds |

### 7.2 OpenTelemetry integration

EXPOSE instruments SQLAlchemy via `opentelemetry-instrumentation-sqlalchemy` (per ADR-003 observability requirements). This emits spans for every database operation including:

- Query duration and statement text (sanitized)
- Connection pool checkout/checkin timing
- Transaction commit/rollback events

The Helm chart's `observability.otlp.endpoint` routes these spans to the operator's telemetry backend (Prometheus + Tempo, Datadog, AWS X-Ray, etc.).

### 7.3 Recommended dashboards

For self-managed deployments, deploy `postgres_exporter` (Prometheus) and import the standard PostgreSQL dashboard (Grafana ID 9628). Key panels:

- Connections by state (active / idle / idle in transaction)
- Query rate and error rate
- Tuple operations (inserts, updates, deletes per table)
- Cache hit ratio over time
- Replication lag (if replicas configured)

---

## 8. Security

### 8.1 Database user privileges

Create a dedicated user with **minimal privileges** -- no superuser, no createdb, no createrole:

```sql
-- Application user (used by EXPOSE at runtime)
CREATE USER expose WITH PASSWORD '<password>';
GRANT CONNECT ON DATABASE expose TO expose;
GRANT USAGE ON SCHEMA public TO expose;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO expose;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO expose;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO expose;

-- Migration user (used by Alembic only; can be the same user in small deployments)
CREATE USER expose_migrate WITH PASSWORD '<password>';
GRANT CONNECT ON DATABASE expose TO expose_migrate;
GRANT ALL PRIVILEGES ON SCHEMA public TO expose_migrate;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO expose_migrate;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO expose_migrate;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT ALL PRIVILEGES ON TABLES TO expose_migrate;
```

For production, use separate users for runtime and migration so the application cannot `ALTER TABLE` or `DROP`.

### 8.2 Network isolation

Postgres must be accessible **only** from the EXPOSE namespace. Enforce this at the network level:

| Environment | Mechanism |
|-------------|-----------|
| Kubernetes | `NetworkPolicy` restricting ingress to Postgres on port 5432 to pods with the EXPOSE selector labels (the Helm chart's default-deny policy provides the baseline) |
| AWS | VPC security group allowing 5432 only from the EKS node security group or EXPOSE pod CIDR |
| Azure | Virtual network rules on the Azure Database for PostgreSQL instance |
| GCP | Authorized networks on the Cloud SQL instance |
| Self-managed | `pg_hba.conf` restricted to EXPOSE application subnet; firewall rules blocking all other sources |

### 8.3 Secrets management

| Requirement | Implementation |
|-------------|----------------|
| Password storage | Kubernetes Secret (base64); for production, use a secrets operator (External Secrets Operator, Vault Agent) to sync from the secrets backend |
| Password rotation | Rotate credentials via the secrets backend; update the Kubernetes Secret; restart pods (zero-downtime with rolling deployment) |
| Audit logging | Enable `pgaudit` extension for DDL and DML audit trails (FedRAMP requirement per ADR-010) |
| Connection string | Never embed in container images, Helm values committed to git, or application logs |

### 8.4 Encryption

| Layer | Requirement |
|-------|-------------|
| In transit | TLS 1.2+ (`sslmode: require` or stricter) |
| At rest | Managed service encryption (KMS) or LUKS for self-managed |
| Backups | Encrypt backup artifacts with the same KMS key or a dedicated backup key |

---

## Appendix: Quick-Start Checklist

For operators deploying EXPOSE with a managed PostgreSQL instance:

- [ ] Provision PostgreSQL 16+ with TLS enabled
- [ ] Create database `expose` and user `expose` with minimal privileges
- [ ] Enable extensions: `uuid-ossp`, `pg_trgm`
- [ ] Create Kubernetes Secret with `user` and `password` keys
- [ ] Configure `values.yaml`: `postgres.host`, `postgres.existingSecret`, `postgres.sslmode: require`
- [ ] Run `alembic upgrade head` (init container or pre-deploy job)
- [ ] Verify: `alembic current` shows `0001_initial_schema`
- [ ] Configure automated daily snapshots with PITR enabled
- [ ] Set up monitoring (connections, latency, cache hit ratio, disk)
- [ ] Apply NetworkPolicy or security group restricting Postgres access to EXPOSE pods only
- [ ] Schedule monthly backup restore test
