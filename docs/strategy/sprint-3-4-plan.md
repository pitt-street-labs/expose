# EXPOSE — Phase 1 Sprint 3-4 Detailed Plan

**Status:** Advisory — not locked. Open for revision in subsequent sessions.
**Date:** 2026-05-09
**Author context:** AI-assisted synthesis from the locked spec-phase artifacts (SPEC.md §6 / §7 / §11.1, ADR-001 / ADR-007 / ADR-008 / ADR-010), produced in response to a request for the detailed Sprint 3-4 plan plus a landed framework skeleton. The SPEC stays the source of truth for behavioural requirements.
**Public name:** EXPOSE / **Internal codename:** FF6K
**Companion code:** Plan ships alongside the framework skeleton (`src/expose/collectors/`, `src/expose/sanitization/`, `tests/test_collectors_framework.py`). Code lands the *shape*; concrete collectors land sprint-by-sprint per this plan.

This is the engineering plan for Phase 1 Sprints 3 and 4: scope, framework architecture, orchestration-framework recommendation closing #36, per-collector implementation matrix for the eleven v1 collectors, sanitization layer plan, isolation tests, sprint-by-sprint breakdown, acceptance criteria, open questions, and Sprint 5-6 hand-off.

Advisory. Decisions implied here (orchestration framework, collector tier mappings, sanitization defaults) become locked when the project lead approves; until then, treat as engineering proposal informed by the locked artifacts.

---

## 1. Sprint 3-4 scope and acceptance

### What's in

Per SPEC §11.1 the Sprint 3-4 deliverable is "Collector framework and v1 collectors." Concretely:

- Collector framework — ABC, work-queue contract, per-call config, tenant-context plumbing, rate-limit handling, observation types, collector health.
- Collector registry and dispatcher entry points.
- **Tier 1 (six):** `ct-crtsh`, `cloud-aws-ranges`, `cloud-azure-ranges`, `cloud-gcp-ranges`, `bgp-he-toolkit`, `whois-rdap`.
- **Tier 2 (two, paid):** `pdns-securitytrails`, `iwide-shodan`. Operator-provided keys.
- **Tier 3 (three):** `active-dns-resolve`, `active-tls-handshake`, `active-http-fingerprint`. Attribution-gated per SPEC §6.3 / ADR-008.
- **Sanitization layer** (SPEC §7): field-level sanitization, canonicalization, suspicious-content flagging, `<external_observation>` LLM-prompt wrapper.
- **Cross-tenant isolation tests** for every collector / dispatcher / queue path landed in this scope.
- **Telemetry hooks** wired into OpenTelemetry per ADR-003 for collector latency, success rate, rate-limit events. Dashboards land later; the *instrumentation* lands here.

### What's out

Deferred to other sprints to keep Sprint 3-4 focused:

- **Attribution engine** — Sprint 5-6.
- **Artifact generation** — Sprint 7.
- **LLM enrichment** — Phase 2 / Sprint 9-10. We land the prompt-wrapper now so Sprint 9-10 has the wrapper to call.
- **`active-port-surface`** — deferred. Framework supports its gating; port-surface policy is the most contested operational decision and benefits from real engagement data.
- **Per-tenant credentials** — production-hardening per ADR-007 §When to revisit. v1 uses deployment-global credentials.
- **Optional Tier-1/2 sources** (`ct-certstream`, `ct-censys`, `pdns-validin`, `pdns-farsight`, `iwide-censys`, `iwide-binaryedge`, `whois-whoisxml`, `whois-domaintools`, `bgp-ripestat`, `bgp-team-cymru`) — Phase 4 iteration based on operator demand. Framework supports them by design.

### Acceptance signal

Sprints 3-4 are "done" when (1) eleven collectors merged with passing integration tests, (2) dispatcher routes from tenant config to workers via the queue, (3) sanitization is the only path from collector output to graph upsert, (4) all isolation tests pass, (5) end-to-end smoke against a fixture seed graph (acme.example, one cloud account) produces the expected entity counts within the expected timeout. Detail expanded under §8.

---

## 2. Collector framework architecture

The framework is the contract between the dispatcher (orchestration / control plane) and the collectors. It is intentionally minimal — the SPEC §6.1 ABC has only two abstract methods (`expand`, `health_check`) — but the supporting value types must be expressive enough that the dispatcher can route, retry, time-out, and rate-limit without a per-collector special case.

### 2.1 Abstract base class

The `Collector` ABC (landed in `src/expose/collectors/base.py`):

- Holds class-level metadata: `collector_id`, `collector_version`, `requires_credentials`, `rate_limit_per_minute`, `tier`. The dispatcher reads these without instantiating the class.
- Constructor takes a `CollectorConfig` — fresh per work item. No mutable global state, no thread-locals. This matches the dispatcher's "fresh instance per call" semantics and keeps tenant context bound to one instance.
- `expand(seed)` is `async def` returning `AsyncIterator[Observation]`. Implementations stream observations into the dispatcher rather than returning a list — enables back-pressure, partial-result handling, and avoids loading entire CT-log result sets into memory.
- `health_check()` is a quick pre-run reachability probe that returns a `CollectorHealthCheck` rather than raising. Collectors failing their health check are skipped for the run; the result feeds the artifact's `collector_health` section per SPEC §6.5.

### 2.2 Work-queue interaction

The dispatcher queues one job per `(collector_id, seed)` pair. Each job carries:

- `tenant_id` (from the run's tenant context) — propagated to the worker.
- `run_id` — links observations back to the run that produced them.
- `seed` — the typed input the collector consumes.
- `credentials_ref` — a *reference* to the secret, not the secret itself. The worker resolves the reference via the secrets backend just-in-time per call (per SPEC §6.4).
- `dispatched_at` — for queue-latency telemetry.

Workers consume jobs, instantiate the collector with a freshly-built `CollectorConfig` (containing the resolved credentials), iterate `expand`, write each observation to the dispatcher's intake. The dispatcher (control plane) is the *only* component with database write authority for the observation graph (SPEC §4.2).

### 2.3 Tenant-context plumbing

Tenant context flows three ways per ADR-007:

1. **Job dispatch** — `tenant_id` is in the queue message.
2. **Collector configuration** — `CollectorConfig.tenant_id` carries it through the worker.
3. **Observation provenance** — every `Observation` instance carries `tenant_id`. The graph upsert layer rejects writes whose observation `tenant_id` doesn't match the worker's expected context. This is belt-and-braces; the dispatcher already checks, but a defensive check at the persistence boundary catches bugs that collide tenants across jobs.

The dispatcher uses Python `contextvars` to propagate tenant context across `asyncio` boundaries within the worker. The cross-tenant isolation test suite (§7 below) verifies the contextvar discipline.

### 2.4 Rate-limit handling

Two layers of rate limiting:

- **Per-collector class-level limit** (`Collector.rate_limit_per_minute`) — the upper bound the source documents (e.g., crt.sh ~30/min unauthenticated, Shodan ~1/sec on Membership tier).
- **Per-call configuration limit** (`CollectorConfig.rate_limit_per_minute`) — the operator's configured per-tenant budget. The framework's rate-limiter takes the minimum of the two and enforces it.

The rate-limiter is a token-bucket implemented in the framework (not in each collector). Collectors call `await self._acquire_token()` before each upstream request. On budget exhaustion, the collector emits a warning observation and yields control to the dispatcher rather than blocking indefinitely.

For unrecoverable rate-limit errors (the budget for the run is fully spent and the upstream source has signalled "do not retry today"), the collector raises `CollectorRateLimitError`. The dispatcher catches it, marks the collector status as `RATE_LIMITED`, and proceeds with degraded data (per SPEC §6.5).

### 2.5 Error semantics

Per SPEC §6.1, individual observation failures are *warnings* (attached to the observation), not exceptions. Catastrophic failures (auth invalid, source unreachable past timeout, schema mismatch) raise specific exceptions:

| Exception | Meaning | Dispatcher action |
|---|---|---|
| `CollectorAuthenticationError` | Credential rejected | Mark collector `FAILURE`; do not retry; surface in artifact |
| `CollectorRateLimitError` | Budget exhausted; do not retry | Mark `RATE_LIMITED`; targets dependent on this collector flagged `removal_uncertain_collector_failure` per SPEC §6.5 |
| `CollectorSourceUnreachable` | DNS/TLS/HTTP failure past timeout | Mark `FAILURE`; same removal-uncertain handling |
| `CollectorError` (generic) | Unexpected collector internals | Mark `FAILURE`; capture stack trace for the audit log |

The `partial_run_semantics` of SPEC §6.5 is implemented at the dispatcher level. The artifact's `collector_health` section reports the per-collector outcome.

### 2.6 Observation type definitions

The `ObservationType` enum (landed in `base.py`) is closed and explicit:

`DNS_RESOLUTION`, `DNS_RECORD`, `CT_LOG_ENTRY`, `PASSIVE_DNS`, `WHOIS_REGISTRATION`, `RDAP_REGISTRATION`, `BGP_ASN_LOOKUP`, `CLOUD_IP_RANGE`, `SCANNER_HOST`, `TLS_HANDSHAKE`, `HTTP_RESPONSE`, `PORT_SCAN_RESULT`.

Closed enum (not open string) lets mypy and the dispatcher exhaustively pattern-match. Adding new observation types requires a framework version bump. New collectors adding observation types in Phase 4 do so via PR; the dispatcher's pattern-match exhaustiveness check catches missed additions in CI.

---

## 3. Orchestration framework recommendation (closes issue #36)

Issue #36 ("orchestration framework decision (Sprint 3 critical-path)") asks: Temporal vs. Celery vs. simpler alternatives for the work queue and worker fan-out. ADR-001 explicitly defers this decision; SPEC §12 names "NATS JetStream + thin Python worker pattern" as the default, "revisit when durability requirements are concrete."

### Recommendation

**Adopt the SPEC §12 default: NATS JetStream as the work queue, with thin async Python workers that pull jobs and execute collectors.** Land in Sprint 3.

### Rationale

The choice reduces to four candidates against the v1 needs:

| Option | Operational complexity | Durability | Multi-tenant fairness | Python ergonomics | LLM-pipeline futureproof |
|---|---|---|---|---|---|
| **NATS JetStream + thin workers** | Low (one binary, one cluster) | Stream-with-ack; sufficient for daily-batch | Subjects-per-tenant is natural | Mature `nats-py` async client; minimal abstraction | Same broker handles future Phase 2 LLM job streams |
| Temporal | High (Postgres or Cassandra back-end, Temporal cluster) | Workflow durability is genuinely industry-leading | Namespace-per-tenant works but adds setup | Excellent SDK; activities are first-class | Same workflow engine for LLM enrichment |
| Celery + Redis/RabbitMQ | Medium | Broker durability depends on broker choice | Per-tenant queues require manual setup | Mature but synchronous-first; async support is bolted on | Acceptable but not elegant |
| In-process asyncio fan-out (no broker) | Lowest | None — restart loses in-flight work | None | Trivial | Cannot scale workers separately from control plane |

NATS JetStream wins on the v1-relevant axes:

- **Operational complexity matches v1 lab posture.** Single binary, no external dependency stack. Self-hostable on ARC alongside Postgres and MinIO. Production deployments use the same pattern.
- **Stream-with-ack durability** is enough for daily batch. We don't need workflow durability (Temporal's superpower) because the run model is "if the run fails, the operator triggers a rerun" per SPEC §10.3 — failed runs do not auto-retry.
- **Subjects-per-tenant** implements per-tenant queues without bespoke setup. Subject hierarchy `tenant.<tenant_id>.collector.<collector_id>` falls out naturally; Sprint 5+ per-tenant rate budgets attach cleanly.
- **`nats-py` async client** is mature, supports JetStream consumer-pull semantics, and integrates with `asyncio` per ADR-001.
- **Phase 2 LLM job streams** can use the same broker. Avoids "two brokers, two operational stories."

### Trigger conditions to revisit

Adopt now; revisit if any of these materialize:

1. **Workflow durability requirements emerge.** If we discover the run needs activity-level retry-with-checkpoint semantics that JetStream's stream-with-ack model can't express cleanly, Temporal becomes the right answer. Likely trigger: the LLM enrichment phase needs sub-call retries that survive worker crashes mid-call.
2. **Throughput exceeds JetStream's Postgres-state-machine capacity.** Unlikely at v1 scale (a single tenant's daily run is < 10k jobs); becomes plausible at 100+ tenants with aggressive Tier-3 enumeration.
3. **Operational complexity of running the JetStream cluster outweighs its simplicity advantage.** If the lab team finds JetStream operations harder than expected, Celery + Redis (which the team already operates for other Korlogos services) becomes the fallback.
4. **A second consumer ecosystem materializes** (e.g., a downstream Environment-2 system needs to subscribe to live collector telemetry). NATS' pub-sub model is good for this; only changes the case if the consumer ecosystem requires Kafka-native semantics, which would push us toward Kafka or Redpanda.

### Closure of #36

This recommendation should be the closure comment on issue #36, with this document linked. If the project lead concurs, the framework choice is locked here; if not, request a formal decision conversation before Sprint 3 starts. **Do not proceed with collector implementation under uncertainty here** — the work-queue contract shapes how `CollectorConfig.credentials` resolution works, how rate-limiter budgets are stored, and how worker autoscaling is scripted. A mid-implementation change costs ~2 weeks (per the schedule risk in `docs/strategy/critical-path.md` §Schedule risks).

---

## 4. Per-collector implementation matrix

Eleven collectors ship in Sprint 3-4. Implementation order in §8.

### 4.1 Tier 1 — Passive, broad query

| Collector | Source | Auth | Rate limit | Observations | Integration test approach | Data-quality concerns |
|---|---|---|---|---|---|---|
| `ct-crtsh` | crt.sh JSON API | None | ~30/min unauthenticated | `CT_LOG_ENTRY`, `Domain`, `Subdomain`, `Certificate` | Replay fixture: cached crt.sh JSON for `acme.example` + adversarial SAN payload | crt.sh occasionally returns duplicates and rate-limits aggressively; deduping by leaf cert SHA-256 is mandatory |
| `cloud-aws-ranges` | `https://ip-ranges.amazonaws.com/ip-ranges.json` | None | Polite cache: 1/day (file refreshes daily per SPEC §6.2) | `CLOUD_IP_RANGE`, `CIDR`, `CloudResource` | Vendor file in `tests/fixtures/cloud-ranges/aws.json` | Manifest schema occasionally adds new region codes; collector must tolerate unknown region strings |
| `cloud-azure-ranges` | Azure Service Tags JSON (downloaded via Microsoft Download Center URL with periodic refresh token) | None for the file itself | Polite cache: 1/day | `CLOUD_IP_RANGE`, `CIDR`, `CloudResource` | Vendor fixture | Microsoft rotates the download URL weekly; collector caches the redirect target |
| `cloud-gcp-ranges` | GCP `_cloud-netblocks.googleusercontent.com` SPF chain | None | Polite cache: 1/day | `CLOUD_IP_RANGE`, `CIDR`, `CloudResource` | Vendor fixture (DNS responses) | SPF chain has nested includes; collector must resolve depth-first with cycle detection |
| `bgp-he-toolkit` | Hurricane Electric BGP toolkit web pages (HTML scrape) | None | Conservative: 6/min — HE rate-limits aggressively | `BGP_ASN_LOOKUP`, `ASN`, `IP` → `ASN` edges | Cached HTML pages in fixtures | HE HTML schema changes every few months; the scraper is the most fragile collector. Add a snapshot-test that fails loudly on schema drift. |
| `whois-rdap` | RDAP queries via authoritative RIR endpoints (ARIN, RIPE, APNIC, LACNIC, AFRINIC) | None for low-volume; some RIRs throttle anonymous | Conservative: 12/min total across RIRs | `RDAP_REGISTRATION`, `Organization`, `Registrant` | Cached RDAP JSON responses | RDAP responses include free-text registrant fields that need sanitization (`whois_organization` field kind in §5 below) |

### 4.2 Tier 2 — Passive, targeted (paid)

| Collector | Source | Auth | Rate limit | Observations | Integration test approach | Data-quality concerns |
|---|---|---|---|---|---|---|
| `pdns-securitytrails` | SecurityTrails API v2 | API key | Per-plan; collector reads from response headers | `PASSIVE_DNS`, `Subdomain`, `IP`, `resolves_to` edges | `respx` mock with cached fixture responses; integration test gated on `SECURITYTRAILS_API_KEY` env var | Plan-tier coverage gaps are silent — a result count of 0 may mean "no observations" or "you don't have access to this dataset." Surface plan-level metadata in the observation. |
| `iwide-shodan` | Shodan API | API key | Plan-dependent; defaults to ~1/sec | `SCANNER_HOST`, `Service`, `TLSCertificateSummary` (when present) | `respx` mock; integration test gated on `SHODAN_API_KEY` env var | Shodan banners are heavily adversary-influenced — sanitization is critical; banner length cap (4096 bytes) is mandatory |

### 4.3 Tier 3 — Active, attribution-gated

| Collector | Source | Auth | Rate limit | Observations | Integration test approach | Data-quality concerns |
|---|---|---|---|---|---|---|
| `active-dns-resolve` | Direct DNS resolution via configured resolvers (`dnspython`) | None | Configurable per resolver; default 60/min | `DNS_RESOLUTION`, `DNS_RECORD`, `Subdomain` → `IP` edges | Mock resolver via `dnspython`'s `dns.resolver.Resolver` test helper; against synthetic zones | DNSSEC validation failures, NXDOMAIN handling, large TXT records all need explicit handling |
| `active-tls-handshake` | Direct TLS handshake to `(host, port)` pairs | None | Configurable; default 60/min | `TLS_HANDSHAKE`, `Service`, `Certificate`, `presented_cert` edges | Local OpenSSL test fixtures; `openssl s_server` + a small CA in test setup | Self-signed certs, expired certs, SNI mismatches all need to be surfaced as observation warnings, not failures |
| `active-http-fingerprint` | Direct HTTP/1.1 + HTTP/2 GET to discovered URLs | None | Configurable; default 30/min | `HTTP_RESPONSE`, `HTTPEndpoint`, `Service` | Local `aiohttp.web` test server with controlled response shapes | Server banners and titles need sanitization (HTML tags, very long strings, base64 blobs). Redirect loops must terminate at depth 5. |

All Tier 3 collectors call `assert_tier_3_dispatch_allowed` (landed in `expose.collectors.tiers`) at the dispatcher boundary before invocation. The collector code itself does not check; the gate is in the dispatcher to keep the policy in one place.

### 4.4 Common cross-collector concerns

- **Evidence storage.** Every collector that handles raw external content (cert PEMs, HTTP responses, DNS responses) writes the raw bytes to the evidence object store keyed by SHA-256, and stores `sha256:<hex>` references on observations. The evidence store interface is a Sprint 3 deliverable (used by collectors); the storage backend is MinIO in v1 lab per SPEC §4.1.
- **Telemetry.** Each collector emits OpenTelemetry spans for each upstream call with `collector_id`, `tenant_id`, source URL (with secrets redacted), latency, response code, observation count. The dispatcher emits aggregate spans per `(run_id, collector_id)`.
- **Determinism.** Per SPEC §9.2 the artifact must be deterministic given the same observation graph state. Collector ordering is non-deterministic (parallel workers); the dispatcher canonicalizes the graph state before artifact generation.

---

## 5. Sanitization layer (SPEC §7)

The sanitization layer is Stage 3 of the pipeline and the trust boundary between collector output and the canonical observation graph (SPEC §2.3). Adversaries plant payloads in cert SANs, HTTP banners, DNS TXT records, WHOIS organization fields specifically to manipulate downstream LLM enrichment or to corrupt the graph. The layer's job is to enforce that no raw external content reaches the graph or LLM-bound prompts without passing through a documented, auditable pipeline.

### 5.1 Per-field sanitization pipeline

For every external string field, the pipeline (landed in `src/expose/sanitization/text.py`) applies four steps in order:

1. **Strip ASCII control characters except `\t`, `\n`, `\r`** (`strip_control_chars`). C0 (0x00-0x1F minus the three) and C1 (0x7F-0x9F) are stripped. C1 is included because it carries terminal-escape-style payloads that legitimate text should never contain.
2. **Normalize Unicode to NFC** (`nfc_normalize`). Pre-composes combining sequences. Required for stable equality comparisons across collector sources and for IDN domain canonicalization downstream.
3. **Length-cap by field kind** (`cap_length_bytes` + `cap_for_kind`). Caps are byte-counts on the UTF-8 encoded form. Kind-specific defaults: cert SAN 255B, HTTP banner 4096B, DNS TXT record 1024B, WHOIS organization 1024B, generic 4096B. Truncation is at codepoint boundaries (no half-character output).
4. **Detect and flag suspicious content** (`detect_suspicious`). HTML tags, embedded Markdown, embedded JSON, very-long strings, base64-encoded blobs. Detection runs on the *sanitized* text so flags reflect what's actually stored.

The end-to-end entry point (`sanitize_field`) returns a `SanitizedField` with the cleaned value and a sorted, deduplicated tuple of `SuspiciousFlag` enums. Each flag is also surfaced in the canonical observation's metadata so attribution rules and analyst tooling can react to flagged content (e.g., demote attribution confidence on flagged cert SAN hits).

### 5.2 Canonicalization rules

Landed in `src/expose/sanitization/canonicalize.py`:

- **`canonicalize_domain`** — strip whitespace and trailing dot, lowercase ASCII, IDN-encode non-ASCII labels via stdlib `idna` codec. Idempotent. Empty input raises `CanonicalizationError`.
- **`canonicalize_ip`** — `ipaddress.ip_address` round-trip. IPv6 compression (e.g., `2001:db8:0:0:0:0:0:1` → `2001:db8::1`) and IPv4 normalization. Idempotent.
- **`canonicalize_cidr`** — `ipaddress.ip_network(strict=False)`. Host bits masked off. Idempotent.
- **`normalize_cert_fingerprint`** — strip OpenSSL `:` separators, optional `-` or space separators, optional `sha256:` prefix; lowercase; validate as 64 hex chars. The `CertFingerprintSha256` schema regex matches the output. Idempotent.
- **`canonicalize_timestamp`** — UTC ISO 8601 with `Z` suffix. Naive datetimes assumed UTC; aware datetimes converted. Microsecond precision.
- **`canonicalize_service_id`** — composite identifier `{protocol}://{canonical_host}:{port}` per SPEC §5.2. IPv6 hosts wrap in brackets per URI syntax. Validates protocol ∈ {tcp, udp} and port 1-65535.

**FIPS gate.** Cert fingerprint *computation* (PEM → SHA-256 hex) requires a FIPS-validated SHA-256 per ADR-010. Until the FIPS adapter (`src/expose/crypto/fips_adapter.py`) lands, this module *only normalizes already-computed fingerprints*. Computation lands in Sprint 3 alongside the FIPS adapter; the test gate (`tests/test_fips_crypto_gate.py`) ensures we don't accidentally import `hashlib`.

### 5.3 Suspicious-content detection

Five flags, each cheap to evaluate (no parsers, regex-only):

- `HTML_TAGS` — content contains `<tag>`-shaped tokens.
- `EMBEDDED_MARKDOWN` — bold, links, or headings.
- `EMBEDDED_JSON` — content starts with `{` or `[`.
- `VERY_LONG` — > 1024 bytes after sanitization (deliberately chatty; analysts can dismiss).
- `BASE64_BLOB` — content matches a 40+ char base64 alphabet exactly.

Plus three pipeline flags surfaced when the corresponding step changed the content:

- `CONTROL_CHARS_STRIPPED`
- `NFC_NORMALIZED`
- `LENGTH_CAPPED`

Heuristics are deliberately permissive — false positives are cheap (analyst skims and moves on). Missing an adversarial payload that slips through is not. The detection step is *not* an injection-payload stripper; that's the LLM-prompt wrapper's job (§5.5).

### 5.4 Integration with collector output flow

The dispatcher (control plane) is the only consumer of the sanitization layer:

1. Worker yields raw `Observation` from collector.
2. Dispatcher receives observation via the work queue.
3. Dispatcher calls `sanitize_field` on every external string field (cert SAN, banner, TXT record contents, WHOIS organization, server header, page title, redirect target).
4. Dispatcher constructs the canonical entity / edge writes using the `canonicalize_*` helpers.
5. Dispatcher upserts into Postgres with the `tenant_id` scoping middleware (per ADR-007).
6. Dispatcher writes the raw evidence bytes to MinIO keyed by SHA-256.

Collectors do *not* call sanitization themselves. This keeps the layer in one place; collectors emit their best-effort raw observation, the dispatcher canonicalizes. The integration test for each collector verifies the post-sanitization graph state, not the raw collector output.

### 5.5 LLM prompt construction

Landed in `expose.sanitization.canonicalize.wrap_for_llm_prompt` per SPEC §7.3. The function:

- Defensively strips any embedded `<external_observation>` open/close tags from the content (so adversary content can't break out of the wrapping).
- Wraps the cleaned content in `<external_observation source='<source>'>...</external_observation>`.
- Returns the wrapped string for inclusion in the LLM user message.

The companion `LLM_SYSTEM_PROMPT_PREFIX` is the system-prompt text that instructs the model to treat tag contents as data, never instructions. The dispatcher (Phase 2 / Sprint 9-10) prepends this to every LLM enrichment call. Sprint 3-4 ships only the prefix and the wrapper; the calling code lands in Phase 2.

This is defense-in-depth. Stage 3 sanitization is the primary defence (length caps + control char strips reduce the payload surface); the prompt wrapper is the secondary defence at the LLM trust boundary. Adversaries who plant payloads in cert SANs see their content rendered as data within marked sections; they do not get to issue instructions to the LLM.

---

## 6. Cross-tenant isolation tests for collectors

ADR-007 requires the cross-tenant isolation suite to gate CI from the moment each new surface lands. Sprints 3-4 add the collector / dispatcher / queue paths; the suite must extend to cover them.

The placeholder file (`tests/test_tenant_isolation.py`) already declares the synthetic tenant fixtures (`TENANT_A`, `TENANT_B`) and the test shapes via `@pytest.mark.skip` placeholders. Sprints 3-4 land these as actual tests:

| New isolation test | What it verifies | Hooks |
|---|---|---|
| `test_dispatcher_jobs_carry_correct_tenant_id_through_queue` | A job dispatched with `tenant_a` context arrives at the worker with `tenant_a` in its message body, never `tenant_b` | Stub queue, two-tenant dispatch sequence, assert message bodies |
| `test_collector_config_holds_only_dispatched_tenant_id` | `CollectorConfig.tenant_id` matches the dispatched job's `tenant_id`; no contextvar leakage | Spawn two collectors in interleaved `asyncio.gather` and assert `config.tenant_id` after each |
| `test_observation_persistence_rejects_tenant_id_mismatch` | If a worker emits an observation with the wrong `tenant_id`, the persistence layer rejects the write | Mock collector returning `tenant_b` observation under `tenant_a` job; assert raises |
| `test_evidence_object_keys_namespaced_by_tenant_id` | Evidence blobs in MinIO are keyed `tenant/<tenant_id>/sha256/<hex>`; tenant A cannot read tenant B's evidence by SHA-256 alone | MinIO fixture with two tenant prefixes; assert cross-tenant retrieval raises |
| `test_tier3_gate_uses_per_tenant_authorization_scope` | The `TenantAuthorizationScope` passed to `is_tier_3_dispatch_allowed` is the dispatched job's scope, not a global default; tenant A's scope cannot leak to tenant B | Two synthetic scopes, two dispatched jobs, assert gate uses each |
| `test_credentials_resolution_is_per_tenant_in_phase_3_ready_form` | The credentials slot returned by the secrets backend matches the dispatched job's tenant. v1 uses deployment-global credentials; this test asserts the *interface* is per-tenant-aware so production-hardening doesn't have to refactor | Stub secrets backend, assert tenant-scoped resolve |
| `test_rate_limit_budgets_isolated_per_tenant` | Tenant A exhausting its rate-limit budget for collector X does not affect tenant B's budget | Token-bucket fixture, two-tenant interleaved acquisition, assert budgets independent |

All seven get the `@pytest.mark.isolation` marker (already declared in `pyproject.toml`). CI runs `isolation`-marked tests on every PR regardless of scope; failures block merge.

---

## 7. Sprint-by-sprint breakdown

### Sprint 3 (weeks 1-2)

**Goal:** Framework lands and Tier 1 collectors are operational against a fixture seed graph.

| Item | Owner | Notes |
|---|---|---|
| **NATS JetStream cluster** stood up on ARC | Lab ops | Single-node v1; clustered v2 |
| **Collector framework skeleton** merged | Engineering | Already landed alongside this plan |
| **Dispatcher** (control plane → queue → workers) end-to-end | Engineering | Includes contextvar tenant propagation |
| **Sanitization layer** wired into dispatcher's observation intake | Engineering | The framework module is landed; this connects it |
| **`ct-crtsh`** | Engineering | First collector; sets the patterns the others follow |
| **`cloud-aws-ranges`**, **`cloud-azure-ranges`**, **`cloud-gcp-ranges`** | Engineering | Three small collectors, all roughly similar |
| **`bgp-he-toolkit`** | Engineering | HTML scraper; most fragile; snapshot test |
| **`whois-rdap`** | Engineering | RDAP via the authoritative RIR endpoints |
| **Cross-tenant isolation tests #1-3** | Engineering | Dispatcher / config / persistence boundary |
| **OTel instrumentation hooks** | Engineering | Collector latency, success rate, rate-limit events |
| **FIPS adapter** for SHA-256 cert fingerprint computation | Engineering | Required for `ct-crtsh` and `active-tls-handshake` |
| **End-to-end smoke** against a fixture seed (acme.example) | Engineering | Validates the full Tier 1 flow |

Sprint 3 exit criterion: the eleven Tier 1 collectors are running against a fixture seed and producing canonicalized observations in the graph, with isolation tests passing. No Tier 2 or Tier 3 yet.

### Sprint 4 (weeks 3-4)

**Goal:** Tier 2 paid collectors land; Tier 3 active probing lands with attribution gating.

| Item | Owner | Notes |
|---|---|---|
| **`pdns-securitytrails`** | Engineering | First paid collector; sets the secrets-backend integration pattern |
| **`iwide-shodan`** | Engineering | Heavy banner sanitization — exercises the sanitization layer's adversary-content paths |
| **`active-dns-resolve`** | Engineering | First Tier-3 collector; exercises the dispatch gate |
| **`active-tls-handshake`** | Engineering | Local OpenSSL test fixtures; certs of various states |
| **`active-http-fingerprint`** | Engineering | Local aiohttp test server |
| **Cross-tenant isolation tests #4-7** | Engineering | Evidence keys / Tier-3 scope / per-tenant credentials interface / rate-limit budget |
| **End-to-end smoke** against fixture seed including Tier 3 | Engineering | Validates the gating works; Tier 3 fires only on confirmed/high entities |
| **Telemetry dashboards (skeleton)** | Engineering | Just the JSON dashboard definitions; production deployment is later |
| **Per-collector integration tests** | Engineering | All eleven collectors have replayable fixture-based tests |
| **Sanitization layer fuzz / property tests** | Engineering | hypothesis-based tests on `sanitize_field` to catch edge cases the unit tests miss |

Sprint 4 exit criterion: all eleven collectors are operational against a fixture seed graph, Tier-3 dispatch gating prevents probing of unattributed entities, all isolation tests pass, end-to-end smoke runs in < 5 minutes against the fixture.

---

## 8. Acceptance criteria for Sprint 3-4 done

Mark Sprint 3-4 done when *all* of the following hold:

1. **Eleven collectors merged.** Each has a passing per-collector integration test against a recorded fixture.
2. **Dispatcher routes correctly.** Given a tenant configuration with `collectors.enabled` listing the eleven IDs, the dispatcher invokes each in turn with the configured tenant context, fresh `CollectorConfig`, and resolved credentials.
3. **Sanitization is the only path.** A code review verifies no collector calls graph upsert directly; all observations flow through sanitization first. Add a CI check: import-time analysis fails the build if `expose.collectors.*` modules import `expose.db.models` directly.
4. **Tier-3 gate enforced.** A negative test demonstrates that dispatching a Tier-3 collector for an unattributed entity outside the authorization scope raises `Tier3DispatchDenied`.
5. **Cross-tenant isolation tests pass.** All seven new tests (§7) land green, plus the existing placeholders that this work activates.
6. **End-to-end smoke succeeds.** Using a fixture seed graph (one apex domain, one cloud account), all eleven collectors run, the graph contains the expected entities and edges, the artifact is *not* yet generated (Sprint 7) but the run completes cleanly.
7. **Telemetry observable.** OpenTelemetry traces from a smoke run are visible in a local Jaeger instance with `tenant_id` and `collector_id` tagged on every span.
8. **No FIPS violations.** `tests/test_fips_crypto_gate.py` continues to pass; the new FIPS adapter (`src/expose/crypto/fips_adapter.py`) is the only crypto-using path.
9. **Documentation matches code.** Each collector has a docstring explaining auth requirements, rate limits, observation types produced, and known data-quality concerns. The Federal Customer Deployment Guide's collector-section stub is updated with the eleven shipped collectors.
10. **Issue #36 closed** with the orchestration-framework recommendation in §3 of this document, and the lab's NATS JetStream operations runbook drafted.

---

## 9. Open questions / blockers / decisions needed

These are surfaced now so they get resolved before they block sprint progress.

| # | Question / blocker | Who decides | When needed | Risk if unresolved |
|---|---|---|---|---|
| Q1 | **Confirm orchestration framework recommendation** (close #36 with NATS JetStream + thin workers, or request formal decision conversation). | Project lead | Before Sprint 3 start | High. Mid-implementation change costs ~2 weeks per `critical-path.md` §Schedule risks. |
| Q2 | **Per-tenant rate-limit budgets — interface only or full implementation?** v1 ships deployment-global credentials per ADR-007 §When to revisit; rate-limit budgets are similar. The interface should be tenant-aware so production-hardening doesn't refactor; whether v1 enforces per-tenant budgets is open. | Engineering / project lead | Mid-Sprint 3 | Medium. Affects how the token-bucket is keyed. |
| Q3 | **Active-port-surface inclusion in Sprint 4 vs deferral.** SPEC §6.2 lists it as a v1 collector; SPEC §11.1 for Sprint 3-4 omits it. Recommendation: defer to the LLM-enrichment phase where attribution accuracy on `medium`-tier candidates is mature enough to widen the Tier-3 dispatch gate. Confirm the deferral. | Project lead | Before Sprint 4 start | Low. Framework supports the gating; only the implementation defers. |
| Q4 | **Fixture seed graph for end-to-end smoke.** Use Korlogos's own perimeter (real engagement data) or a synthetic seed (`acme.example` + invented cloud accounts)? Real data tests under realistic conditions but couples the test suite to the lab's actual surface; synthetic data is more portable but tests less. | Engineering / project lead | Mid-Sprint 3 | Low. Default: synthetic; switch only if test coverage gaps emerge. |
| Q5 | **HE BGP scraper longevity.** HE's HTML schema changes every few months; the scraper is fragile by design. Confirm the SPEC §6.2 inclusion as a Sprint-3 collector vs deferring `bgp-he-toolkit` and shipping `bgp-ripestat` (also free, well-documented JSON API) instead. SPEC §6.2 lists both; SPEC §11.1 names HE for Sprint 3. | Engineering | Mid-Sprint 3 | Low. Either is acceptable; RIPEstat is more durable. Recommendation: ship `bgp-ripestat` *first* and `bgp-he-toolkit` second. Surface this for project-lead approval. |
| Q6 | **Evidence object store interface.** SPEC §5.4 says SHA-256-keyed object storage; sprints 3-4 introduce the *interface* used by collectors. Whether the v1 lab uses MinIO immediately or starts with local-filesystem fixture storage and migrates to MinIO during Sprint 4 is open. | Engineering | Sprint 3 week 1 | Low. Both are easy. Default: filesystem in Sprint 3 (faster iteration), MinIO in Sprint 4. |
| Q7 | **Sanitization edge cases needing LLM oversight.** `EMBEDDED_JSON` / `EMBEDDED_MARKDOWN` flags currently surface the issue; whether they should *also* trigger an LLM-enrichment review pass (Phase 2) is a Sprint 5-6 / Phase 2 decision but should be acknowledged now so the flag is available downstream. | Engineering | Sprint 5-6 | Low. Already designed; just needs forward-pointer. |

Decisions Q1, Q3, Q5 should be resolved at the Sprint 3 kickoff. Q2, Q4, Q6 can be made by engineering during the sprint with project-lead notification. Q7 carries forward into Sprint 5-6.

---

## 10. Hand-off to Sprint 5-6 (attribution engine)

Sprint 5-6 builds the rule-based attribution engine on top of the observation graph that Sprint 3-4 populates. Hand-off contract:

### What Sprint 5-6 inherits

- A populated observation graph (Postgres `entities` + `relationships` tables) with sanitized, canonicalized observations from all eleven collectors.
- Provenance fields on every entity / edge: `collector_id`, `observed_at`, `evidence_ref` (sha256: pointer into MinIO).
- `attribution_status` and `attribution_confidence` columns on `entities` exist (per SPEC §5.4) but are unset at sprint hand-off — Sprint 5-6 fills them.
- Sanitization metadata: `SuspiciousFlag` values from the sanitization layer are surfaced in entity properties so attribution rules can demote flagged content.
- Closed `ObservationType` enum and graph schema enable exhaustive rule-engine pattern matching.

### What Sprint 5-6 should NOT have to do

- **Re-sanitize observations.** Stage 3 is upstream of attribution. Rules consume already-sanitized values.
- **Resolve cross-collector deduplication.** The dispatcher dedupes observations of the same entity from multiple collectors before persisting; rules see one entity per canonical identifier.
- **Re-design the collector framework.** If a Sprint-5-6 attribution rule needs evidence the collectors don't currently emit, that's a *collector* PR (Phase 4 iteration), not an attribution-engine refactor.

### Open questions Sprint 5-6 will need to resolve

- **Predicate vocabulary.** SPEC §8.2 says "closed and versioned" but the v1 vocabulary is open for Sprint 5-6 to specify.
- **Lead score formula defaults.** SPEC §8.3 specifies the formula shape; the initial weights and modifiers are Sprint 5-6 / Sprint 6 deliverables.
- **Rule pack format.** SPEC §8.2 references `schemas/rulepack-v1.json`; Sprint 5-6 owns finalizing it and shipping `examples/rulepacks/example-baseline.json`.

### Sprint 5-6 prep recommendations from this plan

1. **Read sanitization-flag handling code.** Attribution rules reading `entity.properties['suspicious_flags']` is a clean integration; Sprint 5-6 should review the flag enum before proposing the predicate vocabulary.
2. **Review the Tier-3 gating helper.** `assert_tier_3_dispatch_allowed` is the canonical place attribution decisions interact with collector dispatch; Sprint 5-6's attribution decisions feed this gate on the next run, so the contract should be locked here.
3. **Land the end-to-end smoke fixture seed graph in Sprint 3-4** so Sprint 5-6 has real data to write attribution rules against from day one.

---

## 11. Related artifacts

- `docs/SPEC.md` §6 — collector framework specification (source of truth).
- `docs/SPEC.md` §7 — sanitization & normalization specification.
- `docs/SPEC.md` §11.1 — Phase 1 phased build plan (Sprint structure source).
- `docs/SPEC.md` §12 — open questions including orchestration framework default.
- `docs/adr/ADR-001-implementation-language.md` — Python + asyncio + httpx; defers orchestration.
- `docs/adr/ADR-007-multi-tenancy.md` — multi-tenant from day one in code; isolation suite gating CI.
- `docs/adr/ADR-008-authorized-use-and-ethics.md` — Tier-3 attribution gating; medium-mode default scope enforcement.
- `docs/adr/ADR-010-fedramp-ready-posture.md` — FIPS gate forbidding `hashlib` / `secrets`; FIPS adapter requirement.
- `src/expose/collectors/` — collector framework code skeleton landed alongside this plan.
- `src/expose/sanitization/` — sanitization layer code skeleton landed alongside this plan.
- `tests/test_collectors_framework.py` — framework contract tests.
- `tests/test_tenant_isolation.py` — cross-tenant isolation suite (Sprint 3-4 activates more of the placeholders).
- `docs/issues-backlog.md` — Tier-3 hard enforcement, per-tenant credentials, scanner egress profiles all reference Sprint 3-4 work.
- `docs/strategy/critical-path.md` — orchestration-framework decision is named as Sprint 3 critical-path risk; this plan closes #36 to retire the risk.
- `docs/strategy/persona-analysis.md` — per-collector matrix in §4 informs which paid sources matter for the Threat Researcher and Red Teamer personas.
- Issue #36 — orchestration framework decision (this document recommends NATS JetStream + thin workers and proposes closing the issue with that recommendation).
