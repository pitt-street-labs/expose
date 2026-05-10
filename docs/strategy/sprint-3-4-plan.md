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

The framework is the contract between the dispatcher (control plane) and collectors. SPEC §6.1's ABC has two abstract methods (`expand`, `health_check`); the supporting value types must be expressive enough that the dispatcher can route, retry, time-out, and rate-limit without per-collector special cases.

### 2.1 Abstract base class

The `Collector` ABC (`src/expose/collectors/base.py`):

- Class-level metadata: `collector_id`, `collector_version`, `requires_credentials`, `rate_limit_per_minute`, `tier`. The dispatcher reads these without instantiating.
- Constructor takes a `CollectorConfig` — fresh per work item. No mutable global state, no thread-locals; tenant context binds to one instance.
- `expand(seed)` is `async def` returning `AsyncIterator[Observation]`. Streaming (not list-returning) enables back-pressure and avoids loading entire CT-log result sets into memory.
- `health_check()` is a pre-run reachability probe returning `CollectorHealthCheck` rather than raising. Failing collectors are skipped for the run; result feeds artifact `collector_health` section per SPEC §6.5.

### 2.2 Work-queue interaction

The dispatcher queues one job per `(collector_id, seed)` pair. Each job carries `tenant_id`, `run_id`, `seed`, `credentials_ref` (reference, not the secret — workers resolve via the secrets backend just-in-time per SPEC §6.4), and `dispatched_at` for telemetry.

Workers consume jobs, instantiate the collector with a freshly-built `CollectorConfig` containing resolved credentials, iterate `expand`, and stream observations to the dispatcher's intake. The dispatcher is the *only* component with database write authority for the observation graph (SPEC §4.2).

### 2.3 Tenant-context plumbing

Tenant context flows three ways per ADR-007: queue message (`tenant_id`), `CollectorConfig.tenant_id` through the worker, and `Observation.tenant_id` on every emission. The graph upsert layer rejects writes whose observation `tenant_id` doesn't match expected context — belt-and-braces; the dispatcher already checks, but a defensive check at the persistence boundary catches tenant-collision bugs.

The dispatcher uses Python `contextvars` to propagate tenant context across `asyncio` boundaries; the isolation test suite (§6) verifies the discipline.

### 2.4 Rate-limit handling

Two layers: class-level limit (`Collector.rate_limit_per_minute`, the upper bound the source documents — e.g. crt.sh ~30/min unauthenticated, Shodan ~1/sec) and per-call config limit (`CollectorConfig.rate_limit_per_minute`, the operator's per-tenant budget). The framework rate-limiter takes the minimum and enforces it via a token-bucket. Collectors call `await self._acquire_token()` before each upstream request.

On budget exhaustion the collector emits a warning observation and yields rather than blocking indefinitely. Unrecoverable rate-limit (budget spent, source says "do not retry today") raises `CollectorRateLimitError`; dispatcher marks status `RATE_LIMITED` and proceeds with degraded data per SPEC §6.5.

### 2.5 Error semantics

Per SPEC §6.1, individual observation failures are *warnings* on the observation, not exceptions. Catastrophic failures raise specific exceptions:

| Exception | Meaning | Dispatcher action |
|---|---|---|
| `CollectorAuthenticationError` | Credential rejected | `FAILURE`; no retry |
| `CollectorRateLimitError` | Budget exhausted | `RATE_LIMITED`; dependent targets flagged `removal_uncertain_collector_failure` per SPEC §6.5 |
| `CollectorSourceUnreachableError` | DNS/TLS/HTTP timeout | `FAILURE`; same removal-uncertain handling |
| `CollectorError` (generic) | Unexpected collector internals | `FAILURE`; capture stack for audit log |

### 2.6 Observation types

The `ObservationType` enum is closed and explicit: `DNS_RESOLUTION`, `DNS_RECORD`, `CT_LOG_ENTRY`, `PASSIVE_DNS`, `WHOIS_REGISTRATION`, `RDAP_REGISTRATION`, `BGP_ASN_LOOKUP`, `CLOUD_IP_RANGE`, `SCANNER_HOST`, `TLS_HANDSHAKE`, `HTTP_RESPONSE`, `PORT_SCAN_RESULT`. Closed (not open string) for exhaustive pattern-matching; new types require a framework version bump and a CI exhaustiveness check.

---

## 3. Orchestration framework recommendation (closes issue #36)

Issue #36 ("orchestration framework decision (Sprint 3 critical-path)") asks: Temporal vs. Celery vs. simpler alternatives for the work queue and worker fan-out. ADR-001 explicitly defers this decision; SPEC §12 names "NATS JetStream + thin Python worker pattern" as the default, "revisit when durability requirements are concrete."

### Recommendation

**Adopt the SPEC §12 default: NATS JetStream as the work queue, with thin async Python workers that pull jobs and execute collectors.** Land in Sprint 3.

### Rationale

| Option | Ops complexity | Durability | Multi-tenant fairness | Python ergonomics | LLM-future |
|---|---|---|---|---|---|
| **NATS JetStream + thin workers** | Low (one binary) | Stream-with-ack | Subjects-per-tenant natural | Mature `nats-py` async | Same broker for Phase 2 LLM streams |
| Temporal | High (Postgres + cluster) | Industry-leading workflow durability | Namespace-per-tenant | Excellent SDK | Strong |
| Celery + Redis/RabbitMQ | Medium | Broker-dependent | Per-tenant queues need setup | Mature but sync-first | Acceptable |
| In-process asyncio fan-out | Lowest | None | None | Trivial | Cannot scale workers separately |

NATS JetStream wins on v1-relevant axes: ops complexity matches lab posture (single binary, self-hostable on ARC alongside Postgres and MinIO); stream-with-ack durability is enough for daily batch (we don't need workflow durability since SPEC §10.3 specifies failed runs require manual retrigger); subjects-per-tenant `tenant.<tid>.collector.<cid>` falls out naturally; `nats-py` integrates with `asyncio` per ADR-001; Phase 2 LLM streams reuse the same broker.

### Trigger conditions to revisit

Adopt now; revisit if (1) workflow durability requirements emerge — likely trigger: Phase 2 LLM enrichment needs sub-call retries surviving worker crashes mid-call; (2) throughput exceeds JetStream capacity (unlikely at v1 scale, plausible at 100+ tenants with aggressive Tier-3); (3) lab team finds JetStream ops harder than expected — Celery + Redis (already in lab use) is the fallback; (4) a second consumer ecosystem requires Kafka-native semantics.

### Closure of #36

This recommendation should be the closure comment on issue #36 with this document linked. If the project lead concurs, the choice is locked here; if not, request a formal decision conversation before Sprint 3 starts. **Do not proceed with collector implementation under uncertainty** — the work-queue contract shapes credentials resolution, rate-limiter budgets, and worker autoscaling. Mid-implementation change costs ~2 weeks per `critical-path.md` §Schedule risks.

---

## 4. Per-collector implementation matrix

Eleven collectors ship in Sprint 3-4. Implementation order in §8.

### 4.1 Tier 1 — Passive, broad query

| Collector | Source / Auth | Rate limit | Observations | Test approach | Data-quality concerns |
|---|---|---|---|---|---|
| `ct-crtsh` | crt.sh JSON / none | ~30/min unauth | `CT_LOG_ENTRY`, Domain, Subdomain, Certificate | Cached JSON fixture + adversarial SAN payload | Frequent duplicates; dedup by leaf cert SHA-256 mandatory |
| `cloud-aws-ranges` | `ip-ranges.amazonaws.com/ip-ranges.json` / none | Cache 1/day | `CLOUD_IP_RANGE`, CIDR, CloudResource | Vendor file in `tests/fixtures/` | Manifest adds new region codes; tolerate unknowns |
| `cloud-azure-ranges` | Azure Service Tags JSON / none | Cache 1/day | `CLOUD_IP_RANGE`, CIDR, CloudResource | Vendor fixture | Microsoft rotates download URL weekly; cache the redirect |
| `cloud-gcp-ranges` | GCP `_cloud-netblocks` SPF chain / none | Cache 1/day | `CLOUD_IP_RANGE`, CIDR, CloudResource | DNS-response fixture | Nested SPF includes; depth-first with cycle detection |
| `bgp-he-toolkit` | HE BGP toolkit HTML scrape / none | 6/min (HE throttles) | `BGP_ASN_LOOKUP`, ASN, IP→ASN edges | Cached HTML | Most fragile; schema drift snapshot test mandatory (see §9 Q5) |
| `whois-rdap` | RIR RDAP endpoints / none | 12/min total | `RDAP_REGISTRATION`, Organization, Registrant | Cached RDAP JSON | Free-text registrant fields need `whois_organization` sanitization |

### 4.2 Tier 2 — Passive, targeted (paid)

| Collector | Source / Auth | Rate limit | Observations | Test approach | Data-quality concerns |
|---|---|---|---|---|---|
| `pdns-securitytrails` | SecurityTrails API v2 / API key | Per-plan; read from response headers | `PASSIVE_DNS`, Subdomain, IP, `resolves_to` | `respx` mock + key-gated integration | Plan coverage gaps are silent — result=0 may mean no observations OR no access. Surface plan-level metadata. |
| `iwide-shodan` | Shodan API / API key | ~1/sec default | `SCANNER_HOST`, Service, TLSCertificateSummary | `respx` mock + key-gated integration | Banners heavily adversary-influenced; 4096B cap mandatory |

### 4.3 Tier 3 — Active, attribution-gated

| Collector | Source / Auth | Rate limit | Observations | Test approach | Data-quality concerns |
|---|---|---|---|---|---|
| `active-dns-resolve` | `dnspython` resolvers / none | 60/min default | `DNS_RESOLUTION`, `DNS_RECORD`, Subdomain→IP | Mock resolver, synthetic zones | DNSSEC failures, NXDOMAIN, large TXT need explicit handling |
| `active-tls-handshake` | Direct TLS / none | 60/min default | `TLS_HANDSHAKE`, Service, Certificate, `presented_cert` | Local `openssl s_server` + test CA | Self-signed / expired / SNI-mismatch surfaced as warnings, not failures |
| `active-http-fingerprint` | HTTP/1.1 + HTTP/2 GET / none | 30/min default | `HTTP_RESPONSE`, HTTPEndpoint, Service | Local `aiohttp.web` server | Banners/titles need sanitization; redirect-loop cap at depth 5 |

All Tier 3 collectors call `assert_tier_3_dispatch_allowed` at the dispatcher boundary. Collector code doesn't check; the gate is in one place.

### 4.4 Common cross-collector concerns

- **Evidence storage.** Raw external content (cert PEMs, HTTP responses, DNS responses) writes to the evidence object store keyed by SHA-256; observations carry `sha256:<hex>` references. Sprint 3 lands the interface (MinIO in v1 lab per SPEC §4.1).
- **Telemetry.** OpenTelemetry spans per upstream call tagged with `collector_id`, `tenant_id`, source URL (secrets redacted), latency, response code, observation count. Dispatcher emits aggregate spans per `(run_id, collector_id)`.
- **Determinism.** SPEC §9.2 requires deterministic artifacts given the same graph state. Collector ordering is non-deterministic; the dispatcher canonicalizes graph state before artifact generation.

---

## 5. Sanitization layer (SPEC §7)

Stage 3 is the trust boundary between collector output and the canonical observation graph (SPEC §2.3). Adversaries plant payloads in cert SANs, HTTP banners, DNS TXT records, WHOIS organization fields specifically to manipulate downstream LLM enrichment or corrupt the graph. The layer enforces that no raw external content reaches the graph or LLM prompts without passing through a documented pipeline.

### 5.1 Per-field sanitization pipeline

`src/expose/sanitization/text.py` applies four steps in order:

1. **Strip ASCII control characters except `\t`, `\n`, `\r`** (`strip_control_chars`). C0 (0x00-0x1F minus three) and C1 (0x7F-0x9F) are stripped. C1 carries terminal-escape-style payloads legitimate text never contains.
2. **NFC normalize** (`nfc_normalize`). Pre-composes combining sequences. Required for stable equality across collector sources and IDN canonicalization.
3. **Length-cap by field kind** (`cap_length_bytes` + `cap_for_kind`). Byte-counts on UTF-8: cert SAN 255B, HTTP banner 4096B, DNS TXT 1024B, WHOIS organization 1024B, generic 4096B. Truncation at codepoint boundaries.
4. **Detect suspicious content** (`detect_suspicious`). HTML tags, embedded Markdown, embedded JSON, very-long strings, base64 blobs. Runs on *sanitized* text so flags reflect what's stored.

`sanitize_field` returns a `SanitizedField` with cleaned value and a sorted, deduplicated tuple of `SuspiciousFlag`s. Flags are surfaced in observation metadata so attribution rules can react (e.g., demote confidence on flagged cert SAN hits).

### 5.2 Canonicalization rules

`src/expose/sanitization/canonicalize.py`:

- **`canonicalize_domain`** — strip whitespace + trailing dot, lowercase ASCII, IDN-encode non-ASCII via stdlib `idna`. Idempotent; empty raises `CanonicalizationError`.
- **`canonicalize_ip`** — `ipaddress.ip_address` round-trip; IPv6 compression, IPv4 normalization.
- **`canonicalize_cidr`** — `ipaddress.ip_network(strict=False)`; host bits masked.
- **`normalize_cert_fingerprint`** — strip `:` / `-` / space separators and `sha256:` prefix, lowercase, validate 64 hex chars. Output matches `CertFingerprintSha256` schema regex.
- **`canonicalize_timestamp`** — UTC ISO 8601 with `Z` suffix, microsecond precision; naive assumed UTC.
- **`canonicalize_service_id`** — composite `{protocol}://{canonical_host}:{port}` per SPEC §5.2. IPv6 hosts bracketed; validates protocol ∈ {tcp, udp} and port 1-65535.

**FIPS gate.** Cert fingerprint *computation* (PEM → SHA-256) requires a FIPS-validated SHA-256 per ADR-010. Until the FIPS adapter (`src/expose/crypto/fips_adapter.py`) lands, this module *only normalizes already-computed fingerprints*. Computation lands in Sprint 3 alongside the FIPS adapter; the test gate (`tests/test_fips_crypto_gate.py`) prevents accidental `hashlib` imports.

### 5.3 Suspicious-content detection

Five content flags (regex only, no parsers): `HTML_TAGS`, `EMBEDDED_MARKDOWN`, `EMBEDDED_JSON` (anchored at start), `VERY_LONG` (>1024B sanitized), `BASE64_BLOB` (40+ char base64 alphabet). Plus three pipeline flags when the step changed content: `CONTROL_CHARS_STRIPPED`, `NFC_NORMALIZED`, `LENGTH_CAPPED`.

Heuristics deliberately permissive — false positives are cheap; missed payloads are not. Detection is *not* a payload stripper; that's the LLM-prompt wrapper's job (§5.5).

### 5.4 Integration with collector output flow

The dispatcher is the only consumer: (1) worker yields raw `Observation`, (2) dispatcher receives via the queue, (3) dispatcher calls `sanitize_field` on every external string field, (4) dispatcher constructs canonical entity/edge writes via the `canonicalize_*` helpers, (5) dispatcher upserts into Postgres with the `tenant_id`-scoping middleware per ADR-007, (6) dispatcher writes raw evidence to MinIO keyed by SHA-256. Collectors don't call sanitization; this keeps the layer in one place. Per-collector integration tests verify post-sanitization graph state, not raw collector output.

### 5.5 LLM prompt construction

`expose.sanitization.canonicalize.wrap_for_llm_prompt` per SPEC §7.3 defensively strips any embedded `<external_observation>` open/close tags (so adversary content can't break out), wraps in `<external_observation source='<source>'>...</external_observation>`, and returns the wrapped string. Companion `LLM_SYSTEM_PROMPT_PREFIX` instructs the model to treat tag contents as data, never instructions. Sprint 3-4 ships the prefix + wrapper; calling code lands in Phase 2.

Defense-in-depth: Stage 3 sanitization (length caps + control char strips) reduces the payload surface; the prompt wrapper is the secondary defence at the LLM trust boundary.

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

### Sprint 3 (weeks 1-2) — Framework + Tier 1

| Item | Owner |
|---|---|
| NATS JetStream cluster on ARC (single-node v1) | Lab ops |
| Framework skeleton (already merged with this plan) | Engineering |
| Dispatcher end-to-end (control plane → queue → workers, contextvar tenant propagation) | Engineering |
| Sanitization layer wired into dispatcher intake | Engineering |
| `ct-crtsh` (sets patterns for the rest) | Engineering |
| `cloud-aws-ranges`, `cloud-azure-ranges`, `cloud-gcp-ranges` | Engineering |
| `bgp-he-toolkit` (HTML scraper; snapshot test) | Engineering |
| `whois-rdap` (RDAP via RIRs) | Engineering |
| Isolation tests #1-3 (dispatcher / config / persistence) | Engineering |
| OTel instrumentation hooks | Engineering |
| FIPS adapter for SHA-256 cert fingerprint computation | Engineering |
| End-to-end smoke against fixture seed (acme.example) | Engineering |

Exit: six Tier 1 collectors running against a fixture seed, producing canonicalized observations, isolation tests pass.

### Sprint 4 (weeks 3-4) — Tier 2 + Tier 3

| Item | Owner |
|---|---|
| `pdns-securitytrails` (sets secrets-backend integration pattern) | Engineering |
| `iwide-shodan` (heavy banner sanitization) | Engineering |
| `active-dns-resolve` (first Tier-3; exercises dispatch gate) | Engineering |
| `active-tls-handshake` (local OpenSSL fixtures, varied cert states) | Engineering |
| `active-http-fingerprint` (local aiohttp test server) | Engineering |
| Isolation tests #4-7 (evidence / Tier-3 scope / per-tenant credentials interface / rate-limit budget) | Engineering |
| End-to-end smoke including Tier 3 (gating fires only on confirmed/high entities) | Engineering |
| Telemetry dashboard JSON skeletons | Engineering |
| Per-collector replayable integration tests | Engineering |
| `hypothesis`-based property tests on `sanitize_field` | Engineering |

Exit: all eleven collectors operational against fixture, Tier-3 gating prevents probing unattributed entities, isolation tests pass, end-to-end smoke runs <5 minutes.

---

## 8. Acceptance criteria for Sprint 3-4 done

Mark Sprint 3-4 done when *all* hold:

1. **Eleven collectors merged** with passing per-collector integration tests against recorded fixtures.
2. **Dispatcher routes correctly** — tenant config's `collectors.enabled` translates to per-collector worker invocations with fresh `CollectorConfig` and resolved credentials.
3. **Sanitization is the only path** — code review + CI import-time analysis blocks `expose.collectors.*` from importing `expose.db.models`.
4. **Tier-3 gate enforced** — negative test for unattributed-entity dispatch raises `Tier3DispatchDeniedError`.
5. **Cross-tenant isolation tests pass** — all seven new tests (§6) green, plus existing placeholders activated.
6. **End-to-end smoke succeeds** — fixture seed graph (one apex, one cloud account), all eleven collectors run, expected entities/edges present, run completes cleanly (artifact gen is Sprint 7).
7. **Telemetry observable** — OTel traces visible in local Jaeger with `tenant_id` and `collector_id` tagged on every span.
8. **No FIPS violations** — `tests/test_fips_crypto_gate.py` passes; new FIPS adapter is the only crypto-using path.
9. **Docs match code** — each collector has a docstring explaining auth, rate limits, observation types, data-quality concerns; the Federal Customer Deployment Guide's collector stub is updated.
10. **Issue #36 closed** with the §3 recommendation and a NATS JetStream operations runbook drafted.

---

## 9. Open questions / blockers / decisions needed

| # | Question | Who | When | Risk |
|---|---|---|---|---|
| Q1 | Confirm orchestration recommendation (close #36 with NATS JetStream + thin workers, or request decision conversation). | Project lead | Before Sprint 3 | **High** — mid-implementation change costs ~2 weeks |
| Q2 | Per-tenant rate-limit budgets: interface-only or v1 enforcement? Interface must be tenant-aware so production-hardening doesn't refactor; whether v1 *enforces* per-tenant is open. | Eng / lead | Mid-Sprint 3 | Medium |
| Q3 | `active-port-surface` deferral confirmation. SPEC §6.2 lists it as v1; SPEC §11.1 omits it from Sprint 3-4. Recommend defer to Phase 2 when attribution accuracy widens the gate. | Project lead | Before Sprint 4 | Low |
| Q4 | Fixture seed graph: Korlogos's own perimeter (realistic but couples tests to lab surface) vs synthetic (`acme.example`). Default: synthetic; switch if coverage gaps emerge. | Eng / lead | Mid-Sprint 3 | Low |
| Q5 | HE BGP scraper longevity. HE HTML changes every few months; scraper is fragile. SPEC §6.2 also lists `bgp-ripestat` (free JSON API, more durable). Recommend ship RIPEstat first, HE second. | Engineering | Mid-Sprint 3 | Low |
| Q6 | Evidence object store: MinIO from Sprint 3 vs filesystem-then-migrate? Default: filesystem in Sprint 3 (fast iter), MinIO in Sprint 4. | Engineering | Sprint 3 wk 1 | Low |
| Q7 | Whether `EMBEDDED_JSON`/`EMBEDDED_MARKDOWN` flags should trigger LLM review (Phase 2). Acknowledge now so the flag is available downstream. | Engineering | Sprint 5-6 | Low |

Q1, Q3, Q5 resolve at Sprint 3 kickoff. Q2, Q4, Q6 can be eng-decided with lead notification. Q7 carries to Sprint 5-6.

---

## 10. Hand-off to Sprint 5-6 (attribution engine)

### What Sprint 5-6 inherits

- Populated observation graph with sanitized, canonicalized observations from all eleven collectors.
- Provenance on every entity / edge: `collector_id`, `observed_at`, `evidence_ref` (sha256 pointer into MinIO).
- `attribution_status` / `attribution_confidence` columns exist per SPEC §5.4 but are unset — Sprint 5-6 fills them.
- `SuspiciousFlag` values surfaced in entity properties so attribution rules can demote flagged content.
- Closed `ObservationType` enum and graph schema enable exhaustive rule-engine pattern matching.

### What Sprint 5-6 should NOT have to do

- Re-sanitize observations (Stage 3 upstream of attribution).
- Cross-collector deduplication (dispatcher dedupes before persisting; rules see one entity per canonical identifier).
- Re-design the collector framework. New attribution evidence needs from Sprint 5-6 are *collector* PRs (Phase 4), not framework refactors.

### Sprint 5-6 prep recommendations

1. **Review sanitization-flag handling.** Attribution rules reading `entity.properties['suspicious_flags']` is a clean integration; review the flag enum before proposing the predicate vocabulary.
2. **Review the Tier-3 gating helper.** `assert_tier_3_dispatch_allowed` is the canonical interaction between attribution decisions and collector dispatch — Sprint 5-6's decisions feed this gate on the next run; lock the contract here.
3. **Land the smoke fixture seed graph in Sprint 3-4** so Sprint 5-6 writes rules against real data from day one.

Sprint 5-6 own: finalizing the predicate vocabulary (SPEC §8.2 says closed/versioned but v1 set is open), lead score formula defaults (SPEC §8.3 specifies shape; initial weights are Sprint 5-6 deliverables), and the rule pack format (`schemas/rulepack-v1.json` + `examples/rulepacks/example-baseline.json`).

---

## 11. Related artifacts

- `docs/SPEC.md` §6 — collector framework spec (source of truth); §7 — sanitization spec; §11.1 — phased build plan; §12 — orchestration framework default.
- `docs/adr/ADR-001` — Python + asyncio + httpx; defers orchestration.
- `docs/adr/ADR-007` — multi-tenant from day one; isolation suite gates CI.
- `docs/adr/ADR-008` — Tier-3 attribution gating; medium-mode default scope.
- `docs/adr/ADR-010` — FIPS gate forbidding `hashlib` / `secrets`; FIPS adapter requirement.
- `src/expose/collectors/` — framework code skeleton landed alongside this plan.
- `src/expose/sanitization/` — sanitization layer skeleton.
- `tests/test_collectors_framework.py` — framework contract tests.
- `tests/test_tenant_isolation.py` — isolation suite (Sprint 3-4 activates more placeholders).
- `docs/issues-backlog.md` — Tier-3 hard enforcement, per-tenant credentials, scanner egress profiles reference Sprint 3-4 work.
- `docs/strategy/critical-path.md` — names orchestration framework as Sprint 3 critical-path risk; this plan retires it.
- `docs/strategy/persona-analysis.md` — per-collector matrix in §4 informs which paid sources matter for the Threat Researcher and Red Teamer personas.
- Issue #36 — orchestration framework decision; this document recommends NATS JetStream + thin workers and proposes closing the issue with that recommendation.
