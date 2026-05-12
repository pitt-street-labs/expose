# EXPOSE — Project Working Notes for Claude

This file is loaded automatically when Claude is invoked in this directory. It captures working conventions for this repository so each session does not re-derive them.

## What this is

**EXPOSE** (EXtended Perimeter Ontology Security Evaluation) is an open-core External Attack Surface Intelligence (EASI) platform for Korlogos / Pitt Street Labs, with a federal-customer trajectory. Public name was selected in Session H on 2026-05-10. The internal codename **FF6K** (shortened from FatFinger6000) is preserved for development artifacts, internal communications, and historical references.

This repository (`pitt-street-labs/ff6k` on internal Gitea — repo path retains the internal codename for now) has a complete Phase 1 implementation authorized and executed across Sprint 3-4 sessions (2026-05-10). The locked specification foundation was produced from two design sessions on 2026-05-09 plus the Session H rename pass on 2026-05-10.

**Naming convention going forward:**
- Use **EXPOSE** in all public-facing and customer-facing artifacts (README, SPEC, ADRs, marketing materials)
- Use **FF6K** in development artifacts, commit messages, internal communications, and historical references — including the Gitea repo path (`pitt-street-labs/ff6k`) and the memory directory (`~/.claude/projects/-home-jcarlson-projects-ff6k/`) until any explicit decision to rename them
- Product surfaces all share the EXPOSE prefix per ADR-009: **EXPOSE Core**, **EXPOSE Threat Context**, **EXPOSE Identity Surface**, **EXPOSE Research**

## Hard rules (do not violate)

1. **HARD CONSENT GATE — private until explicit per-action consent.** This repo stays private on internal Gitea (`git.int.korlogos.com:8084`). Do **NOT** push to GitHub.com, public registries, mirrors, or any third-party host. Each visibility-changing action requires explicit project-lead consent in the same conversation. Past consent does not extend to new actions. See `~/.claude/projects/-home-jcarlson-projects-ff6k/memory/ff6k-consent-gate.md`.

2. **Do not modify locked artifacts** without an explicit session for that purpose. Locked: all 10 ADRs (`docs/adr/ADR-001..010`), `docs/SPEC.md`, `docs/positioning.md`, all 3 schemas (`schemas/`), `docs/issues-backlog.md`. These are the consensus output of the spec phase; silent edits destroy it. Mechanical rename passes (Session H on 2026-05-10) and similar deliberate session-driven sweeps are the exception.

3. **Phase 1 implementation is authorized and active.** Sessions B-G deliverables are in progress alongside implementation.

4. **Public name is now EXPOSE.** Session H closed on 2026-05-10. Use EXPOSE consistently in public-facing artifacts; FF6K continues as the internal codename. Do not invent variants.

5. **Do not add dependencies, frameworks, or architectural choices** beyond what the ADRs specify. If you encounter a decision the ADRs don't cover, ask the project lead.

6. **DCO sign-off required** on every commit (`git commit -s ...`).

## Pending (do not pre-empt)

- **`docs/problem-statement.md`** — currently a scaffold awaiting the project lead's researcher-journey framing
- **Sessions B-G** — competitive analysis (B), module specs (C), AI-leverage roadmap (D), framework annotation (E), SDLP (F), Federal Customer Deployment Guide (G). Per project-lead split: the project lead drafts B/E/F/G v0.1 here in Claude Code; Sessions C and D are driven in claude.ai chat with project lead and integrated here.
- **Formal trademark search** for EXPOSE in USPTO security classes (9, 38, 42) before any public publication. Preliminary EASM/security-tooling check was clean but not authoritative.
- **Gitea repo rename** (`pitt-street-labs/ff6k` → `pitt-street-labs/expose`) — separate decision deferred to pre-publication review per consent gate.

## Project facts

| Item | Value |
|---|---|
| Public name | `EXPOSE` (EXtended Perimeter Ontology Security Evaluation) — Session H, 2026-05-10 |
| Internal codename | `FF6K` (use in dev artifacts, repo path, commit messages, internal references) |
| Gitea repo | `pitt-street-labs/ff6k` (private, internal-codename path; rename deferred) |
| Gitea URL | https://git.int.korlogos.com:8084/pitt-street-labs/ff6k |
| Issue tracker | Gitea Issues at the repo above (52 issues; 30+ closed) |
| License | Apache 2.0 (engine); separate proprietary modules per ADR-009 |
| MITRE ATT&CK anchor | Reconnaissance (TA0043) only for Core; Resource Development (TA0042) is a commercial Threat Context module concern |
| Two-environment model | E1 = this codebase (deterministic engine); E2 = downstream LLM analysis (out of scope, anticipates Mythos via Project Glasswing) |

## Where things live

| What | Where |
|---|---|
| Specification | `docs/SPEC.md` |
| Strategic positioning | `docs/positioning.md` |
| Architecture decisions | `docs/adr/ADR-001..010-*.md` |
| Per-decision deferred backlogs | `docs/deferred-issues/` |
| Consolidated 34-issue backlog | `docs/issues-backlog.md` (already filed in Gitea Issues) |
| Codename history | `docs/HISTORY.md` |
| Term definitions | `docs/glossary.md` |
| Problem statement (scaffold) | `docs/problem-statement.md` |
| JSON Schemas (Draft 2020-12) | `schemas/canonical-artifact-v1.json`, `manifest-v1.json`, `rulepack-v1.json` |
| Working example rule pack | `examples/rulepacks/example-baseline.json` |
| Original handoff briefing | `HANDOFF.md` (committed as genesis record) |
| Init script (already executed) | `init-and-push-to-gitea.sh` (committed as genesis record; token redacted) |
| Advisory strategy documents | `docs/strategy/` — non-locked analyses: `persona-analysis.md`, `competitive-analysis.md` (Session B), `framework-annotation.md` (Session E), `sdlp.md` (Session F), `federal-customer-deployment-guide.md` (Session G), `critical-path.md`, plus session-driven additions |
| Architecture diagrams | `docs/architecture/` — mermaid diagrams of pipeline stages, two-environment model, deployment topology, observation graph, multi-tenancy, scanner egress, attribution flow, product surfaces, federal deployment pattern |
| Engine source code | `src/expose/` — 160+ Python source files across 20 sub-packages: `api/` (admin, credentials, events, export, findings, graph, provenance, run_log, runs, scheduler, tenants, tenant_config), `broker/`, `cli.py`, `collectors/` (framework + 31 builtin incl. screenshot-vision, waf-origin-discovery, dark-web-indicators), `compliance/`, `crypto/` (signing with Ed25519/ECDSA, fips_adapter), `db/`, `egress/`, `eval/` (runner + datasets + CLI), `import_/`, `integrations/` (splunk + sentinel + chronicle SIEM adapters), `llm/`, `maintenance/`, `modules/` (threat_context + identity_surface commercial modules), `observability/` (metrics + logging + audit_schema), `pipeline/` (dispatcher + executor + rule_evaluator + scheduler + lead_scoring + enforcement + enrichment + credential_resolver), `quotas/`, `repositories/`, `sanitization/`, `scope/`, `secrets/`, `storage/` (local + s3 + evidence), `types/` (canonical + manifest + rulepack + pipeline + shared), `ui/` |
| Database migrations | `alembic.ini` + `alembic/versions/` (v0001 initial_schema lands tenants/entities/relationships/runs) |
| Container build | `Dockerfile` (multi-stage, multi-arch via buildx) + `.dockerignore` |
| Helm chart | `deploy/helm-chart/` (skeleton — full per-component manifests land Sprint 5+) |
| CI workflow | `.github/workflows/ci.yml` (lint + test + schema-sync + FIPS gate + helm-lint + multi-arch container build + ci-gate aggregator) |
| Pre-commit | `.pre-commit-config.yaml` (ruff + gitleaks + check-jsonschema + helm lint) |
| Tests | `tests/` — **4651+ tests as of 92e5c65.** 145+ test files. Conftest provides `pg_container` + `nats_container` shared session fixtures. aiosqlite for fast API unit tests. #73 fixed. |
| Deploy artifacts | `deploy/helm-chart/` (NetworkPolicy + PodSecurity hardened), `deploy/cosign-keypair-setup.md`, `deploy/grafana/` (2 dashboards + README), `scripts/generate-sbom.sh` |
| Strategy docs | `docs/strategy/` — postgres-deployment-guide, lab-to-production-runbook, network-security-guide, sbom-and-signing-guide, air-gap-deployment-guide, persona-analysis, competitive-analysis, framework-annotation, sdlp, federal-customer-deployment-guide, critical-path, commercial-moat-and-revenue, framework-mapping |
| GitHub-launch docs | `README.md` (public-facing), `CHANGELOG.md` (v0.2.0), `ROADMAP.md`, `GOVERNANCE.md`, `CONTRIBUTING.md` (rewritten for public), `docs/collectors.md` (41-collector catalog), `docs/quickstart.md` (full API catalog), `docs/why-expose.md` (12-axis comparison), `docs/use-cases.md` (8 persona workflows), `docs/user-guide.md` (1298-line feature walkthrough) |
| Egress profiles | `src/expose/egress/` — direct, socks5, http_connect, wireguard, **tor** (circuit rotation, auto-rotate, control port auth) |
| Example outputs | `examples/outputs/` — scan report, findings, provenance, graph, audit log, eval report, Splunk HEC events |
| Example workflows | `examples/workflows/` — basic-scan.sh, scheduled-monitoring.sh, siem-integration.sh, eval-rulepack.sh |
| Architecture diagrams | `docs/architecture/90-egress-flow.md`, `docs/architecture/95-dependency-map.md` (4 Mermaid diagrams) |
| GitHub templates | `.github/ISSUE_TEMPLATE/` (bug, feature, collector request), `.github/PULL_REQUEST_TEMPLATE.md`, `.github/DISCUSSION_TEMPLATE/` (ideas, Q&A, show-and-tell) |
| SpiderFoot credentials | `spiderfoot-creds.txt` (gitignored, 31 API keys — Censys, Shodan, SecurityTrails, BinaryEdge, GreyNoise, VirusTotal, PassiveTotal, AlienVault, + 23 more) |
| Example rule packs | `examples/rulepacks/` — baseline + cloud-first + conservative (3 packs, auto-validated) |
| Eval datasets | `examples/eval-datasets/` — confirmed_yours + confirmed_not_yours + ambiguous + adversarial (4 categories) |
| Strategy docs (new) | `docs/strategy/commercial-moat-and-revenue.md`, `docs/strategy/framework-mapping.md` |
| Commercial modules | `src/expose/modules/threat_context/` (dark web), `src/expose/modules/identity_surface/` (registrant pivot + org graph + ethics gate), `src/expose/modules/soc_package/` (STIX 2.1 + MISP + IoC feed), `src/expose/modules/ciso_report/` (sector analysis + threat actors + executive summary) |
| Service layer | `src/expose/services/` — provenance_service, findings_service, run_service (extracted from API handlers) |
| Temporal analysis | `src/expose/pipeline/temporal_analysis.py` — historical banner progression detection (5 pattern types) |
| Enforcement API | `src/expose/api/enforcement.py` — scope refusal audit trail query |
| SOC/Reports API | `src/expose/api/soc.py` (STIX/MISP/IoC/suspicious), `src/expose/api/reports.py` (CISO report), `src/expose/api/timeline.py` (temporal analysis) |
| Identity API | `src/expose/api/identity.py` — registrant pivot + org-graph query endpoints |
| Evidence storage | `src/expose/storage/s3.py` — full S3/MinIO backend with content-addressed keys + integrity verification |
| Typed payloads | `src/expose/types/collector_payloads.py` — DnsPayload, HttpPayload, TlsPayload, PortScanPayload models |
| Eval harness | `src/expose/eval/` — runner, metrics, CLI; `examples/eval-datasets/` — 60 reference cases across 4 categories |
| Legal/social collector | `src/expose/collectors/builtin/legal_social_mentions.py` — WIPO UDRP + NIST NVD + urlscan.io |
| Vendor CVE collector | `src/expose/collectors/builtin/vendor_cve_history.py` — NVD API, 25 CPE mappings, CWE distribution |
| Vendor vulnerability engine | `src/expose/pipeline/vendor_vulnerability.py` — predictive exposure, 18 threat actors, 33 EOL entries |
| Artifact signing | `src/expose/api/signing.py` — Ed25519 keypair, detached .sig, verify endpoint + CLI |
| Observability subchart | `deploy/helm-chart/charts/observability/` — optional Prometheus + Grafana bundle |
| Hero use cases | `docs/hero-use-cases.md` — 5 end-to-end customer walkthroughs (1312 lines) |
| QA gate | `scripts/qa-gate-25.sh` — 25-pass consecutive test suite runner |
| Deployment | Node1 Quadlet: `expose-api` + `expose-postgres` on port 8096, DNS at `expose.int.korlogos.com` |
| Tests | `tests/` — **4939+ tests as of 4159dbd.** 155+ test files. |

## Issue tracker conventions

- **157+ closed / 15 open / 181 total.** v1-tagged: all closed. All original high-priority issues closed. All critical issues closed as of 2026-05-11 production readiness sprint.
- New issues from Pre-Push session: #48 (screenshot vision), #49 (trust degradation), #50 (WAF/origin discovery), #51 (dark web indicators), #52 (legal/social mentions).
- **Session 2026-05-11 (marathon):** 17 issues closed (#72–#90), 30+ commits. D3 graph fix, iterative multi-pass expansion, M&A org search, egress fallback with SOCKS5/tor, 15 new collectors (29 total), relationship creation, multi-TLD expansion with DNS pre-check, credential persistence, admin panel, scan log panel, entity click-to-expand, target profiling + AI-guided collector selection, supply chain inference with 50-provider fingerprint database, SSRF protection, batch DB writes, parallel dispatch, attribution engine. Security review by ChatGPT + Gemini cross-review.
- **Session 2026-05-11 (prep):** 8-agent deep audit (spec, ADRs, roadmap, session history). 16 new issues filed (#96–#111). M&A pipeline wiring, 38-collector UI (was 13), Gemini LLM provider, help tooltips on all sections, scan form UX fixes. Implementation strategy written for 19-agent 5-wave next session (`~/.claude/plans/expose-tier-abcd-strategy.md`).
- #73 (test_findings_api failure): pre-existing, tracked.
- #86 (fuzzy matching "did you mean?"): open, filed.
- #87 (error evaluation batch): open, partially addressed.
- **Tier A critical (#96–#98):** ALL CLOSED. Rule evaluation wired (loads from tenant config), lead scoring full-signal (WAF/DNSBL/environment/M&A), RunEventBus SSE (collector_started/completed/failed events).
- **Tier B high (#99–#101):** #100 closed (enforcement audit trail). #99 functional but persistence gap (in-memory schedules). #101 open (artifact signing).
- **Tier C medium (#102–#108):** ALL CLOSED. ATT&CK annotations verified, attribution fix confirmed, audit logging NIST AU-2/AU-3 complete, Tier 3 gating implemented.
- **Tier D low (#109–#111):** Open — Identity Surface, Grafana dashboards, evidence storage.
- Labels follow `epic:<slug>`, `area:<slug>`, `priority:<level>`, `type:<kind>`.
- Reference issues by number in commits: `Closes #N` or `Refs #N`.
- New work discovered during a session → file an issue immediately (Tier 3, pre-authorized) rather than letting it slip.

## Tier classification for FF6K work

Following `~/CLAUDE.md` change control:

- **Tier 1 (lab infra approval):** Pushing to Gitea is normally Tier 1, but for this repo specifically the project lead has pre-authorized push-after-commit (the init script ran with consent). Net-new infrastructure outside this repo (e.g., deploying FF6K services to Node1/Node2) remains Tier 1.
- **Tier 2 (z590 ops, impact table required):** Local builds, container experiments, schema validation tooling that touches z590 state.
- **Tier 3 (pre-authorized):** Documentation edits, issue management, project bookkeeping inside this repo (excluding locked artifacts), updates to this CLAUDE.md, memory updates.

## Lessons / facts to preserve

- The init script's default `ssh://...:8084/jcarlson/...` URL was wrong on two counts (port 8084 is Gitea HTTPS, not SSH; and the lab namespace is `pitt-street-labs/`, not `jcarlson/`). The committed script reflects the corrected HTTPS+token form, with the token redacted to `${GITEA_TOKEN:?...}` per the credential-sanitization pattern (see project memory).
- Multi-arch image builds (issue #3) and Cloud object storage migration (#9) had their milestones patched after creation — the importer's title-match for milestone assignment didn't account for parenthetical title suffixes.
- Default git identity for commits in this repo is `Enema Combatant <enema-combatant@users.noreply.github.com>` (lab convention across all PSL repos), even though the project lead's persona is "jcarlson" / Jeffro.
- Advisory documents (e.g., `docs/strategy/persona-analysis.md`) carry an explicit "Advisory — not locked" status header to distinguish them from the foundation artifacts (SPEC.md, ADRs, positioning.md). New advisory work belongs under `docs/strategy/` to keep `docs/` root for the locked spec set.
- After the Session H rename pass (2026-05-10), README.md / SECURITY.md / CONTRIBUTING.md reference `github.com/korlogos/expose` URLs. These are aspirational targets — the consent gate still bars any GitHub.com push. Do not edit them piecemeal; if a future decision changes the org/repo name, run a follow-up rename pass.
- **Sprint 3-4 parallel-execution plan** lives at `~/.claude/plans/precious-noodling-dawn.md` (full plan, 17 agents across 4 waves) + `~/.claude/plans/wave-2-kickoff.md` (fresh-session kickoff for Wave 2 onwards). Wave 1 landed at commit `9b0ece4` on 2026-05-10.
- **Agent `isolation: worktree` parameter is broken in this lab session** because the Agent tool's "is git repo" check uses the env snapshot from session start (when `ff6k-handoff.tar.gz` was just extracted, before `git init`). Workaround: create worktrees manually with `git worktree add .claude/worktrees/<name> -b <branch> main`, then spawn agents WITHOUT `isolation: worktree` and have them `cd <worktree-path>` as their first action. Confirmed working in Wave 1 (6 parallel agents, zero conflicts on disjoint write scopes).
- **testcontainers[nats] 4.14.2 emits `DeprecationWarning`s** for `@wait_container_is_ready` decorator + string-predicate `wait_for_logs`. Project-wide `filterwarnings = ["error"]` in pyproject would fail those tests. W1.A used a narrow per-file `pytestmark = [pytest.mark.filterwarnings("default::DeprecationWarning")]` in `tests/test_broker.py` to override. Strict default remains in force everywhere else.
- **Multi-LLM activation pattern** for Gemini + ChatGPT MCP tools is in `~/.claude/projects/-home-jcarlson-projects-ff6k/memory/multi-llm-mcp-activation.md` — concrete symlink + json-patch commands, plus the vault-fetched wrapper that replaces plaintext key exports.
- **D3 graph.js must be loaded before expose.js in base.html** — `ExposeGraph` is defined in `graph.js` but consumed by `expose.js`. Missing this caused silent graph failure (typeof check returned undefined, `_initGraphAndPoll` returned early).
- **Alpine.js evaluates x-model bindings even on x-show=false elements.** Never null out objects used in x-model; reset to default empty objects and use separate `_loaded` flags for loading state detection.
- **Docker-compose alembic config issue:** Container fails with "No 'script_location' key found" because WORKDIR is `/app` but `alembic.ini` references relative paths. Dev server (`uvicorn` direct) works; container needs alembic.ini path fix. Pre-existing, not introduced by #72.
- **Dev server launch:** `EXPOSE_DB_HOST=localhost EXPOSE_DB_PASSWORD=expose-dev EXPOSE_DB_DATABASE=expose EXPOSE_GEMINI_API_KEY="$GEMINI_API_KEY" .venv/bin/python3 -c "from expose.api.app import create_app; import uvicorn; uvicorn.run(create_app(enable_otel=False), host='0.0.0.0', port=8090)"` — requires postgres running (docker-compose postgres service). Note: password is `expose-dev` not `expose`, and field is `EXPOSE_DB_DATABASE` not `EXPOSE_DB_NAME` (pydantic_settings `extra="forbid"` rejects unknown env vars).
- **Tenant config is in-memory** — lost on server restart. Re-apply via `curl -X PUT .../config/` after restart. LLM config: `{"llm_enabled":true,"llm_provider":"gemini","llm_model":"gemini-2.5-flash","llm_cost_ceiling_per_run":1.0}`.
- **Credentials persist** to `~/.expose-credentials.json` (11 slots configured for default tenant). Survive restarts.
- **Stuck "pending" runs** after server crash: fix with `UPDATE runs SET state='failed', completed_at=NOW() WHERE state='pending';` via docker exec psql.
- **8-agent deep audit (2026-05-11)** identified 5 critical gaps: rule evaluation engine (~5% built), lead scoring unwired, RunEventBus silent, enforcement module unused, collector registry 3-way mismatch (UI/credentials/builtin). Full findings in strategy doc.
- **Tier A-D implementation strategy** at `~/.claude/plans/expose-tier-abcd-strategy.md` — 19 agents, 5 waves, ~90 min. Start next session by reading this plan.
- **Production readiness sprint (2026-05-11):** 20+ parallel agents across 4 waves + bonus features. 3687 → 4357 tests (+670). Closed 20 issues in one session. Key deliverables: SOC threat package (STIX 2.1/MISP/IoC), CISO report (sector/threat actor/attraction), temporal banner analysis (5 progression detectors), service layer extraction, Helm chart completion, metadata sanitization, enforcement audit trail, NIST AU-2/AU-3 audit logging, error metrics counters, HTTP connection pooling, scheduler auth fix (CVSS 9.1). All active collector signals now flow through lead scoring. Rule evaluation loads from tenant config with ScopeContext.
- **run_metadata column** added to Run model (JSONB, NOT NULL, default `{}`). All `Run()` constructors across source and tests must include `run_metadata={}`. Enforcement refusals stored at `run_metadata["enforcement_refusals"]`.
- **Shared TokenStore pattern:** `auth.py` exports `default_token_store` singleton. All API modules should import from `auth.py` rather than creating their own `TokenStore()`.
- **Connection pooling pattern:** Active HTTP and favicon collectors create `httpx.AsyncClient` once per `expand()` call (via `async with`) and pass to sub-methods. Do not create clients per-request inside loops.
- **Production deployment (2026-05-11):** Node1 Quadlet at port 8096. Postgres + API containers, DNS at `expose.int.korlogos.com`, TLS via central proxy, Prometheus scraping, portal registered. Credential file volume-mounted at `/data/credentials.json` via `EXPOSE_CREDENTIALS_PATH` env var.
- **Critical production bugs found and fixed:** (1) `synchronize_session` missing on bulk UPDATE in `update_attribution_scores` — corrupted DB session, all entity upserts silently failed. (2) `batch_upsert` parameter overflow — 40K+ entities exceeded Postgres 65535 param limit, fixed with 500-entity chunking. (3) Alembic migration chain — `run_metadata` column added to model but no migration. (4) Credential resolution mismatch — `sfp_censys`/`sfp_binaryedge` mapped to `None` in SpiderFoot module map. (5) Tenant config 500 — DB `config_jsonb` not merged with defaults. (6) **Entity data loss RCA (2026-05-12):** `session.rollback()` in attribution scoring exception handler destroyed entire transaction — ALL flushed entities lost. Fixed with `session.begin_nested()` savepoints. Also fixed SQLAlchemy 2.0 ORM bulk UPDATE incompatibility by switching to Core `Entity.__table__` + `connection.execute()`. Same savepoint fix for relationship batch_create failures. (7) BGP RIPEstat collector crash on string ASN entries from API.
- **Vendor Vulnerability DNA (2026-05-11):** NVD API collector with 25 CPE mappings, vendor profile engine with 18 threat actors + 33 EOL entries, CISO report Vendor DNA section, 5 new lead scoring signals. Predicts likely vulnerability classes from vendor CVE history.
- **QA gate passed:** 25/25 consecutive runs, 32,371 total test executions, zero flakes.
- **Production deployment v0.2.2 (2026-05-12):** Attribution scoring fix + BGP fix + credentials loaded (8 global + 8 tenant keys) + Gemini LLM enrichment working. First successful production scan: 661 entities for korlogos.com (3 passes, ~3.5 min). Container image tag in Quadlet: `localhost/expose:0.2.2`.

## Subsequent session order (recommended)

| Session | Deliverable | Recommended order |
|---|---|---|
| H | Public name selection | First — clears codename overhang |
| B | Competitive analysis | Second — informs marketing |
| E | Framework annotation deep-dive | Third — informs SDLP and deployment guide |
| C | Module specifications (Threat Context, Identity Surface) | Parallel after E |
| D | Novel AI-leverage roadmap | Parallel after E |
| F | Secure Development Lifecycle Plan | Parallel after E |
| G | Federal Customer Deployment Guide | Parallel after E |

After Session G, Phase 1 implementation can begin per `docs/SPEC.md` §11.1.
