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
| Engine source code | `src/expose/` — 111 Python source files across 18 sub-packages: `api/`, `broker/`, `cli.py`, `collectors/` (framework + 14 builtin), `compliance/`, `crypto/`, `db/`, `egress/`, `eval/`, `import_/`, `llm/` (SafeLLMClient + 4 provider adapters), `maintenance/`, `observability/`, `pipeline/` (dispatcher + executor + seed expansion + artifact generator + credential resolver + enforcement), `quotas/`, `repositories/`, `sanitization/`, `scope/`, `secrets/`, `storage/`, `types/`, `ui/` |
| Database migrations | `alembic.ini` + `alembic/versions/` (v0001 initial_schema lands tenants/entities/relationships/runs) |
| Container build | `Dockerfile` (multi-stage, multi-arch via buildx) + `.dockerignore` |
| Helm chart | `deploy/helm-chart/` (skeleton — full per-component manifests land Sprint 5+) |
| CI workflow | `.github/workflows/ci.yml` (lint + test + schema-sync + FIPS gate + helm-lint + multi-arch container build + ci-gate aggregator) |
| Pre-commit | `.pre-commit-config.yaml` (ruff + gitleaks + check-jsonschema + helm lint) |
| Tests | `tests/` — **1059 tests passing as of d881c9a.** 61 test files, 111 source files. Conftest provides `pg_container` + `nats_container` shared session fixtures. aiosqlite for fast API unit tests. |
| Deploy artifacts | `deploy/helm-chart/` (NetworkPolicy + PodSecurity hardened), `deploy/cosign-keypair-setup.md`, `deploy/grafana/` (2 dashboards + README), `scripts/generate-sbom.sh` |
| Strategy docs | `docs/strategy/` — postgres-deployment-guide, lab-to-production-runbook, network-security-guide, sbom-and-signing-guide, air-gap-deployment-guide, persona-analysis, competitive-analysis, framework-annotation, sdlp, federal-customer-deployment-guide, critical-path |
| GitHub-launch docs | `README.md` (public-facing), `CHANGELOG.md`, `ROADMAP.md`, `GOVERNANCE.md`, `CONTRIBUTING.md` (rewritten for public), `docs/collectors.md` (14-collector catalog), `docs/quickstart.md`, `docs/why-expose.md`, `docs/use-cases.md` |
| GitHub templates | `.github/ISSUE_TEMPLATE/` (bug, feature, collector request), `.github/PULL_REQUEST_TEMPLATE.md`, `.github/DISCUSSION_TEMPLATE/` (ideas, Q&A, show-and-tell) |
| SpiderFoot credentials | `spiderfoot-creds.txt` (gitignored, 31 API keys — Censys, Shodan, SecurityTrails, BinaryEdge, GreyNoise, VirusTotal, PassiveTotal, AlienVault, + 23 more) |
| Example rule packs | `examples/rulepacks/` — baseline + cloud-first + conservative (3 packs, auto-validated) |
| Eval datasets | `examples/eval-datasets/` — confirmed_yours + confirmed_not_yours (Phase 2 harness) |

## Issue tracker conventions

- **30+ closed / 20+ open / 52 total.** v1-tagged: all closed. All original high-priority issues closed.
- New issues from Pre-Push session: #48 (screenshot vision), #49 (trust degradation), #50 (WAF/origin discovery), #51 (dark web indicators), #52 (legal/social mentions).
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
