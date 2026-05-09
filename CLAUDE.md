# FF6K — Project Working Notes for Claude

This file is loaded automatically when Claude is invoked in this directory. It captures working conventions for this repository so each session does not re-derive them.

## What this is

**FF6K** (working codename, shortened from FatFinger6000) is an open-core External Attack Surface Intelligence (EASI) platform for Korlogos / Pitt Street Labs, with a federal-customer trajectory. Public name is deferred to **Session H**.

This repository (`pitt-street-labs/ff6k` on internal Gitea) is **specification-only** — no source code yet. Phase 1 implementation has not been authorized. The 33 artifacts here are the locked foundation produced from two design sessions on 2026-05-09.

## Hard rules (do not violate)

1. **HARD CONSENT GATE — private until explicit per-action consent.** This repo stays private on internal Gitea (`git.int.korlogos.com:8084`). Do **NOT** push to GitHub.com, public registries, mirrors, or any third-party host. Each visibility-changing action requires explicit project-lead consent in the same conversation. Past consent does not extend to new actions. See `~/.claude/projects/-home-jcarlson-projects-ff6k/memory/ff6k-consent-gate.md`.

2. **Do not modify locked artifacts** without an explicit session for that purpose. Locked: all 10 ADRs (`docs/adr/ADR-001..010`), `docs/SPEC.md`, `docs/positioning.md`, all 3 schemas (`schemas/`), `docs/issues-backlog.md`. These are the consensus output of the spec phase; silent edits destroy it.

3. **Do not begin Phase 1 implementation** (Python source, collectors, engine code) until the project lead authorizes. Sessions B-H come first.

4. **Do not select a public name.** Session H is reserved for that. Continue using `FF6K` in all working artifacts. Do not invent.

5. **Do not add dependencies, frameworks, or architectural choices** beyond what the ADRs specify. If you encounter a decision the ADRs don't cover, ask the project lead.

6. **DCO sign-off required** on every commit (`git commit -s ...`).

## Pending (do not pre-empt)

- **Public name** — Session H
- **`docs/problem-statement.md`** — currently a scaffold awaiting the project lead's researcher-journey framing
- **Sessions B-G** — competitive analysis, module specs, AI-leverage roadmap, framework annotation, SDLP, Federal Customer Deployment Guide. The project lead drives these conversations with Claude in chat; resulting artifacts come here for integration.
- **Mechanical rename pass** propagating the post-Session-H public name across all artifacts. Do not pre-empt — the README/SECURITY/CONTRIBUTING currently still reference `github.com/korlogos/fatfinger6000` URLs, which are wrong but intentionally left for the rename pass.

## Project facts

| Item | Value |
|---|---|
| Codename | `FF6K` (do not change) |
| Gitea repo | `pitt-street-labs/ff6k` (private) |
| Gitea URL | https://git.int.korlogos.com:8084/pitt-street-labs/ff6k |
| Issue tracker | Gitea Issues at the repo above (34 issues filed across 4 milestones) |
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
| Original handoff briefing | `HANDOFF.md` (un-tracked; session artifact) |
| Init script (already executed) | `init-and-push-to-gitea.sh` |

## Issue tracker conventions

- 34 issues, 7 epics, 4 milestones (Phase 1, Phase 2, Phase 3, Ongoing). Issue 1 = Active scanner egress; issue 34 = ETHICS.md maintenance.
- Labels follow `epic:<slug>`, `area:<slug>`, `priority:<level>`, `type:<kind>`, plus `v1` for v1 deliverables (4 issues).
- Reference issues by number in commits: `Closes #N` or `Refs #N`.
- New work discovered during a session → file an issue immediately (Tier 3, pre-authorized) rather than letting it slip.

## Tier classification for FF6K work

Following `~/CLAUDE.md` change control:

- **Tier 1 (lab infra approval):** Pushing to Gitea is normally Tier 1, but for this repo specifically the project lead has pre-authorized push-after-commit (the init script ran with consent). Net-new infrastructure outside this repo (e.g., deploying FF6K services to Node1/Node2) remains Tier 1.
- **Tier 2 (z590 ops, impact table required):** Local builds, container experiments, schema validation tooling that touches z590 state.
- **Tier 3 (pre-authorized):** Documentation edits, issue management, project bookkeeping inside this repo (excluding locked artifacts), updates to this CLAUDE.md, memory updates.

## Lessons / facts to preserve

- The init script's default `ssh://...:8084/jcarlson/...` URL was wrong on two counts (port 8084 is Gitea HTTPS, not SSH; and the lab namespace is `pitt-street-labs/`, not `jcarlson/`). The committed script reflects the corrected HTTPS+token form.
- Multi-arch image builds (issue #3) and Cloud object storage migration (#9) had their milestones patched after creation — the importer's title-match for milestone assignment didn't account for parenthetical title suffixes.
- Default git identity for commits in this repo is `Enema Combatant <enema-combatant@users.noreply.github.com>` (lab convention across all PSL repos), even though the project lead's persona is "jcarlson" / Jeffro.

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
