# EXPOSE — Critical Path to Public Launch

**Status:** Advisory — not locked. Open for revision in subsequent sessions.
**Date:** 2026-05-10
**Author context:** AI-assisted synthesis from the locked spec-phase artifacts plus the Session H naming decision. Produced in response to a project-lead request for a critical-path analysis.

This document analyses the dependency chain from current state (specification complete, Session H rename complete, no implementation) to a public open-source launch of EXPOSE Core. It defines what "launch" means, identifies the critical path, projects calendar timing under three risk scenarios, names schedule risks in priority order, and recommends a staged-launch approach.

This is advisory. It does not lock decisions about timing, sequencing, or staging. Treat it as input to subsequent project-management decisions.

---

## Defining "launch"

Four candidate launches with very different dates:

| Launch type | Definition | Earliest realistic |
|---|---|---|
| **A. Internal lab launch** | v1 dogfood on ARC, signed JSON artifact end-to-end, no public visibility | ~14 weeks |
| **B. Federal-customer pilot** | A specific federal agency runs EXPOSE Core inside their ATO, gives feedback | Lab launch + 4-6 weeks |
| **C. Public OSS launch** | EXPOSE Core published to GitHub.com under Apache 2.0, public discoverability, community engagement opens | Lab launch + 6 weeks (with all gates met) |
| **D. Commercial managed-service launch** | Korlogos-hosted SaaS, FedRAMP-targeted, paid customers | Public launch + 12-24 months (major business decision per ADR-010) |

**This document targets (C) Public OSS launch** as the primary inflection point. It is the launch that opens federal sales, community engagement, and research adoption in parallel. Lab launch (A) and federal pilot (B) are stages on the way; commercial managed-service (D) is a much later business milestone per ADR-010.

---

## The critical path (longest dependent chain)

| # | Step | Duration | Depends on | Owner |
|---|---|---|---|---|
| 1 | **Session E** — framework annotation deep-dive (MITRE ATT&CK, NIST CSF, NIST 800-53, OWASP, CIS) | 2 weeks | — (can start now) | Drafted in Claude Code; project lead reviews |
| 2 | **Session F + G** — SDLP and Federal Customer Deployment Guide | 4 weeks | Session E (provides control mapping) | Drafted in Claude Code; project lead reviews |
| 3 | **Phase 1 implementation** — Sprints 1-8 per SPEC.md §11.1 | 10 weeks (realistic) | Session F (SDLP) ideally informs Sprint 1-2 design; can overlap Sprint 1-2 | Engineering |
| 4 | **Internal lab validation** — end-to-end smoke + tenant-isolation regression + signed-artifact verification | 2 weeks | Phase 1 complete | Korlogos lab operations |
| 5 | **Pre-publication review** — security audit, doc polish, consent-gate sign-off | 2 weeks | Lab validation passes | Project lead + advisors |
| 6 | **Public launch event** — GitHub publish, blog post, federal-buyer announcement, conference talk submissions | 1 week | All above | Project lead |
| | **Critical path total** | **21 weeks** | | |

---

## Parallel work tracks (off the critical path if executed cleanly)

| Track | Duration | Notes |
|---|---|---|
| Session B (competitive analysis) | 2 weeks | Runs alongside E with no dependency |
| Sessions C, D (claude.ai chat) | 4-6 weeks | Project lead drives; integration here |
| Problem statement narrative | indeterminate | Project lead authored; should land before pre-publication review |
| Trademark search USPTO classes 9/38/42 | 2 weeks (legal) | Runs during Phase 1 implementation; must clear before public launch |
| Domain registration (`expose.security`, `.tools`, variants) | 1 day | After trademark clears |
| GitHub org reservation (`pitt-street-labs/expose`) | 1 day | Pre-publication action, single consent-gate event |
| Phase 2 LLM enrichment | 6 weeks | Ships in v1.1, **not on v1 critical path** |
| Phase 3 production-hardening items | Concurrent | Most ship post-launch |

---

## Calendar projection from 2026-05-10

| Scenario | Public launch ETA | Assumptions |
|---|---|---|
| **Aggressive** | Mid-September 2026 (~18 weeks / 4 mo) | Sessions B/E run weekly, Phase 1 starts week 3 in parallel with F (Sprint 1-2 mostly skeleton, independent of SDLP details), no implementation surprises, trademark clears clean |
| **Realistic** | Mid-October 2026 (~21 weeks / 5 mo) | Sequential session pacing, Phase 1 takes the full 10 weeks, no surprises |
| **Risk-adjusted** | December 2026 – February 2027 (~7-9 mo) | Trademark conflict surfaces; Phase 1 runs 12-14 weeks (typical first-iteration drift); Session G needs sponsoring-agency input that takes scheduling time; Korlogos has concurrent client commitments |

---

## Schedule risks (priority order)

1. **Phase 1 implementation duration estimate is optimistic.** SPEC.md §11.1's 8-10 weeks is reasonable but historically first-cut estimates underrun by 25-50%. The orchestration framework decision (issue #36) is locked into Sprint 3 — if it gets revisited mid-implementation, that's another 2 weeks.
2. **Session G (Federal Customer Deployment Guide) needs federal-side input.** The control-mapping work in ADR-010 is preliminary; making it concrete and defensible likely needs at least one sponsoring-agency conversation. Scheduling that conversation is outside the project lead's direct control.
3. **Trademark search may surface conflicts.** Preliminary EASM check was clean (Session H, 2026-05-10), but USPTO across all relevant security classes (9, 38, 42) is a different exercise. Worst case: rebrand needed. Mitigation: start the search in week 1, not week 12.
4. **Implementation has not been authorized at time of writing (2026-05-10).** Critical path assumes Phase 1 starts after Session F (week 3). If authorization is deferred or staged, every week of delay extends the launch by a week.
5. **Concurrent Korlogos commitments.** Other client work (a municipal agency, an endpoint vendor, ARC operations, lab infrastructure) competes for project-lead bandwidth. Sessions C and D in particular need synchronous attention.

---

## Acceleration levers (in increasing aggressiveness)

| Lever | Time saved | Risk added |
|---|---|---|
| Run Session B in parallel with E (no dependency) | 2 weeks | None |
| Start Phase 1 Sprint 1-2 (foundation, container builds, schema, isolation tests) **immediately** in parallel with Sessions B/E | 2-3 weeks | Some Sprint 1-2 work might need rework if F/G surface SDLP requirements affecting Postgres schema or container hardening |
| Start trademark search in week 1 instead of waiting for Phase 1 | 2 weeks at end | None |
| Stage launch: lab → federal pilot → public OSS (instead of big-bang) | Spreads risk; "launch" date later but each stage less catastrophic if it goes wrong | Marketing complexity |
| Hire / contract a second engineer for Phase 1 | 3-4 weeks | Onboarding cost; coordination overhead |
| Defer Session D (AI-leverage roadmap) to post-launch | 2-4 weeks (if it was on critical path) | Misses the AI-leverage moat for launch positioning; competitors notice |
| Reduce Phase 1 collector matrix from "all v1 collectors" to "minimum viable set" (CT logs + AWS IP ranges + active DNS only) | 2-3 weeks | v1 is less demonstrably functional; reference clients have less to work with |

---

## Recommendation: stage the launch

Targeting one big-bang public launch in 5 months is high-risk with high downside if anything slips. Instead, stage:

| Stage | Target | Calendar (from 2026-05-10) |
|---|---|---|
| **Stage 1 — Internal lab v1** | EXPOSE Core running on ARC, dogfooded against Korlogos's own perimeter | Weeks 12-14 (mid-August 2026) |
| **Stage 2 — Trusted-partner pilot** | 1-2 selected federal-adjacent or partner orgs run EXPOSE within their boundary, give feedback. Not yet on GitHub. | Weeks 16-20 (September 2026) |
| **Stage 3 — Public OSS launch** | GitHub.com publish, blog, RSA / DEF CON talk submissions, federal-buyer announcements | Weeks 22-26 (October–November 2026) |

Each stage gates the next: lab launch validates the engine, pilot launch validates the federal-deployment story (and produces reference customers for the public launch narrative), public launch consolidates community and federal sales credibility.

---

## Critical near-term actions

1. **Authorize Phase 1 Sprint 1-2 now** — the foundation work (project skeleton, Postgres schema, container builds, isolation tests) is independent of B/E/F/G design decisions. Parking implementation until "after all sessions" extends the critical path by 4-6 weeks unnecessarily.
2. **Start trademark search this week** — 2-week legal cycle, can run entirely in parallel with everything else.
3. **Begin scheduling the sponsoring-agency conversation for Session G** — this conversation is outside your direct control to schedule fast, so start asking now.
4. **Author Session B and E drafts in Claude Code over the next 1-2 weeks** — informs F, G, and Phase 1 directly.
5. **Park the Gitea repo rename** (`pitt-street-labs/ff6k` → `expose`) until immediately before public launch — adds friction now for trivial value before launch.

---

## Decision points for the project lead

- **Validate the launch target.** Is (C) Public OSS launch the right target, or do you prefer to optimize for (B) federal-customer pilot first?
- **Validate the staged approach.** Or commit to a single big-bang launch with appropriate risk acceptance.
- **Authorize Phase 1 Sprint 1-2 to begin now in parallel with Sessions B/E.** This is the highest-value acceleration lever.
- **Decide trademark search timing.** Recommend week 1; alternatives are week 4 (after some session output validates the EXPOSE name in context) or week 10 (just before pre-publication review — risky).
- **Decide whether to schedule a sponsoring-agency conversation for Session G now.** If yes, the framing of "EXPOSE FedRAMP-ready posture, available for self-host within ATO, evaluating for managed-service eventual offering" is the opening pitch.

---

## Related artifacts

- `docs/SPEC.md` §11 — phased build plan (source for Phase 1 Sprint structure)
- `docs/strategy/persona-analysis.md` — three-persona strategy (informs which sessions land first)
- `docs/adr/ADR-010-fedramp-ready-posture.md` — federal-deployment context for Session G
- `docs/positioning.md` §7 — subsequent work streams enabled by positioning
- HANDOFF.md — original session brief naming Sessions B-H
- Issue #36 — orchestration framework decision (Sprint 3 critical-path item)
- Issue #37 — persona-analysis follow-ups
- Issue #38 — Session H closed-with-resolution
