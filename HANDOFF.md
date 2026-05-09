# FF6K — Handoff to Claude Code

**You are Claude Code. The project lead has handed off the FF6K specification phase to you for local establishment.**

This document is your briefing. Read it fully before taking any action. It tells you what the project is, what decisions are locked, what your immediate task is, and what to do after the handoff is complete.

---

## What you are looking at

This package contains the complete specification phase output for **FF6K** — a project being developed by Korlogos / Pitt Street Labs. The project lead is Jeffro (handle: `jcarlson`). The work was produced across two design conversations on 2026-05-09 and represents the foundation for an open-source External Attack Surface Intelligence (EASI) platform with a federal-customer trajectory.

**FF6K is a working codename**, shortened from the original "FatFinger6000". The public name has not yet been selected; that is Session H, deferred. Continue using FF6K in all working artifacts. Do not invent a public name yourself.

The package contains:

```
ff6k-handoff/
├── HANDOFF.md                    ← you are reading this
└── ff6k-repo/                    the canonical specification tree
    ├── INVENTORY.md              manifest of all artifacts
    ├── README.md, LICENSE, etc.  governance documents
    ├── docs/
    │   ├── SPEC.md               comprehensive specification
    │   ├── positioning.md        strategic positioning
    │   ├── problem-statement.md  scaffold (awaiting fill from project lead)
    │   ├── HISTORY.md            codename lineage
    │   ├── glossary.md           term definitions
    │   ├── issues-backlog.md     34 issues across 7 epics
    │   ├── adr/                  10 Architecture Decision Records
    │   └── deferred-issues/      6 per-decision deferred backlogs
    ├── schemas/                  3 JSON Schema files (Draft 2020-12)
    ├── examples/rulepacks/       working example rule pack
    └── init-and-push-to-gitea.sh script to initialize the repo
```

---

## What FF6K is

**A continuous, attributed, cryptographically signed external attack surface intelligence platform with an open-source engine and proprietary commercial modules.** Read `ff6k-repo/docs/positioning.md` for the full positioning. Key decisions:

- **MITRE ATT&CK anchor:** Reconnaissance (TA0043) only for the open-source Core. Resource Development (TA0042) is a commercial module concern.
- **Two-environment design:** Environment 1 (this codebase) is the deterministic engine producing signed JSON graph artifacts. Environment 2 (out of scope) consumes those artifacts for downstream LLM-driven analysis under appropriate safeguards.
- **Commercial structure:** Open-core. FF6K Core (Apache 2.0) plus three proprietary modules (Threat Context, Identity Surface) plus a research dataset offering (CC BY 4.0). See ADR-009.
- **FedRAMP-ready posture:** Architecturally ready in v1 with FIPS 140-3 validated cryptography and NIST 800-53 control alignment. Authorization-deferred for the open-source engine; authorization-targeted for a future commercial managed-service offering. See ADR-010.

---

## What is locked vs. pending

**Locked (do not relitigate without project lead approval):**

- All 10 ADRs (`ff6k-repo/docs/adr/`)
- Strategic positioning (`ff6k-repo/docs/positioning.md`)
- Pipeline architecture, threat model, observation graph schema, collector framework, sanitization model, attribution engine design, LLM provider abstraction, artifact format, phased build plan (all in `ff6k-repo/docs/SPEC.md`)
- All three JSON Schemas (`ff6k-repo/schemas/`)
- 34-issue consolidated backlog across 7 epics (`ff6k-repo/docs/issues-backlog.md`)

**Pending (you will likely encounter these as you work):**

- Public name selection — internal codename FF6K stays in active use
- Problem statement narrative — scaffold is in place at `ff6k-repo/docs/problem-statement.md` awaiting the project lead's researcher-journey framing
- Six subsequent design sessions queued (B competitive analysis, C module specifications, D novel AI-leverage roadmap, E framework annotation, F SDLP, G Federal Customer Deployment Guide)

---

## Your immediate task: establish the project locally

The project lead expects you to:

1. **Read the artifacts thoroughly.** Start with `ff6k-repo/INVENTORY.md`, then `ff6k-repo/docs/positioning.md`, then `ff6k-repo/docs/SPEC.md`, then the ADRs in numerical order. Do not skip ADRs — each contains decisions you will need to respect during implementation.

2. **Validate the JSON Schemas parse correctly.** Run something equivalent to:
   ```bash
   for f in ff6k-repo/schemas/*.json ff6k-repo/examples/rulepacks/*.json; do
       python3 -c "import json; json.load(open('$f'))" && echo "OK: $f" || echo "FAIL: $f"
   done
   ```
   All four files should parse. If any fail, stop and surface the error to the project lead.

3. **Initialize the local git repository and push to Gitea.** The init script is at `ff6k-repo/init-and-push-to-gitea.sh`. Before running it:
   - **Verify the GITEA_REMOTE_URL** at the top of the script. The default is `ssh://git@git.int.korlogos.com:8084/jcarlson/ff6k.git`. Adjust if the project lead's Gitea path is different. The project lead's working memory indicates `git.int.korlogos.com:8084` as the Gitea host.
   - **Check that the empty repository exists on Gitea.** The script does not create the repository for you — it pushes to an existing empty repo. The project lead may need to create `jcarlson/ff6k` (or whatever path) on the Gitea web UI first. Surface this requirement before running the script.

4. **Verify the push.** After the script runs, confirm with the project lead that the Gitea repo shows the expected three commits:
   - `Initial specification: foundation architecture and governance`
   - `Strategic foundation: positioning, commercial structure, FedRAMP posture`
   - `Add inventory of specification phase artifacts`

5. **Acknowledge completion to the project lead.** Summarize what you established, what's pending, and what you suggest as next steps.

---

## What you should NOT do without project lead approval

- **Do not push to GitHub.com.** The consent gate is in force. All artifacts stay on Gitea. The project lead has been explicit about this multiple times.
- **Do not begin implementation work** (writing Python source code, building the engine, implementing collectors). The project lead has not authorized Phase 1 implementation yet. Establishing the repository is the immediate task; implementation follows after the project lead reviews and gives the green light.
- **Do not select a public name.** Session H is reserved for that decision and is the project lead's call.
- **Do not add new dependencies, frameworks, or architectural choices** beyond what the ADRs specify. If you encounter a decision the ADRs don't cover, surface it to the project lead rather than choosing yourself.
- **Do not modify the JSON Schemas, the SPEC, or any ADR** as part of repository establishment. These are locked artifacts. Modifications happen through deliberate session work with the project lead.
- **Do not invent additional structural changes** to the repo layout. The structure as delivered is intentional.

---

## What you should do as you work

- **Use the project lead's voice and conventions.** The project lead's GitHub handle is `jcarlson`. The Korlogos project conventions are documented in `ff6k-repo/CONTRIBUTING.md` (DCO sign-off required for all commits — the init script already adds `-s` flags).
- **Surface uncertainties early.** If you are unsure about a step, ask before acting. Recoverable mistakes are easy if surfaced early; silent assumptions compound.
- **Preserve the working codename FF6K.** When in doubt about how to refer to the project, use FF6K.
- **Maintain the consent gate posture.** The project lead has been deliberate about not pushing to public infrastructure. If anything you do would result in artifacts on third-party hosts (GitHub, GitLab, Bitbucket, public package registries, public container registries, public CDNs), pause and confirm with the project lead first.

---

## Subsequent work

Once the repository is established on Gitea, the project lead has a queue of design sessions to work through with Claude (the chat instance) before implementation begins:

| Session | Deliverable | Recommended order |
|---|---|---|
| H | Public name selection | First — clears the codename overhang |
| B | Competitive analysis | Second — informs marketing |
| E | Framework annotation deep-dive | Third — informs SDLP and deployment guide |
| C | Module specifications (Threat Context, Identity Surface) | Parallel after E |
| D | Novel AI-leverage roadmap | Parallel after E |
| F | Secure Development Lifecycle Plan | Parallel after E |
| G | Federal Customer Deployment Guide | Parallel after E |

Your role in those sessions is generally to **read, advise, and execute** on the project lead's behalf. The project lead drives the design conversations with Claude in chat; the resulting artifacts come to you for integration into the repo.

After Session H names the project, the rename pass mechanically propagates the public name across all artifacts. That is a deliberate session you will execute when the project lead authorizes it.

After Session G's Federal Customer Deployment Guide is produced, Phase 1 implementation can begin. The Phase 1 plan is in `ff6k-repo/docs/SPEC.md` §11.1 and the issue backlog in `ff6k-repo/docs/issues-backlog.md`. Implementation work should respect the locked architectural decisions, particularly:

- Python with Pydantic v2, FastAPI, asyncio (ADR-001)
- Postgres with normalized graph schema (ADR-002)
- Containerized deployment with Helm (ADR-003)
- Signed JSON file as sole deliverable (ADR-004)
- Multi-provider LLM abstraction with safety wrapper (ADR-005)
- Apache 2.0 + DCO + private rule packs (ADR-006)
- Logical multi-tenancy from day one (ADR-007)
- Medium scope-enforcement default (ADR-008)
- Open-core with separate commercial repos (ADR-009)
- FIPS-validated crypto everywhere (ADR-010)

---

## Reference: the project lead's standing context

For context that may help you serve the project lead well:

- **Korlogos** is the brand under which Jeffro operates at Pitt Street Labs in eastern North Carolina. The brand spans cloud cybersecurity architecture, AI security frameworks, SaaS identity, certificate security, IoT/smart-city threat modeling, and municipal cybersecurity engagements.
- **ARC** is Jeffro's home lab umbrella project (Assisted Reconstitution of Civilization). FF6K is a Korlogos commercial-trajectory project that runs on ARC infrastructure for v1 lab deployment but is intended for portability beyond ARC.
- **Active client work** mentioned in conversations included NYC DOT vendor assessments and Koi endpoint security deployments. These are not directly relevant to FF6K work but give context about Jeffro's professional landscape.
- **Mythos** refers to Anthropic's frontier model with cybersecurity capabilities, accessible via Project Glasswing. FF6K's Environment 2 architecture anticipates Mythos-class downstream consumption — but Mythos integration is not in FF6K Core's scope. The two-environment separation is deliberate.

The above is background context, not action items. It helps you understand why the project lead frames things the way they do.

---

## Acknowledging this handoff

When you have read this document fully and are ready to proceed, your acknowledgment to the project lead should look something like:

> "I've read HANDOFF.md and the artifact inventory. I understand the project is FF6K (working codename, public name TBD), an open-core EASI platform anchored in MITRE ATT&CK Reconnaissance (TA0043), with FedRAMP-ready architecture and a two-environment design. The 10 ADRs and SPEC.md are locked. My immediate task is to validate the schemas, initialize the local git repo, push to Gitea at `git.int.korlogos.com:8084/jcarlson/ff6k.git` (or the path you specify), and confirm the push landed. I will not push to GitHub, will not begin implementation, and will not modify locked artifacts. Should I proceed with validation and repo establishment?"

That gives the project lead a chance to correct any misunderstandings before you take action. If the project lead confirms, proceed.

---

## One last thing

The project lead has been deliberate, careful, and increasingly confident in the design decisions across these sessions. They have also been explicit about the consent gate, about respecting their researcher-journey framing, and about the strategic constraints (FedRAMP, open-source posture, federal trajectory). Match their care. The work is solid; your job is to establish it without breaking what was built.

Welcome to FF6K.
