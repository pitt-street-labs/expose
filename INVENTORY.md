# FF6K Repository — Artifact Inventory

**Working codename:** FF6K (public name TBD per Session H)
**Internal Gitea:** `git.int.korlogos.com:8084` (target)
**Generated:** 2026-05-09

This document inventories every artifact produced across the specification phase. The repository structure is organized for clean import to internal Gitea and eventual public migration once the public name is selected.

## Repository structure

```
ff6k-repo/                                    (33 files, 408 KB)
├── .gitignore                                Python project gitignore
├── LICENSE                                   Apache 2.0 pointer
├── README.md                                 Project overview
├── SECURITY.md                               Disclosure policy
├── ETHICS.md                                 Intended use and non-goals (v1 deliverable)
├── CONTRIBUTING.md                           Contribution guide (DCO required)
├── CODE_OF_CONDUCT.md                        Contributor Covenant 2.1 + addenda
├── docs/
│   ├── SPEC.md                               Comprehensive specification (~30 KB)
│   ├── positioning.md                        Strategic positioning
│   ├── problem-statement.md                  Researcher-journey scaffold (awaiting fill)
│   ├── HISTORY.md                            Codename lineage and project history
│   ├── glossary.md                           Term definitions
│   ├── issues-backlog.md                     Consolidated 34 issues across 7 epics
│   ├── adr/                                  10 Architecture Decision Records
│   │   ├── ADR-001-implementation-language.md
│   │   ├── ADR-002-graph-storage.md
│   │   ├── ADR-003-deployment-posture.md
│   │   ├── ADR-004-output-artifact.md
│   │   ├── ADR-005-llm-integration.md
│   │   ├── ADR-006-repository-and-licensing.md
│   │   ├── ADR-007-multi-tenancy.md
│   │   ├── ADR-008-authorized-use-and-ethics.md
│   │   ├── ADR-009-commercial-structure.md
│   │   └── ADR-010-fedramp-ready-posture.md
│   └── deferred-issues/                      Per-decision deferred backlogs
│       ├── deferred-issues-decision-03.md
│       ├── deferred-issues-decision-04.md
│       ├── deferred-issues-decision-04-revisited.md
│       ├── deferred-issues-decision-05.md
│       ├── deferred-issues-decision-06.md
│       └── deferred-issues-decision-07.md
├── schemas/                                  JSON Schema files (Draft 2020-12)
│   ├── canonical-artifact-v1.json            Sole deliverable schema
│   ├── manifest-v1.json                      Run manifest schema
│   └── rulepack-v1.json                      Declarative rule pack schema
└── examples/
    └── rulepacks/
        └── example-baseline.json             Working example rule pack
```

## Coverage matrix — what is locked vs. pending

| Area | Status | Document |
|---|---|---|
| Implementation language | Locked | ADR-001 (Python) |
| Graph storage | Locked | ADR-002 (Postgres normalized schema) |
| Deployment posture | Locked | ADR-003 (containerized, Helm, ARC v1) |
| Output artifact format | Locked | ADR-004 (signed JSON file) |
| LLM integration | Locked | ADR-005 (multi-provider + Ollama) |
| Repository and licensing | Locked | ADR-006 (Apache 2.0 engine + private rule packs) |
| Multi-tenancy | Locked | ADR-007 (logical from day one) |
| Authorized use and ethics | Locked | ADR-008 (medium scope default) |
| Commercial structure | Locked | ADR-009 (open-core + 3 commercial modules + research) |
| FedRAMP-ready posture | Locked | ADR-010 (architecturally ready, authorization-deferred) |
| Strategic positioning | Locked | positioning.md |
| MITRE ATT&CK anchor | Locked | positioning.md (TA0043 Reconnaissance) |
| Pipeline architecture | Locked | SPEC.md §2 |
| Threat model | Locked | SPEC.md §3 |
| Observation graph schema | Locked | SPEC.md §5 + canonical-artifact-v1.json |
| Collector framework | Locked | SPEC.md §6 |
| Sanitization | Locked | SPEC.md §7 |
| Attribution engine | Locked | SPEC.md §8 + rulepack-v1.json |
| Artifact generation | Locked | SPEC.md §9 |
| Operations | Locked | SPEC.md §10 |
| Phased build plan | Locked | SPEC.md §11 |
| Issue backlog | Locked | issues-backlog.md (34 issues, 7 epics) |
| Public name | **Pending** | Session H |
| Problem statement narrative | **Pending** | problem-statement.md (scaffold ready) |
| Competitive analysis (deeper) | **Pending** | Session B |
| Module specifications (Threat Context, Identity Surface) | **Pending** | Session C |
| Novel AI-leverage roadmap | **Pending** | Session D |
| Framework annotation deep-dive | **Pending** | Session E |
| Secure Development Lifecycle Plan | **Pending** | Session F |
| Federal Customer Deployment Guide | **Pending** | Session G |

## Conversation lineage

This repository is the consolidated output of two design conversations on 2026-05-09:

**Specification design session.** Eight architectural decisions, comprehensive SPEC.md, three JSON Schema files, example rule pack, glossary, governance documents, six per-decision deferred-issues backlogs.

**Strategic foundation session.** Two additional ADRs (commercial structure, FedRAMP-ready posture), positioning document, problem statement scaffold, HISTORY.md.

The conversation thread title is "FF6K - Primary Dev Convo" per the project lead's working naming convention.

## Decisions and assumptions captured but not in artifacts

A few things we discussed that are not currently captured as separate artifacts but inform the work:

- **Open questions noted in SPEC.md §12** — orchestration framework choice (Temporal vs. Celery vs. NATS), graph engine upgrade path, scanner egress for ARC, eval dataset curation, tenant onboarding UX, Mythos integration coordination
- **Naming history** captured in HISTORY.md — Heliograph, PERIM, EASI all evaluated and rejected with rationale documented
- **Federal procurement framing** — captured in positioning.md §4 and ADR-010

## Status flags

**Consent gate:** This repository is targeted for **internal Gitea on ARC** (`git.int.korlogos.com:8084`). It is **NOT** authorized for publication to GitHub.com or any public host. The public publication consent gate remains in force. Public publication requires explicit lead authorization and at minimum: public name selection (Session H), problem statement population, and a deliberate review pass.

**Naming:** All artifacts use the working codename **FF6K** (shortened from FatFinger6000). Public name selection is deferred to Session H. A mechanical rename pass will propagate the public name across all artifacts before public publication.

**Build state:** This is specification-only. No source code has been written. Phase 1 implementation (per SPEC.md §11.1) has not begun.

## Subsequent session queue

Per the parallelization plan locked in the strategic foundation session:

| Session | Deliverable |
|---|---|
| H | Public name selection |
| B | Competitive analysis (SpiderFoot HX, Mandiant ASM, Censys ASM, Microsoft Defender EASM, others) |
| C | Module specifications (Threat Context, Identity Surface) |
| D | Novel AI-leverage roadmap |
| E | Framework annotation deep-dive |
| F | Secure Development Lifecycle Plan |
| G | Federal Customer Deployment Guide |

Sessions can run in parallel for agent-team execution against the locked foundation. Recommended sequencing if doing them one at a time: H first (clears the codename overhang), then B (informs marketing), then E (informs SDLP and deployment guide), then C/D/F/G in parallel.
