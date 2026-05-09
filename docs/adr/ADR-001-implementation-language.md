# ADR-001: Implementation language

**Status:** Accepted
**Date:** 2026-05-09
**Decision-makers:** Korlogos / Pitt Street Labs

## Context

FatFinger6000 is an external attack surface intelligence pipeline with three workload types: API-bound collectors with high I/O concurrency, an attribution engine that's mostly graph traversal and rule evaluation, and an LLM enrichment layer that's bounded structured-output calls. The choice of implementation language affects collector ergonomics, LLM SDK maturity, deployment artifact, type-safety guarantees, and the realistic pace of contribution from external developers.

Four practical options were considered: Python, Go, TypeScript/Node, and Rust.

## Decision

**Python** is the implementation language for FatFinger6000. Specific stack:

- **Pydantic v2** for type-safe data modeling. Schemas are central to the project; Pydantic gives validated, JSON-Schema-compatible types as a first-class concern.
- **FastAPI** for HTTP surfaces (admin API, future delivery API in production-hardening).
- **asyncio with httpx** for collector concurrency. Collectors are I/O-bound; asyncio handles fan-out scanning at the volumes v1 needs.
- **Anthropic, OpenAI, Google Gemini SDKs** for LLM provider implementations. Python is the most mature ecosystem for all three.
- **Postgres via asyncpg or psycopg3** for the data layer.
- **Alembic** for schema migrations.

Orchestration framework (Temporal vs. Celery vs. simpler alternatives) is deferred. Spec is written generically against work-queue semantics; concrete choice deferred to Phase 1 implementation when real throughput requirements are clearer.

## Consequences

**Positive:**

- Pydantic provides the typed schemas the spec leans on heavily. The canonical artifact schema, rule pack schema, and observation graph entities all benefit from Pydantic's validation, serialization, and JSON Schema generation.
- The Anthropic Python SDK is the reference implementation. OpenAI and Gemini Python SDKs are similarly mature. Local Ollama integration via httpx is straightforward.
- Security tooling ecosystem in Python is unmatched: dnspython, cryptography, Censys/Shodan SDKs, certstream clients.
- Existing ARC infrastructure runs Python services; FatFinger6000 slots into operational patterns the team already knows.
- External contribution friction is low — Python is the most common language for security tooling.

**Negative:**

- The GIL means CPU-bound work needs multiprocessing or external workers. This is mitigated by the workload being I/O-bound for collectors and offloaded to LLM workers for enrichment.
- Dependency management is still annoying despite uv/poetry/Pipfile improvements. We'll standardize on uv for reproducible builds.
- At very high collector concurrency (10k+ concurrent connections) Python's asyncio shows its limits. Realistic v1 volumes are well below that.
- Type checking is opt-in (mypy/pyright) and not enforced by the language. CI will gate on strict type checking to compensate.

## Alternatives considered

**Go** offered better collector concurrency (goroutines beat asyncio for fan-out) and cleaner deployment (single static binary). Rejected because the LLM iteration story is poorer in Go (SDKs less mature, structured output handling more verbose), the security tooling ecosystem is thinner, and the LLM correlation layer is the layer most likely to change rapidly during early iteration.

**TypeScript/Node** would only have made sense if a unified web UI stack was a goal. Pydantic-equivalent (Zod) is good but not as deeply integrated into ecosystem tooling. The ergonomics of long-running batch jobs in Node are worse than Python.

**Rust** was deferred as overkill for v1. The combination of strict typing, fearless concurrency, and binary distribution is genuinely attractive for security tooling, but the LLM iteration story is poorest here and the security-tooling ecosystem is thinnest. Worth revisiting for a Phase 4+ rewrite of hot paths if profiling identifies them.

## References

- Decision recorded in design conversation 2026-05-09.
- Issue tracking orchestration framework selection: see `docs/issues-backlog.md` under deployment-portability epic.
