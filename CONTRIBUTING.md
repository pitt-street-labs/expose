# Contributing to EXPOSE

Thanks for your interest in contributing to EXPOSE. This project is open source under Apache 2.0 and welcomes contributions from the community -- bug fixes, new collectors, documentation improvements, test coverage, and more.

Before diving in, please read:

- **[README.md](README.md)** -- project overview and quick start.
- **[docs/SPEC.md](docs/SPEC.md)** -- comprehensive specification.
- **[ETHICS.md](ETHICS.md)** -- intended use and non-goals. Some contribution categories are explicitly out of scope.
- **[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)** -- community standards.
- **[SECURITY.md](SECURITY.md)** -- vulnerability reporting (do not open public issues for security vulnerabilities).

## Development setup

EXPOSE uses [uv](https://docs.astral.sh/uv/) for dependency management and virtual environment setup.

```bash
git clone https://github.com/pitt-street-labs/expose.git
cd expose

# Install uv if you don't have it
pip install uv

# Install all dependencies (including dev and test extras)
uv sync --all-extras

# Run the test suite (3500+ tests)
uv run pytest

# Run type checking
uv run mypy src/

# Run linter and formatter checks
uv run ruff check src/
uv run ruff format --check src/
```

For containerized integration testing (requires Docker):

```bash
docker compose -f deploy/dev/docker-compose.yml up -d
uv run pytest tests/integration/
```

For Helm chart development (requires k3d and Helm):

```bash
k3d cluster create expose-dev
helm install expose ./deploy/helm-chart \
    --values deploy/dev/local-values.yaml \
    --namespace expose --create-namespace
```

## Code quality

The project enforces strict code quality standards through CI and pre-commit hooks.

**Linting and formatting.** [Ruff](https://docs.astral.sh/ruff/) handles both linting and formatting. Run `uv run ruff check src/` and `uv run ruff format --check src/` before committing.

**Type checking.** [mypy](https://mypy-lang.org/) runs in strict mode. All public functions require type annotations. Run `uv run mypy src/` to check.

**Testing.** [pytest](https://docs.pytest.org/) with `pytest-asyncio` for async tests. All external HTTP calls must be mocked with [respx](https://lundberg.github.io/respx/) -- no live network calls in the test suite. Database tests use testcontainers for real Postgres instances in CI and aiosqlite for fast local runs.

**FIPS crypto gate.** The test suite includes a banned-import scanner (`tests/test_fips_crypto_gate.py`) that blocks direct use of `hashlib`, `secrets`, or `pycryptodome` in the `src/expose/` tree. All cryptographic operations must go through the FIPS adapter at `src/expose/crypto/fips_adapter.py`, which uses the `cryptography` library in FIPS mode (per ADR-010). CI enforces this gate on every PR.

**Pre-commit hooks.** The repository includes a `.pre-commit-config.yaml` with ruff, gitleaks (secret scanning), JSON Schema validation, and Helm lint. Install hooks with:

```bash
uv run pre-commit install
```

## Writing a new collector

Collectors are the primary extension point in EXPOSE. Each collector queries a specific data source and yields `Observation` records into the pipeline. The existing builtin collectors in `src/expose/collectors/builtin/` are the best reference -- study `ct_crtsh.py` or `cloud_ranges.py` before writing your own.

### Step 1: Create the collector module

Create a new file at `src/expose/collectors/builtin/your_collector.py`. Every collector must:

- Subclass `Collector` from `expose.collectors.base`
- Use the `@register_collector` decorator from `expose.collectors.registry`
- Declare class-level metadata: `collector_id`, `collector_version`, `tier`, `requires_credentials`, and `technique_ids`
- Implement two async methods: `expand()` and `health_check()`

```python
"""Short description of the collector -- what it queries and why.

Document the data source, any rate limits, required credentials,
and which seed types are supported.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import ClassVar

import httpx

from expose.collectors.base import (
    Collector,
    CollectorConfig,
    CollectorHealthCheck,
    CollectorSourceUnreachableError,
    Observation,
    ObservationSubject,
    ObservationType,
    Seed,
    SeedType,
)
from expose.collectors.registry import register_collector
from expose.collectors.tiers import CollectorTier
from expose.types.canonical import CollectorStatus, ExtendedIdentifierType

logger = logging.getLogger(__name__)


@register_collector
class YourCollector(Collector):
    """One-line summary of the collector."""

    collector_id: str = "your-collector-id"
    collector_version: str = "0.1.0"
    tier: CollectorTier = CollectorTier.TIER_1  # or TIER_2, TIER_3
    requires_credentials: bool = False
    technique_ids: ClassVar[list[str]] = ["T1596"]  # MITRE ATT&CK Reconnaissance

    def __init__(self, config: CollectorConfig) -> None:
        super().__init__(config)

    async def expand(self, seed: Seed) -> AsyncIterator[Observation]:
        """Query the data source and yield Observation records.

        Skip unsupported seed types with a warning. Raise
        CollectorSourceUnreachableError for catastrophic failures
        (source down, auth invalid). Individual observation failures
        should be logged as warnings, not raised.
        """
        if seed.seed_type != SeedType.DOMAIN:
            logger.warning(
                "%s: skipping unsupported seed type %s",
                self.collector_id,
                seed.seed_type,
            )
            return

        # Query the data source, build observations, yield them
        ...

    async def health_check(self) -> CollectorHealthCheck:
        """Verify the data source is reachable.

        Return a CollectorHealthCheck with status SUCCESS or FAILURE.
        """
        start = datetime.now(tz=UTC)
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(10.0),
                headers={"User-Agent": self.config.user_agent},
            ) as client:
                response = await client.head("https://your-data-source.example.com")
            elapsed_ms = (datetime.now(tz=UTC) - start).total_seconds() * 1000.0

            if response.status_code < 400:
                return CollectorHealthCheck(
                    collector_id=self.collector_id,
                    collector_version=self.collector_version,
                    status=CollectorStatus.SUCCESS,
                    checked_at=start,
                    latency_ms=elapsed_ms,
                )
            return CollectorHealthCheck(
                collector_id=self.collector_id,
                collector_version=self.collector_version,
                status=CollectorStatus.FAILURE,
                checked_at=start,
                latency_ms=elapsed_ms,
                error_message=f"HTTP {response.status_code}",
            )
        except httpx.HTTPError as exc:
            elapsed_ms = (datetime.now(tz=UTC) - start).total_seconds() * 1000.0
            return CollectorHealthCheck(
                collector_id=self.collector_id,
                collector_version=self.collector_version,
                status=CollectorStatus.FAILURE,
                checked_at=start,
                latency_ms=elapsed_ms,
                error_message=str(exc),
            )
```

### Step 2: Understand collector tiers

Collectors are tiered by sensitivity (SPEC section 6.3):

- **Tier 1** -- Passive, broad query. CT logs, passive DNS, ASN/BGP, cloud IP ranges. No attribution gating required.
- **Tier 2** -- Passive, targeted. Internet-wide scan APIs querying seed-graph hosts.
- **Tier 3** -- Active, attribution-gated. DNS resolution, TLS handshake, HTTP fingerprinting, port scanning. Only dispatched against entities with `confirmed` or `high` attribution, or entities explicitly in the tenant authorization scope.

Choose the appropriate tier for your collector. Tier 3 collectors have additional dispatch constraints enforced by the pipeline -- you do not need to implement the gating logic yourself.

### Step 2b: Declare MITRE ATT&CK technique IDs

Every collector **must** declare a `technique_ids` class variable mapping it to one or more MITRE ATT&CK Reconnaissance (TA0043) technique IDs. This is a `ClassVar[list[str]]` on the `Collector` ABC (see `src/expose/collectors/base.py`). Examples from existing collectors:

| Technique | Description | Example collectors |
|-----------|-------------|-------------------|
| `T1596` | Search Open Technical Databases | `scan-shodan`, `scan-censys`, `otx-alienvault` |
| `T1596.001` | DNS/Passive DNS | `active-dns`, `bgp-he-toolkit`, `dns-passive-history` |
| `T1596.003` | Digital Certificates | `ct-crtsh`, `ct-censys`, `ct-certspotter` |
| `T1593` | Search Open Websites/Domains | `wayback-machine`, `common-crawl` |
| `T1592.004` | Client Configurations | `active-http`, `waf-origin-discovery` |
| `T1046` | Network Service Discovery | `active-port-surface` |
| `T1526` | Cloud Service Discovery | `cloud-storage-exposure` |
| `T1597` | Search Closed Sources | `dark-web-indicators` |
| `T1589.002` | Email Addresses | `email-auth` |

The technique IDs flow into the canonical artifact and rule pack evaluation. Do not leave `technique_ids` empty.

### Step 3: Write tests

Create `tests/test_your_collector.py`. All collector tests must mock HTTP interactions -- no live network calls.

```python
"""Tests for the your-collector-id collector.

Uses respx to mock all HTTP interactions -- NO live network calls.
"""

import pytest
import respx

from expose.collectors.base import CollectorConfig, Seed, SeedType
from expose.collectors.builtin.your_collector import YourCollector

TENANT_ID = UUID("018f1f00-0000-7000-8000-00000000ca01")
RUN_ID = UUID("018f1f00-0000-7000-8000-00000000ca02")


def _make_config() -> CollectorConfig:
    return CollectorConfig(
        tenant_id=TENANT_ID,
        run_id=RUN_ID,
        request_timeout_seconds=30.0,
    )


class TestYourCollectorMetadata:
    def test_collector_id(self) -> None:
        assert YourCollector.collector_id == "your-collector-id"

    def test_tier(self) -> None:
        assert YourCollector.tier == CollectorTier.TIER_1


@pytest.mark.asyncio
class TestYourCollectorExpand:
    @respx.mock
    async def test_happy_path(self) -> None:
        # Mock the HTTP call, create a collector, call expand, assert results
        ...

    @respx.mock
    async def test_source_unreachable(self) -> None:
        # Mock a failure, verify CollectorSourceUnreachableError is raised
        ...
```

### Step 4: Create fixture files (if needed)

If your collector parses structured responses, create fixture files under `tests/fixtures/collectors/your_collector/`. Store canned JSON or other response data there and load it in tests. See `tests/fixtures/collectors/ct_crtsh/` for examples.

### Step 5: Sanitize all external input

All data from external sources must pass through the sanitization layer (`expose.sanitization`) before entering the observation graph. Certificate SANs, HTTP banners, DNS records, WHOIS fields -- anything from an adversary-controllable source gets sanitized. See the existing collectors for the pattern.

### Step 6: Open a discussion issue first

Before writing a new collector, open an issue describing the data source, why it adds value, any rate limits or licensing constraints, and which seed types it supports. Some data sources are commercial-only and require operator-provided credentials; those are welcome as long as the engine code itself remains freely usable.

## Contributing a rule pack

Rule packs are data, not code (per SPEC section 8.2). They define attribution rules, lead-score formulas, and evidence-weighting parameters that the rule evaluator (`src/expose/pipeline/rule_evaluator.py`) applies to the observation graph.

**Public example rule packs** ship in `examples/rulepacks/` -- `example-baseline.json`, `cloud-first.json`, and `conservative.json`. These are validated by CI against the JSON Schema at `schemas/rulepack-v1.json`.

### What belongs in the public repo

- **Example rule packs** demonstrating different attribution strategies (conservative, aggressive, industry-specific templates).
- **Schema changes** to `schemas/rulepack-v1.json` when the rule pack format evolves (these require an ADR amendment discussion first).
- **Rule evaluator improvements** in `src/expose/pipeline/rule_evaluator.py` that change how rules are interpreted.
- **Eval dataset entries** in `examples/eval-datasets/` that exercise rule pack edge cases.

### What does NOT belong in the public repo

- **Customer-specific or engagement-specific rule packs.** These belong in private repositories, not the open-source engine. The engine is designed to consume rule packs by reference (`pack_id` + `pack_version`); the pack content itself is operator-provided.
- **Proprietary intelligence feeds** embedded as rule pack data.

### Adding a new example rule pack

1. Create a new JSON file in `examples/rulepacks/`.
2. Validate it against the schema: `check-jsonschema --schemafile schemas/rulepack-v1.json examples/rulepacks/your-pack.json`
3. Write tests in `tests/` that load the pack and verify it against at least one eval dataset from `examples/eval-datasets/`.
4. Add a brief description to `examples/rulepacks/README.md`.
5. Open a PR with the pack, tests, and README update.

## Commit conventions

Subject line under 72 characters, imperative mood ("Add" not "Added"), no trailing period. Use [Conventional Commits](https://www.conventionalcommits.org/) prefixes:

```
feat: add cloud-aws-ranges collector
fix: handle empty SAN list in ct-crtsh collector
docs: clarify Tier 3 dispatch gating in SPEC
test: add regression test for duplicate serial dedup
refactor: extract shared HTTP client config
chore: update ruff to 0.5.0
```

Larger changes benefit from a body explaining the *why*, not just the *what*:

```
feat: add cloud-aws-ranges collector

Implements the cloud-aws-ranges collector reading AWS's ip-ranges.json
manifest. Refreshes daily, parses service tags, populates CloudResource
entities with provider=aws.

Closes #123

Signed-off-by: Your Name <your.email@example.com>
```

### DCO sign-off

Every commit requires a **Developer Certificate of Origin** sign-off. The DCO certifies that you have the right to submit the contribution under the project's open source license. Full text: https://developercertificate.org/

Append the `-s` flag to `git commit`:

```bash
git commit -s -m "feat: add cloud-aws-ranges collector"
```

This adds a `Signed-off-by: Your Name <your.email@example.com>` line. The DCO bot verifies every commit in your pull request; missing sign-offs block merging.

If you forget to sign off, amend or rebase:

```bash
# Amend the last commit
git commit --amend -s --no-edit
git push --force-with-lease

# Sign off on a series of commits
git rebase --signoff main
```

## Pull request process

1. **Fork the repository** and create a feature branch from `main`.
2. **Write your changes** with DCO sign-off on every commit.
3. **Add tests.** New collectors need tests with mocked HTTP; bug fixes need regression tests; new attribution rules need rule-pack validation tests.
4. **Update documentation** as appropriate. SPEC.md changes for architectural decisions, ADR additions for design decisions, README updates for user-facing behavior.
5. **Run the full test suite** locally: `uv run pytest` (all tests should pass).
6. **Run linting and type checking:** `uv run ruff check src/ && uv run mypy src/`
7. **Open the PR** with a clear description: what changed, why, and any operational implications.
8. **Respond to review feedback.** Maintainers may request changes; please be patient as we balance review work with other priorities.

PRs are reviewed by Pitt Street Labs maintainers. Expect 5-10 business days for initial response on substantive PRs.

## Issue labels

The project uses a structured label taxonomy for issue tracking:

| Prefix | Purpose | Examples |
|--------|---------|----------|
| `epic:` | Groups related issues into a feature area | `epic:collectors`, `epic:pipeline`, `epic:observability` |
| `area:` | Identifies the codebase area affected | `area:api`, `area:scope`, `area:sanitization`, `area:helm` |
| `priority:` | Urgency level | `priority:high`, `priority:medium`, `priority:low` |
| `type:` | Kind of work | `type:bug`, `type:feature`, `type:docs`, `type:refactor`, `type:test` |

When filing issues, apply labels that best match. Maintainers will adjust labels during triage if needed.

## What kinds of contributions are welcome

- **Bug fixes** -- always welcome. File an issue first if the bug is non-obvious or its fix has design implications.
- **New collectors** -- welcome with discussion. Open an issue first (see "Writing a new collector" above).
- **Performance improvements** -- welcome with benchmark before/after data.
- **Documentation improvements** -- always welcome. SPEC.md clarifications, deployment guides, glossary updates.
- **Test coverage** -- always welcome. Cross-tenant isolation tests, regression tests, integration tests against synthetic seed graphs.
- **Bug reports** -- open an issue with reproduction steps, EXPOSE version, deployment environment, expected vs. actual behavior.
- **Feature requests** -- open an issue describing the use case. We will discuss scope fit before any code is written.

## What kinds of contributions are not welcome

Per [ETHICS.md](ETHICS.md):

- Active exploitation modules.
- PII enrichment beyond public records.
- Features whose primary purpose is surveillance or unauthorized reconnaissance.
- Features bypassing sanitization or authorization-scope layers.
- Customer-specific rule packs (those belong in private repositories, not the public engine repo).

If you are unsure whether a contribution fits the project, open a discussion issue before writing code.

## Style and standards

**Python.** PEP 8 enforced via `ruff format`. Type annotations required on all public functions; checked via `mypy --strict`. Pydantic v2 for data models.

**Async.** All I/O is async. Use `asyncio.gather` for concurrency, `asyncio.Semaphore` for rate limiting.

**Logging.** Structured logging via OpenTelemetry. No `print()` statements. No PII in log messages.

**Schemas.** Schema changes require updating both Pydantic models (`src/expose/types/`) and JSON Schema files (`schemas/`). CI verifies they stay in sync.

**Tests.** Use `pytest` with `pytest-asyncio` for async tests. Mock external services with `respx` for httpx. Real Postgres via testcontainers for database tests in CI. All data from external sources must be sanitized before graph insertion.

**Comments.** Explain *why*, not *what*. Code that needs heavy "what" comments usually needs refactoring.

## Security

If you discover a security vulnerability, do not open a public issue. See [SECURITY.md](SECURITY.md) for private reporting channels and response SLAs.

## Code of conduct

This project follows the Contributor Covenant version 2.1. See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for the full text and enforcement details.

For Code of Conduct concerns, email `conduct@korlogos.com`.

## License

EXPOSE Core is licensed under [Apache 2.0](LICENSE). By contributing, you agree that your contributions will be licensed under the same terms. The DCO sign-off on each commit is the mechanism for this agreement.

### Open-core boundary

EXPOSE uses an open-core model. Community contributions go to the **Core** (Apache 2.0). The following directories contain proprietary commercial modules and are **not open for community contribution**:

- `src/expose/modules/threat_context/`
- `src/expose/modules/identity_surface/`
- `src/expose/modules/soc_package/`
- `src/expose/modules/ciso_report/`

These directories are stripped from the open-source distribution and are not included in `git archive` builds. PRs touching these paths will be closed.

### Why DCO and not a CLA

We use the DCO (not a Contributor License Agreement) because it's lightweight and well-understood. The DCO certifies origin and right-to-submit; it does not grant relicensing rights beyond Apache 2.0. Your Core contributions remain Apache 2.0 and will not be relicensed into proprietary modules without your explicit written consent. If we ever need broader rights for a specific contribution, we will ask individually -- not through a blanket CLA.

EXPOSE Threat Context, EXPOSE Identity Surface, and EXPOSE Research are separate products with their own licenses (see [GOVERNANCE.md](GOVERNANCE.md) for details on the open-core structure).

## Questions

Open a discussion at https://github.com/pitt-street-labs/expose/discussions for design questions, usage questions, or general conversation. File issues for bug reports and feature requests with concrete asks.

For security disclosure, see [SECURITY.md](SECURITY.md).
