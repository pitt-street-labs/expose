# Contributing to EXPOSE

Thanks for your interest in contributing. EXPOSE is open source under Apache 2.0 and welcomes contributions from the community.

## Before you start

Please read:

- **[`README.md`](README.md)** — project overview.
- **[`docs/SPEC.md`](docs/SPEC.md)** — comprehensive specification.
- **[`ETHICS.md`](ETHICS.md)** — intended use and non-goals. Some contribution categories are explicitly out of scope.
- **[`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md)** — community standards.
- **[`SECURITY.md`](SECURITY.md)** — security disclosure (don't open public issues for vulnerabilities).

## Developer Certificate of Origin

This project requires the **Developer Certificate of Origin** (DCO) on every commit. The DCO is a lightweight alternative to a Contributor License Agreement: by signing off on each commit, you certify that:

> 1. The contribution was created in whole or in part by you and you have the right to submit it under the open source license indicated in the file; or
> 2. The contribution is based upon previous work that, to the best of your knowledge, is covered under an appropriate open source license and you have the right under that license to submit that work with modifications, whether created in whole or in part by you, under the same open source license (unless you are permitted to submit under a different license); or
> 3. The contribution was provided directly to you by some other person who certified (1), (2), or (3) and you have not modified it.
> 4. You understand and agree that this project and the contribution are public and that a record of the contribution (including all personal information you submit with it, including your sign-off) is maintained indefinitely and may be redistributed consistent with this project or the open source license(s) involved.

Full DCO text: https://developercertificate.org/

To sign off on a commit, append the `-s` flag to `git commit`:

```bash
git commit -s -m "Add cloud-aws-ranges collector"
```

This adds a `Signed-off-by: Your Name <your.email@example.com>` line to your commit message. The DCO bot will verify every commit in your pull request has this sign-off; missing sign-offs block merging.

If you forget to sign off, you can amend the commit:

```bash
git commit --amend -s --no-edit
git push --force-with-lease
```

For a series of commits, use `git rebase --signoff main` to sign off on all of them.

## What kinds of contributions are welcome

**Bug fixes.** Always welcome. File an issue first if the bug is non-obvious or its fix has design implications.

**New collectors.** Welcome with discussion. Open an issue describing the collector source, why it adds value, and any rate limits or licensing constraints. Some collector sources are commercial-only and require operator-provided credentials; we welcome those implementations as long as the engine code itself is freely usable.

**Performance improvements.** Welcome. Include benchmark before/after data; ideally a reproducible benchmark we can re-run.

**Documentation improvements.** Always welcome. Including: SPEC.md clarifications, ADR additions for new design decisions, glossary updates, deployment guides for environments we don't currently document well.

**Test coverage.** Always welcome. Cross-tenant isolation tests, regression tests for previous bugs, integration tests against synthetic seed graphs.

**Bug reports.** Open an issue with reproduction steps, EXPOSE version, deployment environment, expected vs. actual behavior.

**Feature requests.** Open an issue describing the use case. We'll discuss whether it fits the project's scope and intent before any code is written.

## What kinds of contributions are not welcome

Per [`ETHICS.md`](ETHICS.md):

- Active exploitation modules.
- PII enrichment beyond public records.
- Features whose primary purpose is surveillance or unauthorized reconnaissance.
- Features bypassing sanitization or authorization-scope layers.
- Customer-specific rule packs (those go in private repositories, not the public engine repo).

If you're unsure whether a contribution fits the project, open a discussion issue before writing code.

## Development setup

```bash
git clone https://github.com/korlogos/expose.git
cd expose

# Install uv (Python package manager): https://docs.astral.sh/uv/
curl -LsSf https://astral.sh/uv/install.sh | sh

# Set up the Python environment
uv sync --all-extras --dev

# Activate the venv
source .venv/bin/activate

# Run tests
uv run pytest

# Run type checking
uv run mypy src/

# Run linter
uv run ruff check src/
uv run ruff format --check src/
```

For containerized integration testing:

```bash
docker compose -f deploy/dev/docker-compose.yml up -d
uv run pytest tests/integration/
```

For Helm chart development:

```bash
# Install k3d for local Kubernetes
curl -s https://raw.githubusercontent.com/k3d-io/k3d/main/install.sh | bash

# Spin up a local cluster
k3d cluster create expose-dev

# Install the chart
helm install expose ./deploy/helm-chart \
    --values deploy/dev/local-values.yaml \
    --namespace expose --create-namespace
```

## Pull request workflow

1. **Fork the repository** and create a feature branch from `main`.
2. **Write your changes** with sign-off on every commit.
3. **Add tests** that cover the change. New collectors need integration tests; new attribution rules need rule-pack-validation tests; bug fixes need regression tests.
4. **Update documentation** as appropriate. SPEC.md changes for architectural changes, ADR additions for design decisions, README updates for user-facing behavior.
5. **Run the full test suite** locally before opening the PR.
6. **Open the PR** with a clear description: what changed, why, and any operational implications.
7. **Respond to review feedback.** Maintainers may request changes; please be patient as we balance review work with other priorities.

PRs are reviewed by Korlogos maintainers. Expect 5-10 business days for initial response on substantive PRs.

## Commit message conventions

Subject line under 72 characters, imperative mood ("Add" not "Added"), no trailing period.

```
Add cloud-aws-ranges collector

Implements the cloud-aws-ranges collector reading AWS's ip-ranges.json
manifest. Refreshes daily, parses service tags, populates CloudResource
entities with provider=aws.

Closes #123

Signed-off-by: Your Name <your.email@example.com>
```

Larger changes benefit from a body explaining the why, not just the what.

## Style and standards

**Python.** PEP 8 enforced via `ruff format`. Type annotations required on all public functions; checked via `mypy`. Pydantic v2 for data models.

**Async.** All I/O is async. Use `asyncio.gather` for concurrency, `asyncio.Semaphore` for rate limiting.

**Logging.** Structured logging via OpenTelemetry. No `print()` statements, no `logger.info("Processing ${user.email}")` style fragments.

**Schemas.** Schema changes require updating both Pydantic models and JSON Schema files in `schemas/`. CI verifies they stay in sync.

**Tests.** Use `pytest`. Async tests via `pytest-asyncio`. Mock external services with `respx` for httpx, real Postgres for database tests (testcontainers in CI).

**Comments.** Explain why, not what. Code that needs heavy "what" comments usually needs refactoring.

## Releases

Releases are tagged from `main` following SemVer:

- **Major** (1.0.0 → 2.0.0) — breaking schema changes, breaking config changes.
- **Minor** (1.0.0 → 1.1.0) — backward-compatible additions, new collectors, new attribution rule predicates.
- **Patch** (1.0.0 → 1.0.1) — bug fixes, security fixes, no behavior changes.

Pre-release tags use `-rc.N` and `-beta.N` suffixes.

## Questions

Open a discussion at https://github.com/korlogos/expose/discussions for design questions, usage questions, or general discussion. File issues for bug reports and feature requests with concrete asks.

For Code of Conduct concerns, email `conduct@korlogos.com`.

For security disclosure, see [`SECURITY.md`](SECURITY.md).
