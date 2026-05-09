#!/usr/bin/env bash
# init-and-push-to-gitea.sh
#
# GENESIS RECORD — DO NOT RE-RUN.
# This script bootstrapped the FF6K repository from the spec-phase handoff
# package on 2026-05-09. It produced the first three commits (foundation,
# strategic foundation, inventory) and pushed them to Gitea. It is preserved
# here as a historical record of how the repo was initialized; re-running
# would fail because .git/ already exists.
#
# Differences from the originally delivered script (which assumed a personal
# `jcarlson/ff6k.git` namespace and SSH transport on port 8084):
#   - GITEA_REMOTE_URL switched to HTTPS+token form (port 8084 is Gitea HTTPS,
#     not SSH) targeting `pitt-street-labs/ff6k` to match lab convention.
#   - REPO_DIR set to "." because the spec tree was flattened from the
#     ff6k-handoff/ff6k-repo/ wrapper to the project root.
# The token embedded in GITEA_REMOTE_URL has been redacted to an environment
# variable placeholder; supply via $GITEA_TOKEN or a credential helper if you
# ever need to re-run against a fresh empty repo.
#
# Prerequisites for a hypothetical re-run:
#   - git installed and configured (user.name, user.email)
#   - GITEA_TOKEN exported (claude-agent token under pitt-street-labs)
#   - Empty repository created on Gitea (this script does NOT create it)

set -euo pipefail

# === Configuration — adjust to your setup ===================================
GITEA_REMOTE_URL="https://claude-agent:${GITEA_TOKEN:?GITEA_TOKEN must be set}@git.int.korlogos.com:8084/pitt-street-labs/ff6k.git"
DEFAULT_BRANCH="main"
REPO_DIR="."

# === Pre-flight ============================================================
if [ ! -d "$REPO_DIR" ]; then
    echo "ERROR: $REPO_DIR/ not found in current working directory." >&2
    exit 1
fi

if [ ! -f "$REPO_DIR/README.md" ] || [ ! -f "$REPO_DIR/INVENTORY.md" ]; then
    echo "ERROR: $REPO_DIR does not look like the ff6k-repo tree (missing README or INVENTORY)." >&2
    exit 1
fi

if ! command -v git &> /dev/null; then
    echo "ERROR: git not installed." >&2
    exit 1
fi

if ! git config --global user.name > /dev/null 2>&1; then
    echo "ERROR: git user.name not configured. Run: git config --global user.name 'Your Name'" >&2
    exit 1
fi

if ! git config --global user.email > /dev/null 2>&1; then
    echo "ERROR: git user.email not configured. Run: git config --global user.email 'you@example.com'" >&2
    exit 1
fi

echo "Pre-flight checks passed."
echo ""
echo "Repo dir:       $REPO_DIR"
echo "Target remote:  $GITEA_REMOTE_URL"
echo "Default branch: $DEFAULT_BRANCH"
echo ""
read -p "Proceed? [y/N] " -n 1 -r
echo
[[ $REPLY =~ ^[Yy]$ ]] || { echo "Aborted."; exit 0; }

# === Initialize ============================================================
cd "$REPO_DIR"

if [ -d ".git" ]; then
    echo "ERROR: .git/ already exists. To re-run, delete .git/ first." >&2
    exit 1
fi

echo "Initializing repository..."
git init -b "$DEFAULT_BRANCH"

# === Commit 1: Foundation specification ====================================
echo ""
echo "Commit 1: Foundation specification..."

git add LICENSE README.md SECURITY.md ETHICS.md CONTRIBUTING.md CODE_OF_CONDUCT.md .gitignore
git add docs/SPEC.md docs/glossary.md docs/issues-backlog.md
git add docs/adr/ADR-001-implementation-language.md
git add docs/adr/ADR-002-graph-storage.md
git add docs/adr/ADR-003-deployment-posture.md
git add docs/adr/ADR-004-output-artifact.md
git add docs/adr/ADR-005-llm-integration.md
git add docs/adr/ADR-006-repository-and-licensing.md
git add docs/adr/ADR-007-multi-tenancy.md
git add docs/adr/ADR-008-authorized-use-and-ethics.md
git add docs/deferred-issues/
git add schemas/
git add examples/

git commit -s -m "Initial specification: foundation architecture and governance

Eight architectural decisions (ADRs 1-8) covering implementation
language, graph storage, deployment posture, output artifact, LLM
integration, repository and licensing, multi-tenancy, and authorized
use.

Comprehensive SPEC.md, JSON Schemas (Draft 2020-12), example rule
pack, governance documents, six per-decision deferred-issues
backlogs.

Working codename: FF6K (public name TBD per Session H)."

# === Commit 2: Strategic foundation =========================================
echo ""
echo "Commit 2: Strategic foundation..."

git add docs/positioning.md
git add docs/problem-statement.md
git add docs/HISTORY.md
git add docs/adr/ADR-009-commercial-structure.md
git add docs/adr/ADR-010-fedramp-ready-posture.md

git commit -s -m "Strategic foundation: positioning, commercial structure, FedRAMP posture

ADR-009: Open-core commercial structure with three proprietary
modules (Threat Context, Identity Surface) plus a research dataset
offering (CC BY 4.0).

ADR-010: FedRAMP-ready posture — architecturally ready in v1 with
FIPS 140-3 cryptography and NIST 800-53 control alignment;
authorization-deferred for the open-source engine; authorization-
targeted for the future commercial managed-service offering.

Niche locked: continuous, attributed, signed, AI-enriched, dual-
audience (defensive CTEM + authorized red team), federal-deployable
open-source substrate, with research-grade dataset offering.
MITRE ATT&CK anchor: Reconnaissance (TA0043) for Core; Resource
Development (TA0042) is a Threat Context commercial module concern."

# === Commit 3: Inventory ===================================================
echo ""
echo "Commit 3: Inventory and consolidation..."

git add INVENTORY.md

git commit -s -m "Add inventory of specification phase artifacts

INVENTORY.md captures the manifest of all artifacts produced across
the two specification phase sessions. Documents what is locked,
what is pending, and the subsequent session queue (B through H)."

# === Add remote and push ===================================================
echo ""
echo "Adding remote: $GITEA_REMOTE_URL"
git remote add origin "$GITEA_REMOTE_URL"

echo ""
echo "Repository state:"
git log --oneline
echo ""

read -p "Push to Gitea now? [y/N] " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Push skipped. To push manually:"
    echo "  cd $REPO_DIR && git push -u origin $DEFAULT_BRANCH"
    exit 0
fi

echo "Pushing to $GITEA_REMOTE_URL ..."
git push -u origin "$DEFAULT_BRANCH"

echo ""
echo "Done. Repository pushed to $GITEA_REMOTE_URL"
echo ""
echo "Next steps:"
echo "  1. Verify the repo on Gitea web UI"
echo "  2. Clone it on your dev machine: git clone $GITEA_REMOTE_URL"
echo "  3. Open the cloned directory in Claude Code to begin implementation"
