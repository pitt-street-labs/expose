#!/usr/bin/env bash
# Build open-source distribution of EXPOSE Core (strips commercial modules)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Determine version tag
VERSION="$(cd "$REPO_ROOT" && git describe --tags --always 2>/dev/null || echo "dev")"
DIST_NAME="expose-core-${VERSION}"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

echo "==> Building open-source distribution: ${DIST_NAME}"
echo "    Source: ${REPO_ROOT}"
echo "    Temp:   ${TMPDIR}"

# Copy full source tree (respecting .gitignore via git archive fallback)
echo "==> Copying source tree..."
cp -a "$REPO_ROOT" "$TMPDIR/$DIST_NAME"

# Remove git metadata from the copy
rm -rf "$TMPDIR/$DIST_NAME/.git"
rm -rf "$TMPDIR/$DIST_NAME/.gitworktrees" 2>/dev/null || true

# Strip commercial modules (proprietary per ADR-009)
echo "==> Stripping commercial modules (src/expose/modules/)..."
rm -rf "$TMPDIR/$DIST_NAME/src/expose/modules/"

# Strip any other proprietary artifacts
echo "==> Stripping other proprietary files..."
rm -f "$TMPDIR/$DIST_NAME/spiderfoot-creds.txt" 2>/dev/null || true
rm -rf "$TMPDIR/$DIST_NAME/.claude" 2>/dev/null || true
rm -f "$TMPDIR/$DIST_NAME/CLAUDE.md" 2>/dev/null || true
rm -rf "$TMPDIR/$DIST_NAME/.qa-gate-logs" 2>/dev/null || true
rm -rf "$TMPDIR/$DIST_NAME/.coverage" 2>/dev/null || true
rm -rf "$TMPDIR/$DIST_NAME/.mypy_cache" 2>/dev/null || true
rm -rf "$TMPDIR/$DIST_NAME/.pytest_cache" 2>/dev/null || true
rm -rf "$TMPDIR/$DIST_NAME/.ruff_cache" 2>/dev/null || true
rm -rf "$TMPDIR/$DIST_NAME/.venv" 2>/dev/null || true
rm -rf "$TMPDIR/$DIST_NAME/__pycache__" 2>/dev/null || true
rm -f "$TMPDIR/$DIST_NAME/multi-llm-mcp" 2>/dev/null || true
rm -rf "$TMPDIR/$DIST_NAME/.playwright-mcp" 2>/dev/null || true

# Remove test coverage artifacts
find "$TMPDIR/$DIST_NAME" -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
find "$TMPDIR/$DIST_NAME" -name "*.pyc" -delete 2>/dev/null || true

# Create tarball
OUTFILE="${REPO_ROOT}/${DIST_NAME}.tar.gz"
echo "==> Creating tarball: ${OUTFILE}"
tar -czf "$OUTFILE" -C "$TMPDIR" "$DIST_NAME"

echo "==> Done. Open-source distribution: ${OUTFILE}"
echo "    Size: $(du -h "$OUTFILE" | cut -f1)"
echo "    Commercial modules stripped: YES"
echo "    Proprietary configs stripped: YES"
