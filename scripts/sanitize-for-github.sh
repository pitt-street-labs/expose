#!/usr/bin/env bash
# sanitize-for-github.sh -- Scan tracked files for internal development artifacts
# that must not appear in the public GitHub release of EXPOSE.
#
# Usage:
#   ./scripts/sanitize-for-github.sh
#
# Exit codes:
#   0 -- clean (no leaks found)
#   1 -- leaks found (review output table)
#
# Install the pre-push hook that calls this script:
#   git config core.hooksPath .githooks
#
# Uses POSIX-compatible grep (no GNU-only flags) for portability.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

# Temporary file for results (cleaned up on exit)
RESULTS_FILE="$(mktemp)"
trap 'rm -f "$RESULTS_FILE"' EXIT

# ---- Excluded files (relative to repo root) ----
# CLAUDE.md                  -- internal working notes, not published
# spiderfoot-creds.txt       -- gitignored credentials file
# HANDOFF.md                 -- genesis record
# init-and-push-to-gitea.sh  -- genesis record
# uv.lock                    -- machine-generated lockfile (hex hashes cause false positives)
# This script itself         -- contains pattern strings as self-references
is_excluded() {
    case "$1" in
        CLAUDE.md)                  return 0 ;;
        spiderfoot-creds.txt)       return 0 ;;
        HANDOFF.md)                 return 0 ;;
        init-and-push-to-gitea.sh)  return 0 ;;
        uv.lock)                    return 0 ;;
        scripts/sanitize-for-github.sh) return 0 ;;
        *)                          return 1 ;;
    esac
}

# ---- Collect scannable files ----
# Uses git ls-files for tracked files, skips excluded and binary files.
FILES_FILE="$(mktemp)"
trap 'rm -f "$RESULTS_FILE" "$FILES_FILE"' EXIT

git ls-files | while IFS= read -r f; do
    is_excluded "$f" && continue

    # Skip binary files (check that file(1) output does NOT contain "text")
    if [ -f "$f" ]; then
        file_type="$(file "$f")"
        case "$file_type" in
            *text*) ;;  # text file -- keep scanning
            *)  continue ;;  # binary -- skip
        esac
    fi

    printf '%s\n' "$f"
done > "$FILES_FILE"

# ---- Pattern definitions ----
# Format: LABEL<tab>REGEX
# POSIX extended regex (grep -E compatible).
PATTERN_FILE="$(mktemp)"
trap 'rm -f "$RESULTS_FILE" "$FILES_FILE" "$PATTERN_FILE"' EXIT

cat > "$PATTERN_FILE" <<'PATTERNS'
internal-date	2026-0[0-9]-
session-ref	Session [A-Z][^a-z]
sprint-ref	Sprint [0-9]
gitea-url	git\.int\.korlogos\.com
internal-ip	172\.16\.
korlogos-internal	korlogos\.com
claude-code-attr	Claude Code
claude-agent-attr	claude-agent
anthropic-email	noreply@anthropic\.com
gitea-token	(^|[^0-9a-f])[0-9a-f]{40}($|[^0-9a-f])
spiderfoot-creds-ref	spiderfoot-creds
api-key-ref	API[_-]?[Kk]ey[[:space:]]*=
session-log-path	~/\.claude/
session-id-ref	session[_-]id
hostname-node1	(^|[^a-zA-Z0-9_-])node1($|[^a-zA-Z0-9_-])
hostname-node2	(^|[^a-zA-Z0-9_-])node2($|[^a-zA-Z0-9_-])
hostname-z590	(^|[^a-zA-Z0-9_-])z590($|[^a-zA-Z0-9_-])
hostname-fw1	(^|[^a-zA-Z0-9_.-])fw1($|[^a-zA-Z0-9_.-])
hostname-sw1	(^|[^a-zA-Z0-9_.-])sw1($|[^a-zA-Z0-9_.-])
hostname-pbx1	(^|[^a-zA-Z0-9_.-])pbx1($|[^a-zA-Z0-9_.-])
pitt-street-labs	pitt-street-labs
internal-codename	FF6K
PATTERNS

# ---- Scan ----
while IFS= read -r filepath; do
    [ -z "$filepath" ] && continue
    [ ! -f "$filepath" ] && continue

    while IFS='	' read -r label regex; do
        [ -z "$label" ] && continue

        # grep -n -E: line numbers + extended regex, POSIX compatible
        # Capture matches first to avoid pipefail killing the script on no-match
        matches="$(grep -n -E "$regex" "$filepath" 2>/dev/null)" || true
        if [ -n "$matches" ]; then
            printf '%s\n' "$matches" | while IFS= read -r match; do
                line_num="${match%%:*}"
                line_content="${match#*:}"

                # Truncate long lines
                if [ "${#line_content}" -gt 120 ]; then
                    line_content="$(printf '%.120s' "$line_content")..."
                fi

                printf '%s\t%s\t%s\n' "$filepath:$line_num" "$label" "$line_content"
            done
        fi
    done < "$PATTERN_FILE"
done < "$FILES_FILE" > "$RESULTS_FILE"

# ---- Report ----
TOTAL="$(wc -l < "$RESULTS_FILE" | tr -d ' ')"

if [ "$TOTAL" -gt 0 ]; then
    printf '\n'
    printf '%-45s  %-25s  %s\n' "FILE:LINE" "PATTERN" "MATCH"
    printf '%-45s  %-25s  %s\n' "----------" "--------" "-----"

    while IFS='	' read -r location label content; do
        printf '%-45s  %-25s  %s\n' "$location" "$label" "$content"
    done < "$RESULTS_FILE"

    printf '\n[FAIL] Found %d internal artifact reference(s) that must be sanitized before GitHub publication.\n' "$TOTAL"
    printf '       Review the table above and clean each match.\n\n'
    exit 1
else
    printf '[PASS] No internal artifact leaks detected. Safe to publish.\n'
    exit 0
fi
