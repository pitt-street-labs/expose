#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# EXPOSE Trademark Preliminary Search
###############################################################################
#
# Purpose:
#   Searches for potential trademark conflicts with "EXPOSE" in classes
#   relevant to security software / SaaS platforms:
#     - Class 9  (Computer software)
#     - Class 38 (Telecommunications services)
#     - Class 42 (Computer services, SaaS)
#
# Method:
#   1. Prints formatted URLs for manual USPTO TESS searches (TESS has no
#      public API and requires an interactive browser session).
#   2. Queries the WIPO Global Brand Database for "EXPOSE" and phonetic
#      variants in US jurisdiction, parsing results for the three target
#      Nice classes.
#   3. Produces a risk-level summary and exit code.
#
# IMPORTANT:
#   This is a PRELIMINARY, automated search. It is NOT a substitute for
#   a formal trademark clearance opinion from qualified IP counsel.
#   The WIPO Global Brand Database may lag behind live USPTO records, and
#   common-law (unregistered) marks are not covered by either database.
#
# Dependencies:
#   - curl (required)
#   - jq  (optional; falls back to grep-based parsing if missing)
#
# Exit codes:
#   0 — LOW risk   (no active marks found in target classes)
#   1 — MEDIUM/HIGH risk (conflicts detected; attorney review recommended)
#
###############################################################################

# ── Configuration ────────────────────────────────────────────────────────────

MARK_PRIMARY="EXPOSE"
MARK_VARIANTS=("EXPOSE" "XPOSE" "EXPOSÉ")
NICE_CLASSES=(9 38 42)
JURISDICTION="US"

DATE_STAMP="$(date +%Y-%m-%d)"
REPORT_LINE="════════════════════════════════════════════════════"

# Counters for risk assessment
TOTAL_ACTIVE=0
TOTAL_RELEVANT=0

# ── Dependency checks ───────────────────────────────────────────────────────

if ! command -v curl &>/dev/null; then
    echo "ERROR: curl is required but not found." >&2
    exit 2
fi

HAS_JQ=false
if command -v jq &>/dev/null; then
    HAS_JQ=true
fi

# ── Helper functions ─────────────────────────────────────────────────────────

print_header() {
    echo ""
    echo "$REPORT_LINE"
    echo "  $MARK_PRIMARY Trademark Preliminary Search"
    echo "$REPORT_LINE"
    echo "  Date:    $DATE_STAMP"
    echo "  Classes: $(printf '%s, ' "${NICE_CLASSES[@]}" | sed 's/, $//')"
    echo "  Jurisdiction: $JURISDICTION"
    echo "$REPORT_LINE"
    echo ""
}

# Build a WIPO Global Brand Database search URL for a given term.
# The branddb frontend exposes a structured search via query parameters.
wipo_search_url() {
    local term="$1"
    # The WIPO branddb search uses URL parameters for structured queries.
    # We filter by source office (US) and Nice classification.
    local classes_param
    classes_param="$(IFS=','; echo "${NICE_CLASSES[*]}")"
    echo "https://branddb.wipo.int/branddb/en/#702${term}706${classes_param}711${JURISDICTION}"
}

# Build a USPTO TESS search URL for a given term and class.
# TESS uses a structured search form; we provide the direct-access URL
# that pre-fills the search field.  Note: TESS sessions are ephemeral
# and may require re-navigation; these URLs open the search landing page.
tess_search_url() {
    local term="$1"
    local class="$2"
    # The new USPTO trademark search system (tmsearch.uspto.gov) replaced
    # legacy TESS in late 2023.  It supports direct query URLs.
    echo "https://tmsearch.uspto.gov/bin/showfield?f=tess&state=4809:uf0jx0.1.1&p_search=searchss&p_s_PARA1=${term}&p_s_PARA2=0${class}&BackReference=&p_L=50&p_plural=yes&p_s_ALL=&a_default=search&a_search=Submit+Query"
}

# Query WIPO Global Brand Database API.
# Returns raw JSON (or empty string on failure).
# The WIPO branddb may block automated access with CAPTCHA; we attempt the
# query and handle failure gracefully.
query_wipo() {
    local term="$1"
    local encoded_term
    encoded_term="$(printf '%s' "$term" | sed 's/ /%20/g; s/é/%C3%A9/g')"

    # WIPO branddb API endpoint for structured search.  This endpoint is
    # not officially documented and may change or require CAPTCHA.
    local api_url="https://branddb.wipo.int/branddb/en/similiar/results"
    local query_url="https://branddb.wipo.int/branddb/en/?q=%7B%22searches%22%3A%5B%7B%22fi%22%3A%22BN%22%2C%22te%22%3A%22${encoded_term}%22%7D%2C%7B%22fi%22%3A%22NC%22%2C%22te%22%3A%22$(IFS='%2C'; echo "${NICE_CLASSES[*]}")%22%7D%2C%7B%22fi%22%3A%22OO%22%2C%22te%22%3A%22${JURISDICTION}%22%7D%5D%7D"

    # Attempt the search via the public-facing structured search endpoint.
    local response
    response="$(curl -sS --max-time 15 \
        -H "Accept: application/json" \
        -H "User-Agent: Mozilla/5.0 (trademark-check-script)" \
        "$query_url" 2>/dev/null)" || true

    echo "$response"
}

# Parse WIPO response and count marks.
# Sets global variables: found_total, found_active, found_relevant
# Arguments: $1 = raw response, $2 = search term (for display)
parse_wipo_response() {
    local response="$1"
    local term="$2"

    found_total=0
    found_active=0
    found_relevant=0

    if [[ -z "$response" ]]; then
        echo "  \"$term\": WIPO query failed or returned empty (CAPTCHA likely)"
        return 1
    fi

    # Check if response is valid JSON
    if [[ "$HAS_JQ" == "true" ]]; then
        if ! echo "$response" | jq empty 2>/dev/null; then
            echo "  \"$term\": WIPO returned non-JSON response (CAPTCHA or rate limit)"
            return 1
        fi

        # Try to extract result count from known WIPO response structures.
        # The response format varies; we try multiple paths.
        found_total="$(echo "$response" | jq -r '.total // .response.numFound // .rows // 0' 2>/dev/null || echo 0)"

        # Count active marks (status contains "Live" or "Registered" or "Active")
        found_active="$(echo "$response" | jq -r '
            [.rows[]? // .response.docs[]? // .results[]? |
             select(.ST? // .statusType? // .status? |
                    tostring | test("Live|Registered|Active|LIVE|REGISTERED|ACTIVE"))]
            | length' 2>/dev/null || echo 0)"

        # Count marks in our target Nice classes
        found_relevant="$(echo "$response" | jq -r --arg classes "$(IFS='|'; echo "${NICE_CLASSES[*]}")" '
            [.rows[]? // .response.docs[]? // .results[]? |
             select((.NC? // .niceClasses? // .classes? | tostring) |
                    test($classes))]
            | length' 2>/dev/null || echo 0)"
    else
        # Fallback: grep-based parsing (less reliable)
        if echo "$response" | grep -qi "captcha\|challenge\|verify"; then
            echo "  \"$term\": WIPO returned CAPTCHA challenge"
            return 1
        fi

        # Rough count of trademark entries
        found_total="$(echo "$response" | grep -oi '"brandName"' | wc -l || echo 0)"
        found_active="$(echo "$response" | grep -oi '"Live"\|"Registered"\|"Active"' | wc -l || echo 0)"
        found_relevant=0
        for class in "${NICE_CLASSES[@]}"; do
            local class_hits
            class_hits="$(echo "$response" | grep -o "\"${class}\"" | wc -l || echo 0)"
            found_relevant=$((found_relevant + class_hits))
        done
    fi

    # Sanitize to integers
    found_total="${found_total//[^0-9]/}"
    found_active="${found_active//[^0-9]/}"
    found_relevant="${found_relevant//[^0-9]/}"
    found_total="${found_total:-0}"
    found_active="${found_active:-0}"
    found_relevant="${found_relevant:-0}"

    echo "  \"$term\": $found_active active marks, $found_relevant in relevant classes (${found_total} total)"
    return 0
}

# ── Main ─────────────────────────────────────────────────────────────────────

print_header

# ── Section 1: Manual search URLs ────────────────────────────────────────────

echo "MANUAL SEARCH URLS (browser required)"
echo "──────────────────────────────────────"
echo ""
echo "USPTO Trademark Search (tmsearch.uspto.gov):"
echo "  General search page: https://tmsearch.uspto.gov/"
echo ""
echo "  Suggested manual searches (paste into TESS 'Basic Word Mark Search'):"
for class in "${NICE_CLASSES[@]}"; do
    printf '    Class %d — search for: EXPOSE AND IC=%03d\n' "$class" "$class"
done
echo ""
echo "  For phonetic variants, also search:"
echo "    XPOSE AND IC=009"
echo "    XPOSE AND IC=038"
echo "    XPOSE AND IC=042"
echo ""
echo "WIPO Global Brand Database:"
for variant in "${MARK_VARIANTS[@]}"; do
    echo "  \"$variant\": $(wipo_search_url "$variant")"
done
echo ""

# ── Section 2: Automated WIPO queries ───────────────────────────────────────

echo "AUTOMATED WIPO GLOBAL BRAND DATABASE SEARCH"
echo "──────────────────────────────────────────────"
echo ""

if [[ "$HAS_JQ" == "true" ]]; then
    echo "  (jq detected — using structured JSON parsing)"
else
    echo "  (jq not found — using fallback grep parsing; results may be less accurate)"
fi
echo ""

wipo_available=true
declare -A variant_active
declare -A variant_relevant

for variant in "${MARK_VARIANTS[@]}"; do
    response="$(query_wipo "$variant")"
    if parse_wipo_response "$response" "$variant"; then
        variant_active["$variant"]="$found_active"
        variant_relevant["$variant"]="$found_relevant"
        TOTAL_ACTIVE=$((TOTAL_ACTIVE + found_active))
        TOTAL_RELEVANT=$((TOTAL_RELEVANT + found_relevant))
    else
        variant_active["$variant"]="?"
        variant_relevant["$variant"]="?"
        wipo_available=false
    fi
done

echo ""

# ── Section 3: Risk assessment ───────────────────────────────────────────────

echo "RISK ASSESSMENT"
echo "──────────────────────────────────────────────"
echo ""

RISK_LEVEL="UNKNOWN"
RECOMMENDATION=""

if [[ "$wipo_available" == "false" ]]; then
    # Could not reach WIPO — cannot make automated determination
    RISK_LEVEL="UNKNOWN"
    RECOMMENDATION="WIPO database was unreachable (CAPTCHA or network). Manual search required."
    RECOMMENDATION="$RECOMMENDATION Run the URLs above in a browser to complete the search."
elif [[ "$TOTAL_RELEVANT" -gt 0 ]]; then
    RISK_LEVEL="HIGH"
    RECOMMENDATION="Active marks found in target Nice classes. Do NOT publish under this name"
    RECOMMENDATION="$RECOMMENDATION without a formal clearance opinion from trademark counsel."
elif [[ "$TOTAL_ACTIVE" -gt 0 ]]; then
    RISK_LEVEL="MEDIUM"
    RECOMMENDATION="Active marks exist for similar terms but in different classes/goods."
    RECOMMENDATION="$RECOMMENDATION Review the specific marks manually. Consider professional"
    RECOMMENDATION="$RECOMMENDATION trademark counsel before publication."
else
    RISK_LEVEL="LOW"
    RECOMMENDATION="No active marks found in WIPO for these terms and classes."
    RECOMMENDATION="$RECOMMENDATION Still recommended: confirm via USPTO TESS manual search"
    RECOMMENDATION="$RECOMMENDATION and consult trademark counsel before final publication."
fi

echo "  Risk level: $RISK_LEVEL"
echo ""

# ── Section 4: Summary report ───────────────────────────────────────────────

echo ""
echo "$REPORT_LINE"
echo "  SUMMARY REPORT"
echo "$REPORT_LINE"
echo ""
cat <<SUMMARY
  $MARK_PRIMARY Trademark Preliminary Search
  ====================================
  Date: $DATE_STAMP
  Classes: $(printf '%s, ' "${NICE_CLASSES[@]}" | sed 's/, $//')
  Jurisdiction: $JURISDICTION

  WIPO Global Brand Database Results:
SUMMARY

for variant in "${MARK_VARIANTS[@]}"; do
    active="${variant_active[$variant]:-?}"
    relevant="${variant_relevant[$variant]:-?}"
    printf '    "%-8s": %s active marks, %s in relevant classes\n' "$variant" "$active" "$relevant"
done

cat <<SUMMARY

  Risk Assessment: $RISK_LEVEL

  Manual Verification Required:
    USPTO TESS: https://tmsearch.uspto.gov/
    WIPO:       https://branddb.wipo.int/branddb/en/

  Recommendation:
    $RECOMMENDATION

  DISCLAIMER:
    This automated search is preliminary only. It does not constitute
    legal advice and is not a substitute for a professional trademark
    clearance search and opinion from qualified intellectual property
    counsel. Common-law (unregistered) marks are not covered.

$REPORT_LINE
SUMMARY

# ── Exit code ────────────────────────────────────────────────────────────────

if [[ "$RISK_LEVEL" == "LOW" ]]; then
    exit 0
else
    # MEDIUM, HIGH, or UNKNOWN all warrant human review
    exit 1
fi
