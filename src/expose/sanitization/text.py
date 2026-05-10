"""Field-level sanitization helpers (per SPEC.md §7.1).

Stage 3 of the pipeline (SPEC §2.2) is the trust boundary between untrusted
external content and the canonical observation graph. This module implements
the field-level sanitization rules for every external string field — cert
SAN, HTTP banner, DNS TXT content, server header, page title, redirect
target, WHOIS organization name.

Per SPEC §7.1, the rules are:

1. Strip ASCII control characters except ``\\t``, ``\\n``, ``\\r``.
2. Normalize Unicode to NFC.
3. Length-cap by field type (cert SAN max 255 bytes; banner max 4096 bytes;
   TXT record max 1024 bytes; other fields per RFC).
4. Detect and flag suspicious content (HTML tags, embedded Markdown,
   embedded JSON, very long strings, base64-encoded blobs).
5. Flagged content is preserved in the evidence object store; the graph
   entry carries a ``content_flagged`` property.

This module deliberately uses *only* the standard library plus ``re`` — no
HTML parser, no Markdown parser. The detection step is heuristic, not
adversary-resistant; its job is to surface "this needs analyst review",
not to strip injection payloads. Stripping is what the LLM-prompt
construction step (``expose.sanitization.canonicalize.wrap_for_llm_prompt``)
does, by wrapping content in ``<external_observation>`` tags.

Length caps are documented constants. Future tuning lands in this module
rather than collector-by-collector to keep the policy auditable.
"""

import re
import unicodedata
from dataclasses import dataclass, field
from enum import Enum

# === Length caps (SPEC §7.1) =================================================
# Each cap is documented with its provenance. Caps are byte-counts on the
# UTF-8 encoded form, NOT codepoint counts — that's what RFCs measure and what
# downstream consumers (Postgres ``bytea`` columns, JSON serializers) care
# about for storage budgeting.

CAP_BYTES_CERT_SAN = 255  # SPEC §7.1 — matches RFC 5280 hard limits
CAP_BYTES_HTTP_BANNER = 4096  # SPEC §7.1 — wide enough for verbose banners
CAP_BYTES_DNS_TXT_RECORD = 1024  # SPEC §7.1 — wider than 255-byte chunk; aggregated record
CAP_BYTES_HTTP_SERVER_HEADER = 1024  # RFC 7231 doesn't limit; pragmatic cap
CAP_BYTES_HTTP_PAGE_TITLE = 2048  # HTML title elements are sometimes verbose
CAP_BYTES_HTTP_REDIRECT_TARGET = 8192  # URLs can be long; matches typical web-server limits
CAP_BYTES_WHOIS_ORGANIZATION = 1024  # RFC 9082 doesn't limit; pragmatic cap
CAP_BYTES_GENERIC_FIELD = 4096  # Default when a more specific cap doesn't apply


class SanitizationFieldKind(str, Enum):
    """Named field kinds with their own length cap.

    Concrete collectors pass the kind to ``sanitize_field`` so the right cap
    applies. ``GENERIC`` falls back to ``CAP_BYTES_GENERIC_FIELD``.
    """

    CERT_SAN = "cert_san"
    HTTP_BANNER = "http_banner"
    DNS_TXT_RECORD = "dns_txt_record"
    HTTP_SERVER_HEADER = "http_server_header"
    HTTP_PAGE_TITLE = "http_page_title"
    HTTP_REDIRECT_TARGET = "http_redirect_target"
    WHOIS_ORGANIZATION = "whois_organization"
    GENERIC = "generic"


_CAP_BY_KIND: dict[SanitizationFieldKind, int] = {
    SanitizationFieldKind.CERT_SAN: CAP_BYTES_CERT_SAN,
    SanitizationFieldKind.HTTP_BANNER: CAP_BYTES_HTTP_BANNER,
    SanitizationFieldKind.DNS_TXT_RECORD: CAP_BYTES_DNS_TXT_RECORD,
    SanitizationFieldKind.HTTP_SERVER_HEADER: CAP_BYTES_HTTP_SERVER_HEADER,
    SanitizationFieldKind.HTTP_PAGE_TITLE: CAP_BYTES_HTTP_PAGE_TITLE,
    SanitizationFieldKind.HTTP_REDIRECT_TARGET: CAP_BYTES_HTTP_REDIRECT_TARGET,
    SanitizationFieldKind.WHOIS_ORGANIZATION: CAP_BYTES_WHOIS_ORGANIZATION,
    SanitizationFieldKind.GENERIC: CAP_BYTES_GENERIC_FIELD,
}


def cap_for_kind(kind: SanitizationFieldKind) -> int:
    """Return the byte-count length cap for ``kind``.

    Pulled out as a function (rather than direct dict access at the call
    site) so the cap policy stays in this module and can be unit-tested.
    """

    return _CAP_BY_KIND[kind]


# === Suspicious-content flags (SPEC §7.1) ===================================
class SuspiciousFlag(str, Enum):
    """Named flags surfaced in the canonical observation's metadata.

    These are flags, not refusals. The graph still stores the sanitized
    content; the flag tells the analyst (and downstream attribution rules)
    that the field deserves a second look.
    """

    HTML_TAGS = "html_tags"
    EMBEDDED_MARKDOWN = "embedded_markdown"
    EMBEDDED_JSON = "embedded_json"
    VERY_LONG = "very_long"
    BASE64_BLOB = "base64_blob"
    CONTROL_CHARS_STRIPPED = "control_chars_stripped"
    LENGTH_CAPPED = "length_capped"
    NFC_NORMALIZED = "nfc_normalized"


# === Sanitization result =====================================================
@dataclass(frozen=True)
class SanitizedField:
    """Output of ``sanitize_field`` — the cleaned text plus diagnostic flags.

    ``flags`` is sorted (because frozen sets don't sort) and reported
    deterministically; downstream consumers iterate it for analyst tooling.
    """

    value: str
    flags: tuple[SuspiciousFlag, ...] = field(default_factory=tuple)
    original_byte_length: int = 0
    sanitized_byte_length: int = 0


# === Control-character stripping ============================================
# Match ASCII control characters EXCEPT the three SPEC §7.1 explicitly allows:
# tab (\t), newline (\n), carriage return (\r). Includes the C1 control set
# (U+0080-U+009F) which is rarely legitimate in plain text and a common
# vector for terminal-escape-style payloads.
_CONTROL_CHAR_RE = re.compile(
    r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F]"
)


def strip_control_chars(text: str) -> tuple[str, bool]:
    """Strip C0 + C1 control characters except ``\\t``, ``\\n``, ``\\r``.

    Returns the cleaned text and a flag indicating whether any characters
    were actually stripped (so the caller can decide whether to attach the
    ``CONTROL_CHARS_STRIPPED`` flag).
    """

    cleaned = _CONTROL_CHAR_RE.sub("", text)
    return cleaned, cleaned != text


# === NFC normalization ======================================================
def nfc_normalize(text: str) -> tuple[str, bool]:
    """Normalize ``text`` to Unicode NFC form (SPEC §7.1).

    Returns the normalized text and a flag indicating whether normalization
    actually changed anything. NFC is a canonical-composition form; combining
    characters are pre-composed where possible. This matters for IDN domain
    canonicalization and for stable equality comparisons across collector
    sources.
    """

    normalized = unicodedata.normalize("NFC", text)
    return normalized, normalized != text


# === Length capping =========================================================
def cap_length_bytes(text: str, cap: int) -> tuple[str, bool]:
    """Truncate ``text`` so its UTF-8 byte length is ≤ ``cap``.

    Truncates at codepoint boundaries (never produces a half-character).
    Returns the truncated text and a flag indicating whether truncation
    happened.
    """

    encoded = text.encode("utf-8")
    if len(encoded) <= cap:
        return text, False
    # Find the longest codepoint-boundary prefix whose byte length ≤ cap.
    truncated_bytes = encoded[:cap]
    # Drop trailing partial-multibyte by decoding with errors='ignore' which
    # produces a clean prefix; this matches what `text[:n]` would do but
    # measured in bytes, not codepoints.
    truncated = truncated_bytes.decode("utf-8", errors="ignore")
    return truncated, True


# === Suspicious-content detection ===========================================
_HTML_TAG_RE = re.compile(r"<[a-zA-Z][^>]{0,256}>")
_MARKDOWN_RE = re.compile(
    r"(\*\*[^*]{1,256}\*\*|\[[^\]]{1,256}\]\([^)]{1,256}\)|^#{1,6}\s)",
    re.MULTILINE,
)
_JSON_RE = re.compile(r"^\s*[\[{]")
_BASE64_RE = re.compile(r"^[A-Za-z0-9+/=]{40,}$")
_LONG_THRESHOLD_BYTES = 1024


def detect_suspicious(text: str) -> tuple[SuspiciousFlag, ...]:
    """Heuristic detection of fields that warrant analyst review.

    Returns a sorted tuple of ``SuspiciousFlag`` values. Heuristics are
    deliberately permissive — false positives are cheap (analyst skims the
    flag and moves on), but a missed adversarial payload can manipulate
    downstream LLM enrichment if it slips through.

    The detection runs on the *sanitized* text, not the original. That way
    flags reflect what's actually stored in the graph.
    """

    flags: set[SuspiciousFlag] = set()
    if _HTML_TAG_RE.search(text):
        flags.add(SuspiciousFlag.HTML_TAGS)
    if _MARKDOWN_RE.search(text):
        flags.add(SuspiciousFlag.EMBEDDED_MARKDOWN)
    if _JSON_RE.search(text):
        flags.add(SuspiciousFlag.EMBEDDED_JSON)
    if len(text.encode("utf-8")) > _LONG_THRESHOLD_BYTES:
        flags.add(SuspiciousFlag.VERY_LONG)
    if _BASE64_RE.match(text):
        flags.add(SuspiciousFlag.BASE64_BLOB)
    return tuple(sorted(flags, key=lambda f: f.value))


# === Top-level pipeline =====================================================
def sanitize_field(
    text: str,
    kind: SanitizationFieldKind = SanitizationFieldKind.GENERIC,
) -> SanitizedField:
    """Apply the SPEC §7.1 pipeline end-to-end to one external string field.

    Pipeline order matters:

    1. Strip control characters (cheap; reduces NFC work on garbage input).
    2. NFC normalize.
    3. Length-cap by field kind.
    4. Detect suspicious content on the *sanitized* output.

    Each step contributes flags. The returned ``SanitizedField`` is what the
    canonicalization layer passes downstream into the canonical artifact;
    the original raw bytes (if needed) live in the evidence object store.
    """

    original_bytes = len(text.encode("utf-8"))
    flags: list[SuspiciousFlag] = []

    # Step 1: strip control chars.
    cleaned, control_changed = strip_control_chars(text)
    if control_changed:
        flags.append(SuspiciousFlag.CONTROL_CHARS_STRIPPED)

    # Step 2: NFC normalize.
    normalized, nfc_changed = nfc_normalize(cleaned)
    if nfc_changed:
        flags.append(SuspiciousFlag.NFC_NORMALIZED)

    # Step 3: length cap.
    capped, was_capped = cap_length_bytes(normalized, cap_for_kind(kind))
    if was_capped:
        flags.append(SuspiciousFlag.LENGTH_CAPPED)

    # Step 4: detect suspicious content on sanitized output.
    detected = detect_suspicious(capped)

    # Combine, dedupe, sort for deterministic output.
    combined = sorted({*flags, *detected}, key=lambda f: f.value)

    return SanitizedField(
        value=capped,
        flags=tuple(combined),
        original_byte_length=original_bytes,
        sanitized_byte_length=len(capped.encode("utf-8")),
    )


__all__ = [
    "CAP_BYTES_CERT_SAN",
    "CAP_BYTES_DNS_TXT_RECORD",
    "CAP_BYTES_GENERIC_FIELD",
    "CAP_BYTES_HTTP_BANNER",
    "CAP_BYTES_HTTP_PAGE_TITLE",
    "CAP_BYTES_HTTP_REDIRECT_TARGET",
    "CAP_BYTES_HTTP_SERVER_HEADER",
    "CAP_BYTES_WHOIS_ORGANIZATION",
    "SanitizationFieldKind",
    "SanitizedField",
    "SuspiciousFlag",
    "cap_for_kind",
    "cap_length_bytes",
    "detect_suspicious",
    "nfc_normalize",
    "sanitize_field",
    "strip_control_chars",
]
