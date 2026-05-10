"""Sanitization and canonicalization layer (per SPEC.md §7).

Stage 3 of the EXPOSE pipeline (SPEC §2.2). The trust boundary between
untrusted external content and the canonical observation graph.

Two complementary modules:

- ``text`` — field-level sanitization (control-char strip, NFC normalize,
  length caps, suspicious-content flagging).
- ``canonicalize`` — typed canonicalization (lowercase IDN domains, canonical
  IPv6, lowercase hex cert fingerprints, UTC ISO 8601), plus the
  ``<external_observation>`` LLM prompt-wrapper from SPEC §7.3.

This package is the single chokepoint between collector output and graph
upsert. Collectors emit raw observations; the dispatcher runs them through
this layer; the graph only ever sees the canonicalized output.
"""

from expose.sanitization.canonicalize import (
    LLM_SYSTEM_PROMPT_PREFIX,
    CanonicalizationError,
    canonicalize_cidr,
    canonicalize_domain,
    canonicalize_ip,
    canonicalize_service_id,
    canonicalize_timestamp,
    normalize_cert_fingerprint,
    wrap_for_llm_prompt,
)
from expose.sanitization.text import (
    CAP_BYTES_CERT_SAN,
    CAP_BYTES_DNS_TXT_RECORD,
    CAP_BYTES_GENERIC_FIELD,
    CAP_BYTES_HTTP_BANNER,
    CAP_BYTES_HTTP_PAGE_TITLE,
    CAP_BYTES_HTTP_REDIRECT_TARGET,
    CAP_BYTES_HTTP_SERVER_HEADER,
    CAP_BYTES_WHOIS_ORGANIZATION,
    SanitizationFieldKind,
    SanitizedField,
    SuspiciousFlag,
    cap_for_kind,
    cap_length_bytes,
    detect_suspicious,
    nfc_normalize,
    sanitize_field,
    strip_control_chars,
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
    "LLM_SYSTEM_PROMPT_PREFIX",
    "CanonicalizationError",
    "SanitizationFieldKind",
    "SanitizedField",
    "SuspiciousFlag",
    "canonicalize_cidr",
    "canonicalize_domain",
    "canonicalize_ip",
    "canonicalize_service_id",
    "canonicalize_timestamp",
    "cap_for_kind",
    "cap_length_bytes",
    "detect_suspicious",
    "nfc_normalize",
    "normalize_cert_fingerprint",
    "sanitize_field",
    "strip_control_chars",
    "wrap_for_llm_prompt",
]
