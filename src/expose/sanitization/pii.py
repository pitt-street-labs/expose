"""Regex-based PII detection and redaction for WHOIS/RDAP contact fields.

This module provides a centralized, reusable PII detection + redaction layer
for the EXPOSE sanitization pipeline (SPEC §7.1).  It targets the specific
patterns found in domain registration data:

- Email addresses
- Phone numbers (international and US formats)
- Personal names (heuristic — 2-3 capitalized words without org indicators)
- Street address fragments
- National IDs (US SSN pattern for v1)

This is deliberately **NOT** a general-purpose PII detector.  It uses regex
patterns only — no ML dependencies, no external services.  The heuristic
personal-name detection mirrors the logic in
:mod:`expose.collectors.builtin.rdap_whois` (``_looks_like_personal_name``)
but is exposed here for reuse across the pipeline.

FIPS gate: This module does not import ``hashlib`` or ``secrets``
(per ADR-010).
"""

from __future__ import annotations

import re
from enum import StrEnum

from pydantic import BaseModel, ConfigDict


class PIICategory(StrEnum):
    """Categories of personally identifiable information detected."""

    EMAIL = "email"
    PHONE = "phone"
    PERSON_NAME = "person_name"
    STREET_ADDRESS = "street_address"
    NATIONAL_ID = "national_id"  # SSN, passport, etc.


class PIIDetection(BaseModel):
    """A single PII detection within source text.

    ``start`` and ``end`` are character offsets into the original string.
    ``confidence`` is a heuristic score (0.0-1.0) — high for deterministic
    patterns like email (0.95), lower for ambiguous ones like personal
    names (0.6).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    category: PIICategory
    value: str
    start: int
    end: int
    confidence: float


class PIIResult(BaseModel):
    """Result of PII detection + optional redaction on a text string.

    ``pii_found`` is a convenience boolean — ``True`` iff ``detections``
    is non-empty.  ``redacted`` contains the text with all detected PII
    replaced by the replacement string.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    original: str
    redacted: str
    detections: list[PIIDetection]
    pii_found: bool


# ---------------------------------------------------------------------------
# Detection patterns
# ---------------------------------------------------------------------------

# Email: standard pattern matching user@domain.tld
_EMAIL_RE = re.compile(r"[\w.-]+@[\w.-]+\.\w{2,}")

# Phone: international format, US format, various separators.
# Matches +1-555-123-4567, +44 20 7123 4567, (555) 123-4567, 555.123.4567
_PHONE_RE = re.compile(
    r"\+?\d{1,3}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}"
)

# Street address: number + street name + suffix.
# Matches "123 Main St", "4500 Technology Blvd", "10 Downing Street".
_STREET_RE = re.compile(
    r"\d+\s+\w+\s+(?:St(?:reet)?|Ave(?:nue)?|Rd|Blvd|Dr(?:ive)?|Ln|Way|Ct|Pl|Terr|Circle)\b",
    re.IGNORECASE,
)

# National ID: US SSN pattern (xxx-xx-xxxx).  Only US for v1.
_SSN_RE = re.compile(r"\d{3}-\d{2}-\d{4}")

# Personal name heuristic: 2-3 capitalized words.
# This is deliberately the same pattern as rdap_whois._PERSONAL_NAME_RE.
_PERSONAL_NAME_RE = re.compile(r"[A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2}")

# Organization indicators — names containing these are NOT personal names.
# Mirrors rdap_whois._ORG_INDICATORS_RE but compiled once here for reuse.
_ORG_INDICATORS_RE = re.compile(
    r"""
    (?:
        \b(?:Inc|LLC|Ltd|Corp|Co|GmbH|AG|SA|BV|NV|AB|Oy|AS|SRL|PLC)\.?\b
        | \b(?:Association|Authority|Foundation|Institute|University|Ministry)\b
        | \b(?:Department|Bureau|Agency|Commission|Council|Board)\b
        | \b(?:Group|Holdings|Partners|Services|Solutions|Technologies)\b
        | \b(?:Networks|Communications|Telecom|Systems|Labs?|Laboratories)\b
        | ,\s  # "Acme, Inc." pattern
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)

# Per-category confidence scores.  Deterministic patterns (email, SSN) get
# high confidence; heuristic patterns (personal names) get lower scores.
_CONFIDENCE: dict[PIICategory, float] = {
    PIICategory.EMAIL: 0.95,
    PIICategory.PHONE: 0.85,
    PIICategory.PERSON_NAME: 0.6,
    PIICategory.STREET_ADDRESS: 0.8,
    PIICategory.NATIONAL_ID: 0.95,
}


def _is_org_name(candidate: str, context: str = "", match_end: int = 0) -> bool:
    """Return True if ``candidate`` looks like an organization, not a person.

    When ``context`` and ``match_end`` are provided, a small window of text
    after the match is also checked for org indicators.  This catches cases
    like "Deutsche Telekom AG" where the regex matches "Deutsche Telekom"
    but the org indicator "AG" follows immediately after.

    The trailing window is deliberately short (20 chars) so that distant org
    indicators (e.g., "John Smith works at Cloudflare Inc") do not suppress
    legitimate personal-name detections.
    """
    if _ORG_INDICATORS_RE.search(candidate):
        return True
    # Check a small trailing window for adjacent org indicators.
    if context and match_end > 0:
        trailing = context[match_end : match_end + 20]
        if _ORG_INDICATORS_RE.search(trailing):
            return True
    return False


class PIIDetector:
    """Regex-based PII detection for WHOIS/RDAP contact fields.

    This is NOT a general-purpose PII detector.  It targets the specific
    patterns found in domain registration data: email addresses, phone
    numbers in international format, personal names (heuristic), and
    street address fragments.
    """

    def detect(self, text: str) -> list[PIIDetection]:
        """Find PII patterns in ``text``.

        Returns a list of :class:`PIIDetection` objects, one per match,
        sorted by start offset.  Overlapping matches are all reported;
        the caller decides how to handle them.
        """
        detections: list[PIIDetection] = []

        # Email
        for m in _EMAIL_RE.finditer(text):
            detections.append(
                PIIDetection(
                    category=PIICategory.EMAIL,
                    value=m.group(),
                    start=m.start(),
                    end=m.end(),
                    confidence=_CONFIDENCE[PIICategory.EMAIL],
                )
            )

        # Phone
        for m in _PHONE_RE.finditer(text):
            detections.append(
                PIIDetection(
                    category=PIICategory.PHONE,
                    value=m.group(),
                    start=m.start(),
                    end=m.end(),
                    confidence=_CONFIDENCE[PIICategory.PHONE],
                )
            )

        # Street address
        for m in _STREET_RE.finditer(text):
            detections.append(
                PIIDetection(
                    category=PIICategory.STREET_ADDRESS,
                    value=m.group(),
                    start=m.start(),
                    end=m.end(),
                    confidence=_CONFIDENCE[PIICategory.STREET_ADDRESS],
                )
            )

        # National ID (SSN)
        for m in _SSN_RE.finditer(text):
            detections.append(
                PIIDetection(
                    category=PIICategory.NATIONAL_ID,
                    value=m.group(),
                    start=m.start(),
                    end=m.end(),
                    confidence=_CONFIDENCE[PIICategory.NATIONAL_ID],
                )
            )

        # Personal name (heuristic — skip org names)
        for m in _PERSONAL_NAME_RE.finditer(text):
            candidate = m.group()
            if not _is_org_name(candidate, context=text, match_end=m.end()):
                detections.append(
                    PIIDetection(
                        category=PIICategory.PERSON_NAME,
                        value=candidate,
                        start=m.start(),
                        end=m.end(),
                        confidence=_CONFIDENCE[PIICategory.PERSON_NAME],
                    )
                )

        # Sort by start offset for deterministic output.
        detections.sort(key=lambda d: d.start)
        return detections

    def redact(self, text: str, replacement: str = "[REDACTED]") -> PIIResult:
        """Detect and redact PII from ``text``.

        All detected PII spans are replaced with ``replacement``.
        Replacement proceeds right-to-left (by descending start offset)
        so character offsets in earlier detections remain valid.

        Returns a :class:`PIIResult` with both the original and redacted
        text, plus the full detection list.
        """
        detections = self.detect(text)
        redacted = text

        # Replace right-to-left so offsets stay valid.
        for det in reversed(detections):
            redacted = redacted[: det.start] + replacement + redacted[det.end :]

        return PIIResult(
            original=text,
            redacted=redacted,
            detections=detections,
            pii_found=len(detections) > 0,
        )

    def contains_pii(self, text: str) -> bool:
        """Quick check: does ``text`` contain any PII patterns?

        This is a short-circuit convenience — it returns as soon as the
        first pattern matches, without building the full detection list.
        """
        if _EMAIL_RE.search(text):
            return True
        if _PHONE_RE.search(text):
            return True
        if _SSN_RE.search(text):
            return True
        if _STREET_RE.search(text):
            return True
        # Personal name check requires the org-indicator filter.
        return any(
            not _is_org_name(m.group(), context=text, match_end=m.end())
            for m in _PERSONAL_NAME_RE.finditer(text)
        )


__all__ = [
    "PIICategory",
    "PIIDetection",
    "PIIDetector",
    "PIIResult",
]
