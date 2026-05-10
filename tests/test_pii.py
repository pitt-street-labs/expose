"""Tests for the PII detection and redaction module (issue #32).

Coverage:

 1. Detect email address.
 2. Detect phone number (international format).
 3. Detect phone number (US format).
 4. Detect person name ("John Smith").
 5. Don't flag org name as person name ("Cloudflare Inc").
 6. Detect street address.
 7. Detect SSN pattern.
 8. No PII in clean text produces empty detections.
 9. Multiple PII types in one string.
10. Redact replaces all PII with placeholder.
11. Redact preserves non-PII text.
12. PIIResult.pii_found is True when PII detected.
13. PIIResult.pii_found is False when clean.
14. Custom replacement string works.
15. Detection confidence is set appropriately (email=0.95, name=0.6).
16. contains_pii short-circuit returns correct booleans.

All tests are synchronous — the PII detector is a pure-CPU regex layer
with no I/O.
"""

from __future__ import annotations

import pytest

from expose.sanitization.pii import PIICategory, PIIDetector


@pytest.fixture
def detector() -> PIIDetector:
    """Fresh PIIDetector per test."""
    return PIIDetector()


# ---------------------------------------------------------------------------
# 1. Detect email address
# ---------------------------------------------------------------------------
def test_detect_email(detector: PIIDetector) -> None:
    """An email address in the text is detected with category EMAIL."""
    detections = detector.detect("Contact: admin@example.com for info")
    assert len(detections) == 1
    assert detections[0].category == PIICategory.EMAIL
    assert detections[0].value == "admin@example.com"
    assert detections[0].start == 9
    assert detections[0].end == 26


# ---------------------------------------------------------------------------
# 2. Detect phone number (international format)
# ---------------------------------------------------------------------------
def test_detect_phone_international(detector: PIIDetector) -> None:
    """International phone numbers with country code are detected."""
    detections = detector.detect("Call +44 20 7123 4567 for support")
    phones = [d for d in detections if d.category == PIICategory.PHONE]
    assert len(phones) >= 1
    assert "+44 20 7123 4567" in phones[0].value


# ---------------------------------------------------------------------------
# 3. Detect phone number (US format)
# ---------------------------------------------------------------------------
def test_detect_phone_us(detector: PIIDetector) -> None:
    """US-format phone numbers are detected."""
    detections = detector.detect("Phone: 555-123-4567")
    phones = [d for d in detections if d.category == PIICategory.PHONE]
    assert len(phones) >= 1
    assert "555-123-4567" in phones[0].value


# ---------------------------------------------------------------------------
# 4. Detect person name
# ---------------------------------------------------------------------------
def test_detect_person_name(detector: PIIDetector) -> None:
    """Two capitalized words matching a personal name pattern are flagged."""
    detections = detector.detect("Registrant: John Smith")
    names = [d for d in detections if d.category == PIICategory.PERSON_NAME]
    assert len(names) >= 1
    assert "John Smith" in names[0].value


# ---------------------------------------------------------------------------
# 5. Don't flag org name as person name
# ---------------------------------------------------------------------------
def test_org_name_not_flagged(detector: PIIDetector) -> None:
    """Organization names with indicators (Inc, LLC, etc.) are not PII."""
    org_strings = [
        "Cloudflare Inc",
        "Amazon Web Services LLC",
        "Mozilla Foundation",
        "Acme Technologies Group",
        "Deutsche Telekom AG",
    ]
    for org in org_strings:
        detections = detector.detect(org)
        names = [d for d in detections if d.category == PIICategory.PERSON_NAME]
        assert len(names) == 0, f"Org name falsely flagged as person: {org}"


# ---------------------------------------------------------------------------
# 6. Detect street address
# ---------------------------------------------------------------------------
def test_detect_street_address(detector: PIIDetector) -> None:
    """A street address pattern is detected."""
    detections = detector.detect("Located at 123 Main St in Springfield")
    addrs = [d for d in detections if d.category == PIICategory.STREET_ADDRESS]
    assert len(addrs) == 1
    assert "123 Main St" in addrs[0].value


# ---------------------------------------------------------------------------
# 7. Detect SSN pattern
# ---------------------------------------------------------------------------
def test_detect_ssn(detector: PIIDetector) -> None:
    """A US SSN pattern (xxx-xx-xxxx) is detected as NATIONAL_ID."""
    detections = detector.detect("SSN: 123-45-6789")
    ssns = [d for d in detections if d.category == PIICategory.NATIONAL_ID]
    assert len(ssns) >= 1
    assert ssns[0].value == "123-45-6789"


# ---------------------------------------------------------------------------
# 8. No PII in clean text
# ---------------------------------------------------------------------------
def test_clean_text_no_detections(detector: PIIDetector) -> None:
    """Text without PII produces an empty detection list."""
    detections = detector.detect("example.com nameserver ns1.example.com")
    # "example.com" alone is not an email — no '@' sign.
    names = [d for d in detections if d.category == PIICategory.PERSON_NAME]
    emails = [d for d in detections if d.category == PIICategory.EMAIL]
    assert len(names) == 0
    assert len(emails) == 0


# ---------------------------------------------------------------------------
# 9. Multiple PII types in one string
# ---------------------------------------------------------------------------
def test_multiple_pii_types(detector: PIIDetector) -> None:
    """A string containing multiple PII types yields detections for each."""
    text = "John Smith, admin@example.com, 555-123-4567, 123 Main St"
    detections = detector.detect(text)
    categories_found = {d.category for d in detections}
    assert PIICategory.PERSON_NAME in categories_found
    assert PIICategory.EMAIL in categories_found
    assert PIICategory.PHONE in categories_found
    assert PIICategory.STREET_ADDRESS in categories_found


# ---------------------------------------------------------------------------
# 10. Redact replaces all PII with placeholder
# ---------------------------------------------------------------------------
def test_redact_replaces_pii(detector: PIIDetector) -> None:
    """All detected PII spans are replaced by the default placeholder."""
    result = detector.redact("Contact admin@example.com or call 555-123-4567")
    assert "admin@example.com" not in result.redacted
    assert "555-123-4567" not in result.redacted
    assert "[REDACTED]" in result.redacted


# ---------------------------------------------------------------------------
# 11. Redact preserves non-PII text
# ---------------------------------------------------------------------------
def test_redact_preserves_non_pii(detector: PIIDetector) -> None:
    """Non-PII portions of the text survive redaction unchanged."""
    result = detector.redact("Contact admin@example.com for info")
    assert result.redacted.startswith("Contact ")
    assert result.redacted.endswith(" for info")


# ---------------------------------------------------------------------------
# 12. PIIResult.pii_found is True when PII detected
# ---------------------------------------------------------------------------
def test_pii_found_true(detector: PIIDetector) -> None:
    """pii_found is True when the text contains detectable PII."""
    result = detector.redact("admin@example.com")
    assert result.pii_found is True


# ---------------------------------------------------------------------------
# 13. PIIResult.pii_found is False when clean
# ---------------------------------------------------------------------------
def test_pii_found_false(detector: PIIDetector) -> None:
    """pii_found is False when the text contains no detectable PII."""
    result = detector.redact("example.com is a domain name")
    assert result.pii_found is False
    assert len(result.detections) == 0


# ---------------------------------------------------------------------------
# 14. Custom replacement string works
# ---------------------------------------------------------------------------
def test_custom_replacement(detector: PIIDetector) -> None:
    """A custom replacement string is used instead of the default."""
    result = detector.redact("admin@example.com", replacement="***")
    assert "***" in result.redacted
    assert "admin@example.com" not in result.redacted
    assert "[REDACTED]" not in result.redacted


# ---------------------------------------------------------------------------
# 15. Detection confidence is set appropriately
# ---------------------------------------------------------------------------
def test_confidence_levels(detector: PIIDetector) -> None:
    """Email gets 0.95 confidence; person name gets 0.6."""
    text = "John Smith admin@example.com"
    detections = detector.detect(text)

    email_dets = [d for d in detections if d.category == PIICategory.EMAIL]
    name_dets = [d for d in detections if d.category == PIICategory.PERSON_NAME]

    assert len(email_dets) >= 1
    assert email_dets[0].confidence == pytest.approx(0.95)

    assert len(name_dets) >= 1
    assert name_dets[0].confidence == pytest.approx(0.6)


# ---------------------------------------------------------------------------
# 16. contains_pii short-circuit
# ---------------------------------------------------------------------------
def test_contains_pii_true(detector: PIIDetector) -> None:
    """contains_pii returns True for text with PII."""
    assert detector.contains_pii("admin@example.com") is True


def test_contains_pii_false(detector: PIIDetector) -> None:
    """contains_pii returns False for clean text."""
    assert detector.contains_pii("example.com is a domain") is False


# ---------------------------------------------------------------------------
# 17. PIIResult model is frozen (immutable)
# ---------------------------------------------------------------------------
def test_pii_result_frozen(detector: PIIDetector) -> None:
    """PIIResult instances are immutable (frozen Pydantic model)."""
    result = detector.redact("admin@example.com")
    with pytest.raises(Exception):  # noqa: B017
        result.redacted = "tampered"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# 18. Original text is preserved in PIIResult
# ---------------------------------------------------------------------------
def test_original_preserved(detector: PIIDetector) -> None:
    """The original text is stored verbatim in the result."""
    original = "Contact admin@example.com"
    result = detector.redact(original)
    assert result.original == original
