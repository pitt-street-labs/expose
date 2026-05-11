"""Screenshot vision collector (Tier 2, passive, targeted — per issue #48).

Captures HTTP response content from DOMAIN and IP seeds for downstream
vision analysis (Stage 4c).  For each seed, issues an HTTP GET via
``httpx`` and extracts:

- ``page_title`` — content of the ``<title>`` element (first 2048 bytes).
- ``meta_description`` — ``<meta name="description" content="...">`` value.
- ``body_text_preview`` — first 2000 characters of the decoded body.
- ``status_code`` — HTTP status code.
- ``content_type`` — response ``Content-Type`` header.

Only HTML responses are captured (``text/html`` content-type); non-HTML
responses are skipped with a warning.  Response bodies are capped at 1 MB
to avoid memory pressure on large downloads.

Observations use ``ObservationType.HTTP_RESPONSE`` (the closest match in
the enum) with ``technique_ids = ["T1592.004"]`` (Gather Victim Host
Information: Client Configurations).

Dependencies
------------
- ``httpx`` (in project deps) for async HTTP.
- No ``hashlib`` / ``secrets`` — FIPS gate clean (ADR-010).
"""

from __future__ import annotations

import logging
import re
import time
import warnings
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any, ClassVar

import httpx

from expose.collectors.base import (
    Collector,
    CollectorConfig,
    CollectorHealthCheck,
    Observation,
    ObservationSubject,
    ObservationType,
    Seed,
    SeedType,
)
from expose.collectors.registry import register_collector
from expose.collectors.tiers import CollectorTier
from expose.sanitization.canonicalize import canonicalize_domain, canonicalize_ip
from expose.sanitization.text import SanitizationFieldKind, sanitize_field
from expose.types.canonical import CollectorStatus, IdentifierType

logger = logging.getLogger(__name__)

# Maximum response body size (1 MB).  Responses exceeding this are
# truncated before any content extraction.
_MAX_BODY_BYTES = 1_048_576  # 1 MB

# Maximum characters for the body_text_preview field.
_BODY_TEXT_PREVIEW_CAP = 2000

# Title extraction regex — matches the first <title> element.
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

# Meta description extraction — matches <meta name="description" content="...">.
_META_DESC_RE = re.compile(
    r'<meta\s+[^>]*name\s*=\s*["\']description["\']\s+[^>]*content\s*=\s*["\']([^"\']*)["\']',
    re.IGNORECASE | re.DOTALL,
)
# Also match the reversed attribute order (content before name).
_META_DESC_RE_ALT = re.compile(
    r'<meta\s+[^>]*content\s*=\s*["\']([^"\']*)["\'][^>]*name\s*=\s*["\']description["\']',
    re.IGNORECASE | re.DOTALL,
)

# Health-check target — a well-known, high-availability endpoint.
_HEALTH_CHECK_URL = "https://httpbin.org/head"


def _resolve_identifier(
    host: str, seed_type: SeedType
) -> tuple[IdentifierType, str]:
    """Determine the identifier type and canonical value for a host string."""
    if seed_type == SeedType.IP:
        canonical = canonicalize_ip(host)
        return IdentifierType.IP, canonical
    canonical = canonicalize_domain(host)
    return IdentifierType.DOMAIN, canonical


def _extract_title(body_text: str) -> str | None:
    """Extract <title> content from HTML text."""
    match = _TITLE_RE.search(body_text[:2048])
    if match:
        raw_title = match.group(1).strip()
        if raw_title:
            return sanitize_field(
                raw_title, SanitizationFieldKind.HTTP_PAGE_TITLE
            ).value
    return None


def _extract_meta_description(body_text: str) -> str | None:
    """Extract <meta name="description" content="..."> from HTML text."""
    for pattern in (_META_DESC_RE, _META_DESC_RE_ALT):
        match = pattern.search(body_text[:4096])
        if match:
            raw_desc = match.group(1).strip()
            if raw_desc:
                return sanitize_field(
                    raw_desc, SanitizationFieldKind.GENERIC
                ).value
    return None


def _extract_body_text_preview(body_text: str) -> str:
    """Extract the first _BODY_TEXT_PREVIEW_CAP characters of the body.

    Strips HTML tags for a cleaner preview, then truncates.
    """
    # Rough HTML tag removal for preview purposes.
    stripped = re.sub(r"<[^>]+>", " ", body_text)
    # Collapse whitespace.
    stripped = re.sub(r"\s+", " ", stripped).strip()
    return stripped[:_BODY_TEXT_PREVIEW_CAP]


@register_collector
class ScreenshotVisionCollector(Collector):
    """Tier-2 passive/targeted collector for web content capture.

    Fetches HTTP responses from DOMAIN/IP seeds and extracts structured
    metadata for downstream vision analysis (Stage 4c).  Only processes
    HTML responses; non-HTML content is skipped with a warning.
    """

    collector_id: str = "screenshot-vision"
    collector_version: str = "0.1.0"
    tier: CollectorTier = CollectorTier.TIER_2
    requires_credentials: bool = False
    rate_limit_per_minute: int | None = None
    technique_ids: ClassVar[list[str]] = ["T1592.004"]

    # ------------------------------------------------------------------
    # expand
    # ------------------------------------------------------------------
    async def expand(self, seed: Seed) -> AsyncIterator[Observation]:
        """Fetch HTTP response from seed and yield observation with content."""
        if seed.seed_type not in {SeedType.DOMAIN, SeedType.IP}:
            return

        host = seed.value
        identifier_type, canonical_value = _resolve_identifier(
            host, seed.seed_type
        )

        # Try HTTPS first, fall back to HTTP.
        urls = [f"https://{host}", f"http://{host}"]
        obs_warnings: list[str] = []

        for url in urls:
            try:
                observation = await self._fetch_and_build(
                    url=url,
                    host=host,
                    identifier_type=identifier_type,
                    canonical_value=canonical_value,
                    obs_warnings=obs_warnings,
                )
                if observation is not None:
                    yield observation
                    return  # One successful fetch is enough.
            except (httpx.ConnectError, httpx.ConnectTimeout, OSError) as exc:
                msg = f"Connection failed for {url}: {exc}"
                obs_warnings.append(msg)
                logger.debug(msg)
            except httpx.TooManyRedirects as exc:
                msg = f"Too many redirects for {url}: {exc}"
                obs_warnings.append(msg)
                logger.debug(msg)

        # All URLs failed -- emit a warning observation rather than raising.
        # This is a Tier-2 passive collector; total failure is expected for
        # hosts that do not serve HTTP.
        logger.info(
            "screenshot-vision: all probes failed for %s: %s",
            host,
            "; ".join(obs_warnings),
        )

    # ------------------------------------------------------------------
    # health_check
    # ------------------------------------------------------------------
    async def health_check(self) -> CollectorHealthCheck:
        """Quick reachability probe using HEAD to a known endpoint."""
        start = time.monotonic()
        try:
            with warnings.catch_warnings():
                warnings.filterwarnings("ignore", category=DeprecationWarning)
                warnings.filterwarnings(
                    "ignore", message="Unverified HTTPS request"
                )
                async with httpx.AsyncClient(verify=False) as client:  # noqa: S501
                    resp = await client.head(
                        _HEALTH_CHECK_URL,
                        timeout=self.config.request_timeout_seconds,
                    )
            latency = (time.monotonic() - start) * 1000.0
            return CollectorHealthCheck(
                collector_id=self.collector_id,
                collector_version=self.collector_version,
                status=(
                    CollectorStatus.SUCCESS
                    if resp.status_code < 500  # noqa: PLR2004
                    else CollectorStatus.FAILURE
                ),
                checked_at=datetime.now(tz=UTC),
                latency_ms=latency,
            )
        except Exception as exc:
            latency = (time.monotonic() - start) * 1000.0
            return CollectorHealthCheck(
                collector_id=self.collector_id,
                collector_version=self.collector_version,
                status=CollectorStatus.FAILURE,
                checked_at=datetime.now(tz=UTC),
                latency_ms=latency,
                error_message=str(exc),
            )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _egress_httpx_kwargs(self) -> dict[str, Any]:
        """Extract httpx client kwargs from the egress profile, if configured."""
        egress_profile = self.config.extra.get("egress_profile")
        if egress_profile is not None:
            from expose.egress.base import EgressProfile  # noqa: PLC0415

            if isinstance(egress_profile, EgressProfile):
                return egress_profile.configure_httpx_client()
        return {}

    async def _fetch_and_build(
        self,
        *,
        url: str,
        host: str,
        identifier_type: IdentifierType,
        canonical_value: str,
        obs_warnings: list[str],
    ) -> Observation | None:
        """Fetch URL and build an Observation if response is HTML.

        Returns None if the response is not HTML (with a warning appended).
        """
        egress_kwargs = self._egress_httpx_kwargs()
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", category=DeprecationWarning)
            warnings.filterwarnings("ignore", message="Unverified HTTPS request")
            async with httpx.AsyncClient(
                **egress_kwargs,
                verify=False,  # noqa: S501
                max_redirects=5,
                timeout=self.config.request_timeout_seconds,
                follow_redirects=True,
            ) as client:
                client.headers["User-Agent"] = self.config.user_agent
                response = await client.get(url)

        # Check content-type for HTML.
        content_type = response.headers.get("content-type", "")
        if "text/html" not in content_type.lower():
            obs_warnings.append(
                f"Non-HTML content-type from {url}: {content_type}"
            )
            return None

        # Cap response body at _MAX_BODY_BYTES.
        body_bytes = response.content[:_MAX_BODY_BYTES]
        body_text = body_bytes.decode("utf-8", errors="replace")

        # Extract structured fields.
        page_title = _extract_title(body_text)
        meta_description = _extract_meta_description(body_text)
        body_text_preview = _extract_body_text_preview(body_text)
        status_code = response.status_code

        # Sanitize content-type.
        sanitized_ct = sanitize_field(
            content_type, SanitizationFieldKind.GENERIC
        ).value

        payload: dict[str, Any] = {
            "url": sanitize_field(
                str(response.url), SanitizationFieldKind.HTTP_REDIRECT_TARGET
            ).value,
            "page_title": page_title,
            "meta_description": meta_description,
            "body_text_preview": body_text_preview,
            "status_code": status_code,
            "content_type": sanitized_ct,
        }

        return Observation(
            collector_id=self.collector_id,
            collector_version=self.collector_version,
            tenant_id=self.config.tenant_id,
            observation_type=ObservationType.HTTP_RESPONSE,
            subject=ObservationSubject(
                identifier_type=identifier_type,
                identifier_value=canonical_value,
            ),
            observed_at=datetime.now(tz=UTC),
            structured_payload=payload,
            evidence_blob=body_bytes,
            evidence_blob_content_type="text/html",
            warnings=obs_warnings[:],
        )


__all__ = [
    "ScreenshotVisionCollector",
]
