"""Microsoft Sentinel (Log Analytics Data Collector API) adapter.

Delivers EXPOSE observations and findings to a Microsoft Sentinel workspace
via the HTTP Data Collector API.  Authentication uses HMAC-SHA256 signatures
computed per the Azure documentation:

    https://learn.microsoft.com/en-us/azure/azure-monitor/logs/data-collector-api

The signature covers: ``POST\\n{content-length}\\napplication/json\\n
x-ms-date:{rfc1123-date}\\n/api/logs``.

Events are written to custom log tables ``EXPOSE_Observations_CL`` and
``EXPOSE_Findings_CL``.  Field names carry Log Analytics type suffixes
(``_s`` for string, ``_d`` for double, ``_t`` for datetime).

FIPS note: HMAC-SHA256 uses ``cryptography.hazmat.primitives.hmac.HMAC``
(not stdlib ``hmac`` / ``hashlib``) to stay within the ADR-010 FIPS boundary.
"""

from __future__ import annotations

# Copyright 2026 Korlogos / Pitt Street Labs. All rights reserved.
# This file is part of EXPOSE Commercial Modules and is NOT covered by the
# Apache 2.0 license that governs the core engine. Unauthorized copying,
# distribution, or use of this file is strictly prohibited. Contact
# licensing@korlogos.com for commercial licensing terms.

import base64
import json
import logging
import time
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import httpx
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC

from expose.integrations.siem import (
    CircuitBreakerOpen,
    DeliveryResult,
    SIEMAdapter,
    SIEMConfig,
    TenantMismatchError,
)

__all__ = ["SentinelAdapter"]

logger = logging.getLogger(__name__)

# Custom table names for Sentinel.
_OBSERVATIONS_TABLE = "EXPOSE_Observations_CL"
_FINDINGS_TABLE = "EXPOSE_Findings_CL"


class SentinelAdapter(SIEMAdapter):
    """Microsoft Sentinel Log Analytics Data Collector adapter."""

    adapter_id = "sentinel"
    display_name = "Microsoft Sentinel"

    def __init__(
        self,
        config: SIEMConfig,
        *,
        workspace_id: str = "",
        tenant_id: UUID | None = None,
    ) -> None:
        super().__init__(config, tenant_id=tenant_id)
        self._workspace_id = workspace_id or self._extract_workspace_id(config.endpoint)

    # ----- public interface ---------------------------------------------------

    async def send_observations(
        self,
        observations: list[dict[str, Any]],
        tenant_id: UUID,
    ) -> DeliveryResult:
        """Deliver observations to the EXPOSE_Observations_CL table."""
        self._validate_tenant(tenant_id)
        if not self._config.enabled:
            return DeliveryResult(
                adapter_id=self.adapter_id,
                success=True,
                events_sent=0,
                events_failed=0,
                duration_ms=0.0,
            )

        start = time.monotonic()
        total_sent = 0
        total_failed = 0

        for i in range(0, len(observations), self._config.batch_size):
            batch = observations[i : i + self._config.batch_size]
            mapped = [self._map_observation(obs, tenant_id) for obs in batch]
            body = json.dumps(mapped, separators=(",", ":"), sort_keys=True)

            try:
                response = await self._post_log_analytics(
                    body,
                    _OBSERVATIONS_TABLE,
                )
                if 200 <= response.status_code < 300:  # noqa: PLR2004
                    total_sent += len(batch)
                else:
                    total_failed += len(batch)
            except (httpx.HTTPError, httpx.HTTPStatusError, CircuitBreakerOpen):
                total_failed += len(batch)

        return self._timed_result(
            success=total_failed == 0,
            events_sent=total_sent,
            events_failed=total_failed,
            start=start,
            error=f"{total_failed} events failed" if total_failed else None,
        )

    async def send_finding(
        self,
        finding: dict[str, Any],
        tenant_id: UUID,
    ) -> DeliveryResult:
        """Deliver a single finding to the EXPOSE_Findings_CL table."""
        self._validate_tenant(tenant_id)
        if not self._config.enabled:
            return DeliveryResult(
                adapter_id=self.adapter_id,
                success=True,
                events_sent=0,
                events_failed=0,
                duration_ms=0.0,
            )

        start = time.monotonic()
        mapped = [self._map_finding(finding, tenant_id)]
        body = json.dumps(mapped, separators=(",", ":"), sort_keys=True)

        try:
            response = await self._post_log_analytics(body, _FINDINGS_TABLE)
            success = 200 <= response.status_code < 300  # noqa: PLR2004
            return self._timed_result(
                success=success,
                events_sent=1 if success else 0,
                events_failed=0 if success else 1,
                start=start,
                error=None if success else f"HTTP {response.status_code}",
            )
        except (httpx.HTTPError, httpx.HTTPStatusError, CircuitBreakerOpen) as exc:
            return self._timed_result(
                success=False,
                events_sent=0,
                events_failed=1,
                start=start,
                error=str(exc),
            )

    async def health_check(self) -> bool:
        """Verify Sentinel endpoint is reachable (POST with empty array)."""
        try:
            body = "[]"
            response = await self._post_log_analytics(body, _OBSERVATIONS_TABLE)
            # Sentinel returns 200 even for empty payloads when auth is valid.
            return 200 <= response.status_code < 400  # noqa: PLR2004
        except (httpx.HTTPError, httpx.HTTPStatusError):
            return False

    # ----- HMAC signature construction ----------------------------------------

    @staticmethod
    def build_signature(
        workspace_id: str,
        shared_key: str,
        date: str,
        content_length: int,
        method: str = "POST",
        content_type: str = "application/json",
        resource: str = "/api/logs",
    ) -> str:
        """Build the HMAC-SHA256 ``Authorization: SharedKey ...`` header value.

        Signature string: ``{method}\\n{content_length}\\n{content_type}\\n
        x-ms-date:{date}\\n{resource}``

        Uses ``cryptography.hazmat.primitives.hmac.HMAC`` to comply with
        ADR-010 FIPS crypto boundary (no stdlib ``hmac`` / ``hashlib``).
        """
        string_to_sign = f"{method}\n{content_length}\n{content_type}\nx-ms-date:{date}\n{resource}"

        key_bytes = base64.b64decode(shared_key)
        h = HMAC(key_bytes, hashes.SHA256())
        h.update(string_to_sign.encode("utf-8"))
        encoded_hash = base64.b64encode(h.finalize()).decode("utf-8")

        return f"SharedKey {workspace_id}:{encoded_hash}"

    # ----- internal helpers ---------------------------------------------------

    @staticmethod
    def _extract_workspace_id(endpoint: str) -> str:
        """Extract workspace ID from ``https://{id}.ods.opinsights.azure.com``."""
        # Strip protocol.
        host = endpoint.replace("https://", "").replace("http://", "")
        parts = host.split(".")
        return parts[0] if parts else ""

    @property
    def _api_url(self) -> str:
        return (
            f"https://{self._workspace_id}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"
        )

    async def _post_log_analytics(
        self,
        body: str,
        log_type: str,
    ) -> httpx.Response:
        """POST a JSON body to the Log Analytics Data Collector API."""
        rfc1123_date = datetime.now(UTC).strftime("%a, %d %b %Y %H:%M:%S GMT")
        content_bytes = body.encode("utf-8")
        authorization = self.build_signature(
            self._workspace_id,
            self._config.auth_token,
            rfc1123_date,
            len(content_bytes),
        )
        headers = {
            "Content-Type": "application/json",
            "Authorization": authorization,
            "Log-Type": log_type,
            "x-ms-date": rfc1123_date,
            "time-generated-field": "observed_at_t",
        }
        return await self._post_with_retry(
            self._api_url,
            headers=headers,
            content=content_bytes,
        )

    @staticmethod
    def _map_observation(obs: dict[str, Any], tenant_id: UUID) -> dict[str, Any]:
        """Map an EXPOSE observation to Log Analytics fields with type suffixes."""
        return {
            "tenant_id_s": str(tenant_id),
            "entity_identifier_s": obs.get("entity_identifier", "unknown"),
            "entity_type_s": obs.get("entity_type", ""),
            "observation_type_s": obs.get("observation_type", "unknown"),
            "collector_id_s": obs.get("collector_id", ""),
            "observed_at_t": obs.get("observed_at", ""),
            "severity_s": obs.get("severity", "info"),
            "source_ip_s": obs.get("source_ip", ""),
            "dest_ip_s": obs.get("dest_ip", ""),
            "dest_port_d": obs.get("dest_port", 0),
            "protocol_s": obs.get("protocol", ""),
            "service_name_s": obs.get("service_name", ""),
            "raw_data_s": json.dumps(obs.get("data")) if obs.get("data") else "",
        }

    @staticmethod
    def _map_finding(finding: dict[str, Any], tenant_id: UUID) -> dict[str, Any]:
        """Map an EXPOSE finding to Log Analytics fields with type suffixes."""
        return {
            "tenant_id_s": str(tenant_id),
            "finding_id_s": finding.get("finding_id", ""),
            "title_s": finding.get("title", ""),
            "severity_s": finding.get("severity", "info"),
            "description_s": finding.get("description", ""),
            "entity_identifier_s": finding.get("entity_identifier", ""),
            "entity_type_s": finding.get("entity_type", ""),
            "indicators_s": json.dumps(finding.get("indicators"))
            if finding.get("indicators")
            else "",
        }
