# Copyright 2026 Korlogos / Pitt Street Labs. All rights reserved.
# This file is part of the EXPOSE commercial module and is NOT covered
# by the Apache 2.0 license that governs the open-source core.
# Unauthorized copying, distribution, or use is prohibited.
#
"""Google Chronicle (MALACHITE) ingestion adapter.

Delivers EXPOSE observations and findings to Chronicle's Ingestion API
via the ``unstructuredlogentries:batchCreate`` endpoint.  Events are
mapped to the Unified Data Model (UDM) schema before submission.

Auth: Google service account OAuth2 bearer token (passed as
``config.auth_token``).

See https://cloud.google.com/chronicle/docs/reference/ingestion-api
"""

from __future__ import annotations

# Copyright 2026 Korlogos / Pitt Street Labs. All rights reserved.
# This file is part of EXPOSE Commercial Modules and is NOT covered by the
# Apache 2.0 license that governs the core engine. Unauthorized copying,
# distribution, or use of this file is strictly prohibited. Contact
# licensing@korlogos.com for commercial licensing terms.

import json
import logging
import time
from typing import Any
from uuid import UUID

import httpx

from expose.integrations.siem import (
    CircuitBreakerOpen,
    DeliveryResult,
    SIEMAdapter,
    SIEMConfig,
    TenantMismatchError,
)

__all__ = ["ChronicleAdapter"]

logger = logging.getLogger(__name__)

# Default Chronicle ingestion endpoint.
_DEFAULT_ENDPOINT = (
    "https://malachiteingestion-pa.googleapis.com/v2/unstructuredlogentries:batchCreate"
)

# Chronicle log type for EXPOSE events.
_LOG_TYPE = "EXPOSE_OBSERVATION"


class ChronicleAdapter(SIEMAdapter):
    """Google Chronicle / MALACHITE ingestion adapter."""

    adapter_id = "chronicle"
    display_name = "Google Chronicle (MALACHITE)"

    def __init__(
        self,
        config: SIEMConfig,
        *,
        tenant_id: UUID | None = None,
    ) -> None:
        super().__init__(config, tenant_id=tenant_id)

    # ----- public interface ---------------------------------------------------

    async def send_observations(
        self,
        observations: list[dict[str, Any]],
        tenant_id: UUID,
    ) -> DeliveryResult:
        """Batch-deliver observations as UDM-mapped Chronicle log entries."""
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
            entries = [self._map_observation_to_udm(obs, tenant_id) for obs in batch]
            request_body = self._build_batch_request(entries)
            payload = json.dumps(request_body, separators=(",", ":"), sort_keys=True)

            try:
                response = await self._post_with_retry(
                    self._ingestion_url,
                    headers=self._auth_headers,
                    content=payload.encode(),
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
        """Deliver a single finding as a Chronicle log entry."""
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
        entry = self._map_finding_to_udm(finding, tenant_id)
        request_body = self._build_batch_request([entry])
        payload = json.dumps(request_body, separators=(",", ":"), sort_keys=True)

        try:
            response = await self._post_with_retry(
                self._ingestion_url,
                headers=self._auth_headers,
                content=payload.encode(),
            )
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
        """Check Chronicle endpoint reachability with an empty batch."""
        try:
            request_body = self._build_batch_request([])
            payload = json.dumps(request_body, separators=(",", ":"), sort_keys=True)
            response = await self._http_client.post(
                self._ingestion_url,
                content=payload.encode(),
                headers=self._auth_headers,
                timeout=5.0,
            )
            return 200 <= response.status_code < 400  # noqa: PLR2004
        except httpx.HTTPError:
            return False

    # ----- internal helpers ---------------------------------------------------

    @property
    def _ingestion_url(self) -> str:
        endpoint = self._config.endpoint.rstrip("/")
        if "unstructuredlogentries" in endpoint:
            return endpoint
        return f"{endpoint}/v2/unstructuredlogentries:batchCreate"

    @property
    def _auth_headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._config.auth_token}",
            "Content-Type": "application/json",
        }

    @staticmethod
    def _build_batch_request(entries: list[dict[str, Any]]) -> dict[str, Any]:
        """Build the Chronicle batchCreate request body."""
        return {
            "customer_id": "",  # filled by Chronicle from the service account
            "log_type": _LOG_TYPE,
            "entries": entries,
        }

    @staticmethod
    def _udm_event_type_for_entity(entity_type: str) -> str:
        """Map EXPOSE entity type to the best-fit UDM event_type.

        - ``domain`` / ``subdomain`` -> ``NETWORK_DNS`` (DNS resolution events)
        - ``ip`` / ``cidr`` -> ``NETWORK_UNCATEGORIZED`` (general network)
        - ``cloud_resource_id`` -> ``RESOURCE_READ`` (cloud resource observation)
        - ``url`` -> ``NETWORK_HTTP`` (HTTP-level observation)
        - default -> ``NETWORK_UNCATEGORIZED``
        """
        _map = {
            "domain": "NETWORK_DNS",
            "subdomain": "NETWORK_DNS",
            "ip": "NETWORK_UNCATEGORIZED",
            "cidr": "NETWORK_UNCATEGORIZED",
            "cloud_resource_id": "RESOURCE_READ",
            "url": "NETWORK_HTTP",
        }
        return _map.get(entity_type, "NETWORK_UNCATEGORIZED")

    @staticmethod
    def _map_observation_to_udm(
        obs: dict[str, Any],
        tenant_id: UUID,
    ) -> dict[str, Any]:
        """Map an EXPOSE observation to a UDM-structured log entry."""
        entity_type = obs.get("entity_type", "")
        udm_event: dict[str, Any] = {
            "metadata": {
                "event_type": ChronicleAdapter._udm_event_type_for_entity(entity_type),
                "product_name": "EXPOSE",
                "vendor_name": "Korlogos",
                "description": obs.get("observation_type", "unknown"),
            },
        }

        # Principal (source of the observation).
        principal: dict[str, Any] = {}
        if obs.get("entity_identifier"):
            if entity_type in ("domain", "subdomain"):
                principal["hostname"] = obs["entity_identifier"]
            elif entity_type == "ip":
                principal["ip"] = [obs["entity_identifier"]]
            elif entity_type == "url":
                principal["url"] = obs["entity_identifier"]
            else:
                principal["hostname"] = obs["entity_identifier"]
        if obs.get("source_ip"):
            principal["ip"] = [obs["source_ip"]]
        if principal:
            udm_event["principal"] = principal

        # Target.
        target: dict[str, Any] = {}
        if obs.get("dest_ip"):
            target["ip"] = [obs["dest_ip"]]
        if obs.get("dest_port"):
            target["port"] = obs["dest_port"]
        if target:
            udm_event["target"] = target

        # Network / DNS.
        if obs.get("dns_questions"):
            udm_event["network"] = {
                "dns": {
                    "questions": obs["dns_questions"],
                },
            }

        # Cloud resource context.
        if entity_type == "cloud_resource_id":
            udm_event["target"] = udm_event.get("target", {})
            udm_event["target"]["resource"] = {
                "name": obs.get("entity_identifier", ""),
                "product_object_id": obs.get("entity_identifier", ""),
                "resource_type": obs.get("cloud_service", "UNSPECIFIED"),
            }

        # Additional context as labels.
        udm_event["additional"] = {
            "fields": {
                "tenant_id": str(tenant_id),
                "collector_id": obs.get("collector_id", ""),
                "severity": obs.get("severity", "info"),
                "observed_at": obs.get("observed_at", ""),
                "entity_type": entity_type,
            },
        }

        return {
            "log_text": json.dumps(udm_event, separators=(",", ":"), sort_keys=True),
        }

    @staticmethod
    def _map_finding_to_udm(
        finding: dict[str, Any],
        tenant_id: UUID,
    ) -> dict[str, Any]:
        """Map an EXPOSE finding to a UDM-structured log entry."""
        udm_event: dict[str, Any] = {
            "metadata": {
                "event_type": "GENERIC_EVENT",
                "product_name": "EXPOSE",
                "vendor_name": "Korlogos",
                "description": finding.get("title", ""),
            },
            "principal": {
                "hostname": finding.get("entity_identifier", "unknown"),
            },
            "security_result": [
                {
                    "summary": finding.get("title", ""),
                    "severity": (finding.get("severity", "info")).upper(),
                    "description": finding.get("description", ""),
                },
            ],
            "additional": {
                "fields": {
                    "tenant_id": str(tenant_id),
                    "finding_id": finding.get("finding_id", ""),
                    "entity_type": finding.get("entity_type", ""),
                },
            },
        }

        return {
            "log_text": json.dumps(udm_event, separators=(",", ":"), sort_keys=True),
        }
