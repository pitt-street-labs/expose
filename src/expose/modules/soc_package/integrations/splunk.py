"""Splunk HTTP Event Collector (HEC) adapter.

Sends EXPOSE observations and findings to Splunk via the HEC ``/services/
collector/event`` endpoint.  Events are mapped to the Splunk Common
Information Model (CIM) and delivered as newline-delimited JSON (the
native HEC batch format).

Auth: ``Authorization: Splunk {token}``

Sourcetypes:
- ``expose:observation`` for observation batches
- ``expose:finding`` for individual findings

CIM data model mapping based on ``entity_type``:
- ``domain`` / ``subdomain`` -> DNS data model (``query``, ``query_type``)
- ``ip`` -> Network Traffic data model (``src`` / ``dest``)
- ``cidr`` -> Network Traffic + asset inventory (``src_range``)
- ``cloud_resource_id`` -> Cloud Infrastructure (``object_id``, ``vendor_product``)
- ``url`` -> Web data model (``url``, ``http_method``)

Severity mapping:
- EXPOSE ``info`` -> Splunk CIM ``informational``
- EXPOSE ``low`` / ``medium`` -> Splunk CIM ``low`` / ``medium``
- EXPOSE ``high`` / ``critical`` -> Splunk CIM ``high`` / ``critical``

See https://docs.splunk.com/Documentation/Splunk/latest/Data/FormateventsforHTTPEventCollector
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

__all__ = ["SplunkHECAdapter"]

logger = logging.getLogger(__name__)

# EXPOSE severity -> Splunk CIM severity mapping.
_SEVERITY_MAP: dict[str, str] = {
    "info": "informational",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}


class SplunkHECAdapter(SIEMAdapter):
    """Splunk HTTP Event Collector adapter."""

    adapter_id = "splunk"
    display_name = "Splunk HTTP Event Collector"

    def __init__(
        self,
        config: SIEMConfig,
        *,
        index: str = "main",
        tenant_id: UUID | None = None,
    ) -> None:
        super().__init__(config, tenant_id=tenant_id)
        self._index = index

    # ----- public interface ---------------------------------------------------

    async def send_observations(
        self,
        observations: list[dict[str, Any]],
        tenant_id: UUID,
    ) -> DeliveryResult:
        """Batch-deliver observations as CIM-mapped HEC events."""
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

        # Process in batch_size chunks.
        for i in range(0, len(observations), self._config.batch_size):
            batch = observations[i : i + self._config.batch_size]
            hec_events = [self._map_observation_to_hec(obs, tenant_id) for obs in batch]
            payload = "\n".join(
                json.dumps(evt, separators=(",", ":"), sort_keys=True) for evt in hec_events
            )

            try:
                response = await self._post_with_retry(
                    self._hec_url,
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
        """Deliver a single finding as an HEC event."""
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
        hec_event = self._map_finding_to_hec(finding, tenant_id)
        payload = json.dumps(hec_event, separators=(",", ":"), sort_keys=True)

        try:
            response = await self._post_with_retry(
                self._hec_url,
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
        """Check HEC reachability with a GET to the health endpoint."""
        try:
            response = await self._http_client.get(
                f"{self._config.endpoint.rstrip('/')}/services/collector/health/1.0",
                headers=self._auth_headers,
                timeout=5.0,
            )
            return 200 <= response.status_code < 300  # noqa: PLR2004
        except httpx.HTTPError:
            return False

    # ----- internal helpers ---------------------------------------------------

    @property
    def _hec_url(self) -> str:
        return f"{self._config.endpoint.rstrip('/')}/services/collector/event"

    @property
    def _auth_headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Splunk {self._config.auth_token}",
            "Content-Type": "application/json",
        }

    @staticmethod
    def _map_cim_severity(severity: str) -> str:
        """Map EXPOSE severity to Splunk CIM severity."""
        return _SEVERITY_MAP.get(severity.lower(), "informational")

    @staticmethod
    def _entity_type_cim_fields(obs: dict[str, Any]) -> dict[str, Any]:
        """Return CIM fields derived from the EXPOSE entity type.

        EXPOSE canonical entity types (from ``IdentifierType``) map to
        specific Splunk CIM data model fields:

        - ``domain`` / ``subdomain`` -> DNS data model
        - ``ip`` -> Network Traffic
        - ``cidr`` -> Network Traffic (range)
        - ``cloud_resource_id`` -> Cloud Infrastructure
        - ``url`` -> Web data model
        """
        entity_type = obs.get("entity_type", "")
        entity_id = obs.get("entity_identifier", "")
        fields: dict[str, Any] = {}

        if entity_type in ("domain", "subdomain"):
            fields["query"] = entity_id
            fields["query_type"] = obs.get("dns_record_type", "A")
            fields["cim_data_model"] = "DNS"
        elif entity_type == "ip":
            fields["src"] = entity_id
            fields["cim_data_model"] = "Network_Traffic"
        elif entity_type == "cidr":
            fields["src_range"] = entity_id
            fields["cim_data_model"] = "Network_Traffic"
        elif entity_type == "cloud_resource_id":
            fields["object_id"] = entity_id
            fields["vendor_product"] = obs.get("cloud_provider", "unknown")
            fields["cim_data_model"] = "Cloud_Infrastructure"
        elif entity_type == "url":
            fields["url"] = entity_id
            fields["http_method"] = obs.get("http_method", "GET")
            fields["cim_data_model"] = "Web"
        else:
            fields["cim_data_model"] = "Network_Traffic"

        return fields

    def _map_observation_to_hec(
        self,
        obs: dict[str, Any],
        tenant_id: UUID,
    ) -> dict[str, Any]:
        """Map an EXPOSE observation dict to a Splunk HEC envelope with CIM fields."""
        entity_id = obs.get("entity_identifier", "unknown")
        cim_fields = self._entity_type_cim_fields(obs)
        return {
            "index": self._index,
            "sourcetype": "expose:observation",
            "host": entity_id,
            "source": f"expose:tenant:{tenant_id}",
            "event": {
                "tenant_id": str(tenant_id),
                "entity_identifier": entity_id,
                "entity_type": obs.get("entity_type", ""),
                "observation_type": obs.get("observation_type", "unknown"),
                "collector_id": obs.get("collector_id"),
                "observed_at": obs.get("observed_at"),
                "severity": self._map_cim_severity(obs.get("severity", "info")),
                "raw_data": obs.get("data"),
                # CIM Data Model fields (Network Traffic / Endpoint)
                "src": obs.get("source_ip"),
                "dest": obs.get("dest_ip"),
                "dest_port": obs.get("dest_port"),
                "transport": obs.get("protocol"),
                "app": obs.get("service_name"),
                # Entity-type-specific CIM fields
                **cim_fields,
            },
        }

    def _map_finding_to_hec(
        self,
        finding: dict[str, Any],
        tenant_id: UUID,
    ) -> dict[str, Any]:
        """Map an EXPOSE finding dict to a Splunk HEC envelope."""
        return {
            "index": self._index,
            "sourcetype": "expose:finding",
            "host": finding.get("entity_identifier", "unknown"),
            "source": f"expose:tenant:{tenant_id}",
            "event": {
                "tenant_id": str(tenant_id),
                "finding_id": finding.get("finding_id"),
                "title": finding.get("title"),
                "severity": self._map_cim_severity(finding.get("severity", "info")),
                "description": finding.get("description"),
                "entity_identifier": finding.get("entity_identifier"),
                "entity_type": finding.get("entity_type", ""),
                "indicators": finding.get("indicators"),
            },
        }
