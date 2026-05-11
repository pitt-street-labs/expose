"""Integration adapters — ticketing and SIEM delivery.

Ticketing adapters escalate high-priority findings into external ticketing
systems (Jira Cloud, ServiceNow).  SIEM adapters map EXPOSE observations and
findings to each SIEM's native schema and deliver events via vendor ingestion
APIs (Splunk HEC, Microsoft Sentinel, Google Chronicle).

Sub-modules — ticketing:

- ``ticketing`` — ``TicketingAdapter`` ABC, ``TicketingConfig``, ``TicketResult``.
- ``jira`` — ``JiraAdapter`` (Jira Cloud).
- ``servicenow`` — ``ServiceNowAdapter`` (ServiceNow Incident table).

Sub-modules — SIEM:

- ``siem`` — ``SIEMAdapter`` ABC, ``SIEMConfig``, ``DeliveryResult``.
- ``splunk`` — ``SplunkHECAdapter`` (Splunk HTTP Event Collector, CIM mapping).
- ``sentinel`` — ``SentinelAdapter`` (Microsoft Sentinel Log Analytics, HMAC-SHA256 auth).
- ``chronicle`` — ``ChronicleAdapter`` (Google Chronicle / MALACHITE, UDM mapping).
"""

from expose.integrations.chronicle import ChronicleAdapter
from expose.integrations.sentinel import SentinelAdapter
from expose.integrations.siem import DeliveryResult, SIEMAdapter, SIEMConfig
from expose.integrations.splunk import SplunkHECAdapter

__all__ = [
    "ChronicleAdapter",
    "DeliveryResult",
    "SIEMAdapter",
    "SIEMConfig",
    "SentinelAdapter",
    "SplunkHECAdapter",
]
