"""Typed Pydantic models for collector structured payloads.

Each collector emits a ``structured_payload: dict[str, Any]`` on its
observations.  These models capture the *documented shape* of those
payloads so new code can validate and access fields with type safety.

All models use ``ConfigDict(extra="allow")`` so that:
  - Unknown / future fields do not cause validation errors.
  - Round-tripping (dict -> model -> dict via ``model_dump()``) preserves
    every key, even ones not in the schema.

This module is **additive** -- existing code continues to pass and
consume raw dicts unchanged.  Use the ``as_*_payload()`` helpers in
``expose.types`` to narrow a dict into a typed model when you want
safety.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


# ---------------------------------------------------------------------------
# DNS payload  (active-dns-resolve)
# ---------------------------------------------------------------------------

class MxExchange(BaseModel):
    """A single MX exchange entry."""

    model_config = ConfigDict(extra="allow", frozen=True)

    priority: int
    exchange: str


class DnsPayload(BaseModel):
    """Structured payload from the ``active-dns-resolve`` collector.

    Different DNS record types populate different subsets of fields:
      - A/AAAA: ``values``, ``ttl``
      - CNAME: ``target``
      - MX: ``exchanges``
      - NS: ``nameservers``
      - TXT: ``values``
      - SOA: ``mname``, ``rname``, ``serial``, ``refresh``, ``retry``,
        ``expire``, ``minimum``
      - WILDCARD: ``wildcard_detected``, ``wildcard_values``
      - DNSSEC: ``dnssec_enabled``

    All fields are optional (``total=False`` semantics via defaults)
    because only a subset is present for any given record type.
    """

    model_config = ConfigDict(extra="allow", frozen=True)

    # -- Common --
    _collector_id: str = ""
    record_type: str = ""

    # -- A / AAAA / TXT --
    values: list[str] = Field(default_factory=list)
    ttl: int | None = None

    # -- CNAME --
    target: str | None = None

    # -- MX --
    exchanges: list[MxExchange] = Field(default_factory=list)

    # -- NS --
    nameservers: list[str] = Field(default_factory=list)

    # -- SOA --
    mname: str | None = None
    rname: str | None = None
    serial: int | None = None
    refresh: int | None = None
    retry: int | None = None
    expire: int | None = None
    minimum: int | None = None

    # -- Wildcard detection --
    wildcard_detected: bool | None = None
    wildcard_values: list[str] = Field(default_factory=list)
    severity: str | None = None
    note: str | None = None

    # -- DNSSEC --
    dnssec_enabled: bool | None = None


# ---------------------------------------------------------------------------
# HTTP payload  (active-http-fingerprint)
# ---------------------------------------------------------------------------

class CookieIssue(BaseModel):
    """A single cookie security finding."""

    model_config = ConfigDict(extra="allow", frozen=True)

    name: str = ""
    missing_flags: list[str] = Field(default_factory=list)
    issues: list[str] = Field(default_factory=list)


class CorsMisconfig(BaseModel):
    """CORS misconfiguration details."""

    model_config = ConfigDict(extra="allow", frozen=True)

    wildcard_origin: bool = False
    null_origin: bool = False
    credentials_with_wildcard: bool = False


class HttpPayload(BaseModel):
    """Structured payload from the ``active-http-fingerprint`` collector.

    The HTTP collector fingerprints a target's web stack: status code,
    server header, security headers, redirect chain, detected
    technologies, cookie security, and CORS configuration.
    """

    model_config = ConfigDict(extra="allow", frozen=True)

    _collector_id: str = ""
    url: str = ""
    status_code: int = 0
    server_header: str | None = None
    content_type: str | None = None
    title: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    redirect_chain: list[str] = Field(default_factory=list)
    banner: str | None = None
    technologies: list[str] = Field(default_factory=list)
    cookie_issues: list[CookieIssue] = Field(default_factory=list)
    cors_misconfig: CorsMisconfig | None = None


# ---------------------------------------------------------------------------
# TLS payload  (active-tls-handshake)
# ---------------------------------------------------------------------------

class TlsPayload(BaseModel):
    """Structured payload from the ``active-tls-handshake`` collector.

    Contains the negotiated TLS parameters and parsed certificate
    details from a live handshake.
    """

    model_config = ConfigDict(extra="allow", frozen=True)

    _collector_id: str = ""
    tls_version: str = ""
    protocol_assessment: str | None = None
    cipher_suite: str = ""
    cipher_strength: str | None = None

    # Certificate fields
    cert_subject_cn: str | None = None
    cert_issuer_cn: str | None = None
    cert_issuer_org: str | None = None
    cert_serial: str | None = None
    cert_not_before: str | None = None  # ISO 8601
    cert_not_after: str | None = None  # ISO 8601
    cert_sans: list[str] = Field(default_factory=list)
    cert_fingerprint_sha256: str | None = None

    # Key details
    key_algorithm: str | None = None
    key_size_bits: int | None = None
    key_weak: bool | None = None

    # Chain
    chain_depth: int | None = None
    self_signed: bool | None = None

    # JARM
    jarm_fingerprint: str | None = None


# ---------------------------------------------------------------------------
# Port scan payload  (active-port-surface)
# ---------------------------------------------------------------------------

class PortScanPayload(BaseModel):
    """Structured payload from the ``active-port-surface`` collector.

    Contains open ports, service identification, banners, and port risk
    classification from a TCP connect scan.
    """

    model_config = ConfigDict(extra="allow", frozen=True)

    _collector_id: str = ""
    open_ports: list[int] = Field(default_factory=list)
    closed_ports_probed: int = 0
    total_ports_probed: int = 0
    probe_timeout_seconds: float = 0.0
    banners: dict[str, str] = Field(default_factory=dict)
    services: dict[str, str] = Field(default_factory=dict)
    port_categories: dict[str, str] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Type narrowing helpers
# ---------------------------------------------------------------------------

def as_dns_payload(props: dict) -> DnsPayload:
    """Validate and narrow a raw properties dict to a ``DnsPayload``.

    Extra keys are preserved (``extra="allow"``), so this is safe to
    call on any dict that originated from the ``active-dns-resolve``
    collector.

    Raises ``pydantic.ValidationError`` if the dict contains values that
    violate the schema (e.g., ``ttl`` is not an int).
    """
    return DnsPayload.model_validate(props)


def as_http_payload(props: dict) -> HttpPayload:
    """Validate and narrow a raw properties dict to an ``HttpPayload``."""
    return HttpPayload.model_validate(props)


def as_tls_payload(props: dict) -> TlsPayload:
    """Validate and narrow a raw properties dict to a ``TlsPayload``."""
    return TlsPayload.model_validate(props)


def as_port_scan_payload(props: dict) -> PortScanPayload:
    """Validate and narrow a raw properties dict to a ``PortScanPayload``."""
    return PortScanPayload.model_validate(props)


__all__ = [
    "CookieIssue",
    "CorsMisconfig",
    "DnsPayload",
    "HttpPayload",
    "MxExchange",
    "PortScanPayload",
    "TlsPayload",
    "as_dns_payload",
    "as_http_payload",
    "as_port_scan_payload",
    "as_tls_payload",
]
