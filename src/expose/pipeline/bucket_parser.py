"""Bucket listing parsers and sensitive-object classification.

Parses XML (S3, Azure) and JSON (GCP) bucket/container listings into
structured ``BucketObject`` records, then classifies each object against
a curated list of sensitive filename patterns commonly found in
misconfigured cloud storage.

The ``BucketAnalysis`` model aggregates the results for a single bucket
probe: provider, name, public/listable status, total objects, sensitive
objects, and any endpoints extracted from the listing.

No network calls are made — all functions operate on already-fetched
response bodies.
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class BucketObject(BaseModel):
    """One object (key) inside a cloud storage bucket/container."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    key: str = Field(min_length=1)
    size_bytes: int = Field(ge=0)
    last_modified: str | None = None
    is_sensitive: bool = False
    sensitivity_reason: str | None = None


class BucketAnalysis(BaseModel):
    """Aggregated analysis of a single bucket probe."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    cloud_provider: str  # "aws", "azure", "gcp"
    bucket_name: str = Field(min_length=1)
    is_public: bool
    is_listable: bool
    total_objects: int = Field(ge=0)
    sensitive_objects: list[BucketObject] = Field(default_factory=list)
    extracted_endpoints: list[str] = Field(default_factory=list)


SENSITIVE_PATTERNS: list[dict[str, str]] = [
    {"pattern": r"\.env$", "reason": "Environment variables file"},
    {"pattern": r"\.pem$", "reason": "PEM certificate/key"},
    {"pattern": r"\.key$", "reason": "Private key file"},
    {"pattern": r"config\.(json|yaml|yml|toml|xml)$", "reason": "Configuration file"},
    {"pattern": r"\.git/", "reason": "Git repository data"},
    {"pattern": r"backup.*\.sql", "reason": "Database backup"},
    {"pattern": r"swagger\.(json|yaml)$", "reason": "API specification"},
    {"pattern": r"openapi\.(json|yaml)$", "reason": "API specification"},
    {"pattern": r"docker-compose.*\.ya?ml$", "reason": "Docker Compose config"},
    {"pattern": r"\.terraform/", "reason": "Terraform state"},
    {"pattern": r"credentials", "reason": "Potential credentials file"},
    {"pattern": r"\.htpasswd$", "reason": "Apache password file"},
    {"pattern": r"id_rsa", "reason": "SSH private key"},
    {"pattern": r"wp-config\.php$", "reason": "WordPress configuration"},
]

# Pre-compile for performance.
_COMPILED_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(p["pattern"], re.IGNORECASE), p["reason"]) for p in SENSITIVE_PATTERNS
]


def classify_objects(objects: list[BucketObject]) -> list[BucketObject]:
    """Mark objects as sensitive based on ``SENSITIVE_PATTERNS``.

    Returns a new list; original objects are not mutated (they are frozen).
    Objects that match at least one pattern get ``is_sensitive=True`` and
    ``sensitivity_reason`` set to the first matching pattern's reason.
    """
    result: list[BucketObject] = []
    for obj in objects:
        reason = _match_sensitive(obj.key)
        if reason is not None:
            result.append(
                BucketObject(
                    key=obj.key,
                    size_bytes=obj.size_bytes,
                    last_modified=obj.last_modified,
                    is_sensitive=True,
                    sensitivity_reason=reason,
                )
            )
        else:
            result.append(obj)
    return result


def _match_sensitive(key: str) -> str | None:
    """Return the reason string if ``key`` matches a sensitive pattern, else None."""
    for pattern, reason in _COMPILED_PATTERNS:
        if pattern.search(key):
            return reason
    return None


# === S3 XML parsing =========================================================

# S3 listing XML uses a default namespace; we strip it for simpler XPath.
_S3_NS_RE = re.compile(r"\{[^}]+\}")


def parse_s3_listing(xml_content: str) -> list[BucketObject]:
    """Parse an S3 ListBucketResult XML response into ``BucketObject`` records.

    Expected XML structure (abbreviated)::

        <ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
          <Contents>
            <Key>path/to/file.txt</Key>
            <Size>12345</Size>
            <LastModified>2024-01-15T10:30:00.000Z</LastModified>
          </Contents>
          ...
        </ListBucketResult>

    Returns an empty list on parse failure rather than raising.
    """
    try:
        root = ET.fromstring(xml_content)  # noqa: S314
    except ET.ParseError:
        return []

    objects: list[BucketObject] = []
    # Handle namespaced or non-namespaced XML.
    for contents in _find_all_strip_ns(root, "Contents"):
        key = _text_strip_ns(contents, "Key")
        size_text = _text_strip_ns(contents, "Size")
        last_modified = _text_strip_ns(contents, "LastModified")

        if not key:
            continue

        size_bytes = int(size_text) if size_text and size_text.isdigit() else 0
        objects.append(
            BucketObject(
                key=key,
                size_bytes=size_bytes,
                last_modified=last_modified,
            )
        )

    return objects


# === Azure XML parsing =====================================================


def parse_azure_listing(xml_content: str) -> list[BucketObject]:
    """Parse an Azure Blob Storage listing XML into ``BucketObject`` records.

    Expected XML structure (abbreviated)::

        <EnumerationResults>
          <Blobs>
            <Blob>
              <Name>path/to/file.txt</Name>
              <Properties>
                <Content-Length>12345</Content-Length>
                <Last-Modified>Mon, 15 Jan 2024 10:30:00 GMT</Last-Modified>
              </Properties>
            </Blob>
          </Blobs>
        </EnumerationResults>

    Returns an empty list on parse failure.
    """
    try:
        root = ET.fromstring(xml_content)  # noqa: S314
    except ET.ParseError:
        return []

    objects: list[BucketObject] = []
    blobs_el = root.find("Blobs")
    if blobs_el is None:
        return objects

    for blob in blobs_el.findall("Blob"):
        name_el = blob.find("Name")
        if name_el is None or not name_el.text:
            continue

        props = blob.find("Properties")
        size_bytes = 0
        last_modified: str | None = None
        if props is not None:
            cl_el = props.find("Content-Length")
            if cl_el is not None and cl_el.text and cl_el.text.isdigit():
                size_bytes = int(cl_el.text)
            lm_el = props.find("Last-Modified")
            if lm_el is not None and lm_el.text:
                last_modified = lm_el.text

        objects.append(
            BucketObject(
                key=name_el.text,
                size_bytes=size_bytes,
                last_modified=last_modified,
            )
        )

    return objects


# === GCP JSON parsing ======================================================


def parse_gcp_listing(json_content: str) -> list[BucketObject]:
    """Parse a GCP Cloud Storage JSON listing into ``BucketObject`` records.

    Expected JSON structure::

        {
            "items": [
                {"name": "path/to/file.txt", "size": "12345", "updated": "2024-01-15T10:30:00.000Z"}
            ]
        }

    Returns an empty list on parse failure.
    """
    try:
        data: dict[str, Any] = json.loads(json_content)
    except (json.JSONDecodeError, TypeError):
        return []

    objects: list[BucketObject] = []
    for item in data.get("items", []):
        name = item.get("name")
        if not name:
            continue

        size_str = str(item.get("size", "0"))
        size_bytes = int(size_str) if size_str.isdigit() else 0
        updated = item.get("updated")

        objects.append(
            BucketObject(
                key=name,
                size_bytes=size_bytes,
                last_modified=updated,
            )
        )

    return objects


# === Namespace-stripping XML helpers ========================================


def _find_all_strip_ns(
    element: ET.Element,
    tag: str,
) -> list[ET.Element]:
    """Find all child elements matching ``tag`` regardless of XML namespace."""
    results: list[ET.Element] = []
    for child in element:
        local_tag = _S3_NS_RE.sub("", child.tag)
        if local_tag == tag:
            results.append(child)
    return results


def _text_strip_ns(parent: ET.Element, tag: str) -> str | None:
    """Get the text of a child element matching ``tag``, stripping namespace."""
    for child in parent:
        local_tag = _S3_NS_RE.sub("", child.tag)
        if local_tag == tag:
            return child.text
    return None


__all__ = [
    "SENSITIVE_PATTERNS",
    "BucketAnalysis",
    "BucketObject",
    "classify_objects",
    "parse_azure_listing",
    "parse_gcp_listing",
    "parse_s3_listing",
]
