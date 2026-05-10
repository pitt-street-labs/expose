"""Shared type aliases used across EXPOSE Pydantic models.

These are NewType-style aliases over `uuid.UUID` so the type checker catches
mix-ups (e.g., passing a TenantId where a RunId is expected). Runtime they are
plain UUIDs serialized as RFC 4122 strings in the artifact.
"""
from typing import NewType
from uuid import UUID

TenantId = NewType("TenantId", UUID)
RunId = NewType("RunId", UUID)
EntityId = NewType("EntityId", UUID)

__all__ = ["EntityId", "RunId", "TenantId"]
