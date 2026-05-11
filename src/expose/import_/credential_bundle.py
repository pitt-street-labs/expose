"""Native JSON credential bundle format for EXPOSE import/export.

The bundle is a lightweight JSON envelope that holds credential slot IDs
mapped to their plaintext values (for import) or masked values (for export).
It is the canonical "save/restore" format for credentials, distinct from the
SpiderFoot importer which reads a third-party SQLite schema.

Security notes:

- **Export masks by default.** The :func:`export_bundle` function replaces
  credential values with ``****<last-4-chars>`` so the operator can verify
  which keys are configured without revealing full secret material. Full-value
  export is available via ``mask=False`` for backup/migration workflows —
  the operator accepts the risk explicitly.
- **Import overwrites.** Importing a bundle calls ``backend.set`` with
  overwrite-on-conflict semantics (idempotent, matching the SpiderFoot
  importer contract).
- **No secret values are logged.** The module follows the project-wide
  prohibition established in ``SecretsBackend`` and ``SpiderFootImporter``.
"""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict

# Number of trailing characters to reveal in masked credential values.
# Values of this length or shorter are fully masked to prevent revealing
# the entire secret.
_MASK_VISIBLE_CHARS = 4


class CredentialBundle(BaseModel):
    """A portable credential bundle for import/export.

    Attributes:
        format_version: Schema version string. Currently ``"1.0"``.
        exported_at: UTC timestamp of when the bundle was created.
        credentials: Mapping of credential slot ID to value. For export
            bundles, values are masked unless full export was requested.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    format_version: str = "1.0"
    exported_at: datetime
    credentials: dict[str, str]


def mask_value(value: str) -> str:
    """Mask a credential value, showing only the last 4 characters.

    Returns ``"****"`` for values of 4 characters or fewer (to avoid
    revealing the entire value), or ``"****<last-4>"`` for longer values.

    Examples:
        >>> mask_value("abcdefgh1234")
        '****1234'
        >>> mask_value("ab")
        '****'
        >>> mask_value("")
        '****'
    """
    if len(value) <= _MASK_VISIBLE_CHARS:
        return "****"
    return "****" + value[-_MASK_VISIBLE_CHARS:]


def export_bundle(secrets: dict[str, str], *, mask: bool = True) -> CredentialBundle:
    """Build a :class:`CredentialBundle` from a secrets dictionary.

    Args:
        secrets: Mapping of slot_id to plaintext credential value.
        mask: If ``True`` (default), values are masked via :func:`mask_value`.
            Set to ``False`` for full-value backup exports.

    Returns:
        A frozen ``CredentialBundle`` ready for JSON serialization.
    """
    credentials = {
        slot_id: (mask_value(value) if mask else value)
        for slot_id, value in secrets.items()
    }
    return CredentialBundle(
        format_version="1.0",
        exported_at=datetime.now(UTC),
        credentials=credentials,
    )


def import_bundle(bundle: CredentialBundle) -> dict[str, str]:
    """Extract the credential mapping from a bundle for storage.

    Args:
        bundle: A parsed ``CredentialBundle`` (typically from JSON upload).

    Returns:
        A plain ``dict[str, str]`` mapping slot_id to value, ready to be
        written into the secrets backend via ``backend.set``.

    Note:
        This function does NOT filter out masked values (``****...``).
        If an operator re-imports an *exported* bundle that was masked,
        the masked placeholder values will overwrite the real credentials.
        The API layer is responsible for warning or rejecting such imports.
    """
    return dict(bundle.credentials)


__all__ = [
    "CredentialBundle",
    "export_bundle",
    "import_bundle",
    "mask_value",
]
