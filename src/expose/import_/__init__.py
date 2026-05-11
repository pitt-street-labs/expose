"""Third-party config importers — SpiderFoot today; OWASP Amass + theHarvester future.

EXPOSE operators frequently arrive with an existing OSINT tool footprint:
SpiderFoot configurations validated by months of use, Amass scope files,
theHarvester source lists. Re-entering API keys and scope into EXPOSE is both
tedious and error-prone (a transcribed key with a single character flipped
fails authentication in a way that looks identical to a revoked key).

Importers in this package read external tool state and populate EXPOSE's
secrets backend (and, sprint-by-sprint, scope/seed configuration) so the
operator can bootstrap an EXPOSE deployment from an already-working
SpiderFoot install.

Naming: this package is ``import_`` (trailing underscore) because ``import``
is a Python reserved word. Re-exports below let consumers write
``from expose.import_ import SpiderFootImporter`` without ever needing to
spell the package name in user-facing code paths.

Sub-modules:

- ``spiderfoot`` — :class:`SpiderFootImporter` reads the SpiderFoot SQLite
  ``tbl_config`` table and writes mapped collector credentials into the
  EXPOSE :class:`expose.secrets.SecretsBackend`. CLI wiring lands in W4.A's
  ``expose import spiderfoot`` subcommand.
"""

from expose.import_.credential_bundle import (
    CredentialBundle,
    export_bundle,
    import_bundle,
    mask_value,
)
from expose.import_.spiderfoot import (
    SPIDERFOOT_MODULE_MAP,
    ImportedKey,
    ImportSummary,
    SpiderFootImporter,
)

__all__ = [
    "SPIDERFOOT_MODULE_MAP",
    "CredentialBundle",
    "ImportSummary",
    "ImportedKey",
    "SpiderFootImporter",
    "export_bundle",
    "import_bundle",
    "mask_value",
]
