"""FIPS-mode crypto gate (per ADR-010).

ADR-010 requires "FIPS 140-3 validated cryptography everywhere — TLS, signing,
hashing, key management, password storage, all use FIPS-validated implementations
from day one. Specific stack choices: the `cryptography` Python library in FIPS
mode, AWS-LC bindings, or BoringSSL bindings — never the default Python
`hashlib` or `secrets` modules in non-FIPS mode."

This test scans the EXPOSE source tree for direct imports of banned modules.
The check is allowlist-based for tests (we may need `secrets` for synthetic
fixtures), but blocks any import in `src/expose/` outside an explicit FIPS
adapter.

Banned in `src/expose/`:
  - `import hashlib` / `from hashlib ...`
  - `import secrets` / `from secrets ...`
  - `from Crypto ...` (pycryptodome — not FIPS-validated by default)

Allowed:
  - `from cryptography ...` (the FIPS-capable library)
  - Anything inside `src/expose/crypto/fips_adapter.py` (when it lands;
    encapsulates any necessary low-level use behind a FIPS-mode-checked wrapper)
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_ROOT = REPO_ROOT / "src" / "expose"

BANNED_PATTERNS = [
    re.compile(r"^\s*import\s+hashlib\b", re.MULTILINE),
    re.compile(r"^\s*from\s+hashlib\b", re.MULTILINE),
    re.compile(r"^\s*import\s+secrets\b", re.MULTILINE),
    re.compile(r"^\s*from\s+secrets\b", re.MULTILINE),
    re.compile(r"^\s*from\s+Crypto\b", re.MULTILINE),  # pycryptodome
    re.compile(r"^\s*import\s+Crypto\b", re.MULTILINE),
]

ALLOWED_FILES = {
    # When a FIPS adapter lands, list it here. The adapter must use the
    # `cryptography` library in FIPS-mode; the allowlist exists to keep the
    # exception explicit and reviewable.
    # SRC_ROOT / "crypto" / "fips_adapter.py",
}


def _python_files() -> list[Path]:
    return [
        p
        for p in SRC_ROOT.rglob("*.py")
        if p not in ALLOWED_FILES
    ]


@pytest.mark.parametrize("path", _python_files(), ids=lambda p: str(p.relative_to(SRC_ROOT)))
def test_no_banned_crypto_imports(path: Path) -> None:
    """No EXPOSE source file may import non-FIPS-validated crypto primitives."""
    text = path.read_text(encoding="utf-8")
    violations = []
    for pattern in BANNED_PATTERNS:
        for match in pattern.finditer(text):
            line_no = text[: match.start()].count("\n") + 1
            violations.append(f"  {path.relative_to(REPO_ROOT)}:{line_no}: {match.group(0).strip()}")
    if violations:
        pytest.fail(
            "Non-FIPS crypto import found (violates ADR-010):\n"
            + "\n".join(violations)
            + "\n\nUse the `cryptography` library in FIPS mode, or land a FIPS"
            " adapter in src/expose/crypto/fips_adapter.py and add to the"
            " ALLOWED_FILES set in this test."
        )


def test_fips_gate_finds_files() -> None:
    """Sanity: the gate is actually scanning files (catches a gate that turned
    into a no-op via path mistakes)."""
    files = _python_files()
    assert len(files) >= 3, (
        f"FIPS gate found only {len(files)} files to scan; expected ≥3. "
        "Check src/expose/ exists and contains Python sources."
    )
