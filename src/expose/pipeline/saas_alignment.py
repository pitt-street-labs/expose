"""SaaS product-to-endpoint alignment analysis (Issue #54).

Matches observations against a knowledge base of SaaS/enterprise product
signatures and identifies surface gaps.  Two modes of operation:

1. **Inbound (fingerprinting):** Given a set of observations, identify which
   SaaS products are present based on URL paths, HTTP headers, TLS SANs,
   TLS issuer strings, favicon hashes, and DNS CNAME records.

2. **Outbound (expected-surface validation):** Given a list of products
   the target is *known* to use, check which are visible in the observation
   set.  Missing expected products and unexpected product fingerprints are
   both flagged as surface gaps.

The product knowledge base is a JSON catalog (see
``examples/product-signatures/catalog.json`` for the shipped baseline).
Custom catalogs can be loaded at runtime.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any, ClassVar

from pydantic import BaseModel, ConfigDict, Field

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Default catalog location (relative to the repo root)
# ---------------------------------------------------------------------------
_DEFAULT_CATALOG_PATH = (
    Path(__file__).resolve().parents[3]
    / "examples"
    / "product-signatures"
    / "catalog.json"
)

# Minimum aggregate confidence to include a product match in results.
_MATCH_CONFIDENCE_THRESHOLD = 0.3


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class ProductSignature(BaseModel):
    """A single signature pattern that may identify a SaaS product."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    type: str  # "url_path", "header", "tls_san", "tls_issuer", "favicon_hash", "dns_cname"
    pattern: str = Field(min_length=1)
    name: str | None = None  # header name for "header" type
    value_pattern: str | None = None  # value regex for "header" type
    confidence: float = Field(ge=0.0, le=1.0)


class ProductDefinition(BaseModel):
    """A SaaS/enterprise product with its identifying signatures."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    product_id: str = Field(min_length=1)
    vendor: str = Field(min_length=1)
    product_name: str = Field(min_length=1)
    category: str = Field(min_length=1)
    signatures: list[ProductSignature]
    expected_ports: list[int] = Field(default_factory=list)
    related_products: list[str] = Field(default_factory=list)


class ProductMatch(BaseModel):
    """A confirmed match between observations and a product signature."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    product_id: str
    vendor: str
    product_name: str
    matched_signatures: list[str]  # human-readable descriptions of which signatures matched
    confidence: float = Field(ge=0.0, le=1.0)  # aggregate confidence
    entity_identifier: str  # which entity/observation matched


class SurfaceGap(BaseModel):
    """A gap between expected and observed product surface."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    product_id: str
    product_name: str
    gap_type: str  # "missing_expected" or "unexpected_product"
    description: str
    severity: str = "info"  # "info", "low", "medium", "high"


class AlignmentResult(BaseModel):
    """Complete result of a SaaS alignment analysis run."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    matched_products: list[ProductMatch]
    surface_gaps: list[SurfaceGap]
    products_checked: int
    entities_checked: int


# ---------------------------------------------------------------------------
# Product catalog
# ---------------------------------------------------------------------------


class ProductCatalog:
    """Loads and queries the product signature knowledge base."""

    def __init__(self, catalog_path: Path | None = None) -> None:
        self._products: dict[str, ProductDefinition] = {}
        if catalog_path is not None:
            self.load(catalog_path)

    def load(self, catalog_path: Path) -> None:
        """Load product definitions from a JSON catalog file.

        Raises ``FileNotFoundError`` if the path does not exist and
        ``ValueError`` if the JSON structure is invalid.
        """
        if not catalog_path.exists():
            raise FileNotFoundError(f"Catalog not found: {catalog_path}")

        raw = json.loads(catalog_path.read_text(encoding="utf-8"))

        if not isinstance(raw, dict) or "products" not in raw:
            raise ValueError("Catalog JSON must contain a 'products' key")

        for entry in raw["products"]:
            product = ProductDefinition.model_validate(entry)
            self._products[product.product_id] = product

        logger.info(
            "Loaded %d products from %s", len(self._products), catalog_path
        )

    def get_product(self, product_id: str) -> ProductDefinition | None:
        """Return a product definition by ID, or None if not found."""
        return self._products.get(product_id)

    def list_products(self) -> list[ProductDefinition]:
        """Return all loaded product definitions."""
        return list(self._products.values())

    def search_by_vendor(self, vendor: str) -> list[ProductDefinition]:
        """Return all products from a given vendor (case-insensitive)."""
        needle = vendor.lower()
        return [p for p in self._products.values() if p.vendor.lower() == needle]


# ---------------------------------------------------------------------------
# Alignment analyzer
# ---------------------------------------------------------------------------


class SaaSAlignmentAnalyzer:
    """Matches observations against product signatures and identifies surface gaps."""

    def __init__(self, catalog: ProductCatalog) -> None:
        self._catalog = catalog

    # -- public API ----------------------------------------------------------

    def fingerprint(
        self,
        observations: list[dict[str, Any]],
    ) -> list[ProductMatch]:
        """Match observations against all products in catalog (inbound mode).

        For each observation, checks URL paths, HTTP headers, TLS SANs,
        TLS issuer strings, favicon hashes, and DNS CNAME values against
        every product's signatures.

        Aggregate confidence per product is the maximum confidence across
        all matched signatures.  Products below the threshold (0.3) are
        filtered out.
        """
        products = self._catalog.list_products()
        if not products:
            return []

        # product_id -> (max_confidence, matched_sigs_set, entity_identifier)
        matches: dict[str, tuple[float, list[str], str]] = {}

        for obs in observations:
            for product in products:
                for sig in product.signatures:
                    hit = self._check_signature(sig, obs)
                    if hit is not None:
                        sig_desc, entity_id = hit
                        existing = matches.get(product.product_id)
                        if existing is None:
                            matches[product.product_id] = (
                                sig.confidence,
                                [sig_desc],
                                entity_id,
                            )
                        else:
                            old_conf, old_sigs, old_entity = existing
                            new_conf = max(old_conf, sig.confidence)
                            if sig_desc not in old_sigs:
                                old_sigs.append(sig_desc)
                            matches[product.product_id] = (
                                new_conf,
                                old_sigs,
                                old_entity,
                            )

        result: list[ProductMatch] = []
        for pid, (conf, sigs, entity_id) in matches.items():
            if conf < _MATCH_CONFIDENCE_THRESHOLD:
                continue
            product = self._catalog.get_product(pid)
            if product is None:
                continue
            result.append(
                ProductMatch(
                    product_id=pid,
                    vendor=product.vendor,
                    product_name=product.product_name,
                    matched_signatures=sigs,
                    confidence=conf,
                    entity_identifier=entity_id,
                )
            )

        return result

    def validate_expected_surface(
        self,
        *,
        expected_products: list[str],
        observations: list[dict[str, Any]],
    ) -> list[SurfaceGap]:
        """Check if expected products are visible in observations (outbound mode).

        For each expected product:
          - If no observation matches any of its signatures, emit a
            ``SurfaceGap(gap_type="missing_expected")``.

        For fingerprinted products NOT in the expected list:
          - Emit ``SurfaceGap(gap_type="unexpected_product", severity="medium")``.
        """
        gaps: list[SurfaceGap] = []

        # Fingerprint first to know what is actually present.
        fingerprinted = self.fingerprint(observations)
        fingerprinted_ids = {m.product_id for m in fingerprinted}

        # Check for missing expected products.
        for pid in expected_products:
            product = self._catalog.get_product(pid)
            if product is None:
                gaps.append(
                    SurfaceGap(
                        product_id=pid,
                        product_name=pid,
                        gap_type="missing_expected",
                        description=f"Product '{pid}' is not in the catalog and could not be validated",
                        severity="info",
                    )
                )
                continue

            if pid not in fingerprinted_ids:
                gaps.append(
                    SurfaceGap(
                        product_id=pid,
                        product_name=product.product_name,
                        gap_type="missing_expected",
                        description=(
                            f"Expected product '{product.product_name}' "
                            f"({product.vendor}) was not detected in observations"
                        ),
                        severity="low",
                    )
                )

        # Check for unexpected products.
        expected_set = set(expected_products)
        for match in fingerprinted:
            if match.product_id not in expected_set:
                gaps.append(
                    SurfaceGap(
                        product_id=match.product_id,
                        product_name=match.product_name,
                        gap_type="unexpected_product",
                        description=(
                            f"Product '{match.product_name}' ({match.vendor}) "
                            f"was detected but is not in the expected product list"
                        ),
                        severity="medium",
                    )
                )

        return gaps

    def analyze(
        self,
        *,
        observations: list[dict[str, Any]],
        expected_products: list[str] | None = None,
    ) -> AlignmentResult:
        """Full analysis: fingerprint + gap validation.

        When ``expected_products`` is provided, also runs expected-surface
        validation and includes the resulting gaps.
        """
        products = self._catalog.list_products()
        matched = self.fingerprint(observations)

        gaps: list[SurfaceGap] = []
        if expected_products is not None:
            gaps = self.validate_expected_surface(
                expected_products=expected_products,
                observations=observations,
            )

        return AlignmentResult(
            matched_products=matched,
            surface_gaps=gaps,
            products_checked=len(products),
            entities_checked=len(observations),
        )

    # -- internal signature matching -----------------------------------------

    # Supported signature types, mapped to method suffixes.
    _SIG_TYPE_SUFFIXES: ClassVar[dict[str, str]] = {
        "url_path": "_match_url_path",
        "header": "_match_header",
        "tls_san": "_match_tls_san",
        "tls_issuer": "_match_tls_issuer",
        "favicon_hash": "_match_favicon_hash",
        "dns_cname": "_match_dns_cname",
    }

    def _check_signature(
        self,
        sig: ProductSignature,
        obs: dict[str, Any],
    ) -> tuple[str, str] | None:
        """Check a single signature against a single observation.

        Returns ``(human_description, entity_identifier)`` on match, or
        ``None`` on no match.
        """
        entity_id = obs.get("url", obs.get("identifier", obs.get("host", "unknown")))
        method_name = self._SIG_TYPE_SUFFIXES.get(sig.type)
        if method_name is None:
            return None
        matcher = getattr(self, method_name)
        return matcher(sig, obs, entity_id)

    @staticmethod
    def _match_url_path(
        sig: ProductSignature,
        obs: dict[str, Any],
        entity_id: str,
    ) -> tuple[str, str] | None:
        """Match a URL path pattern against the observation's url field."""
        url = obs.get("url")
        if not isinstance(url, str):
            return None
        # Extract path from URL.
        # Simple approach: find the path portion after the scheme+authority.
        path = url
        if "://" in url:
            after_scheme = url.split("://", 1)[1]
            slash_idx = after_scheme.find("/")
            path = after_scheme[slash_idx:] if slash_idx != -1 else "/"

        if re.search(sig.pattern, path):
            return (f"url_path:{sig.pattern}", entity_id)
        return None

    @staticmethod
    def _match_header(
        sig: ProductSignature,
        obs: dict[str, Any],
        entity_id: str,
    ) -> tuple[str, str] | None:
        """Match a header name+value pattern against the observation's headers."""
        if sig.name is None:
            return None

        # Check top-level headers dict (from active_http structured_payload).
        headers = obs.get("headers", {})
        if not isinstance(headers, dict):
            return None

        # Also check server_header as a special case.
        header_name_lower = sig.name.lower()
        value: str | None = None

        if header_name_lower == "server":
            server = obs.get("server_header")
            if isinstance(server, str):
                value = server
        else:
            # Case-insensitive header lookup.
            for k, v in headers.items():
                if k.lower() == header_name_lower:
                    value = v
                    break

        if value is None:
            return None

        if sig.value_pattern is not None and re.search(sig.value_pattern, value):
            return (f"header:{sig.name}={sig.value_pattern}", entity_id)

        return None

    @staticmethod
    def _match_tls_san(
        sig: ProductSignature,
        obs: dict[str, Any],
        entity_id: str,
    ) -> tuple[str, str] | None:
        """Match a TLS SAN pattern against the observation's cert_sans list."""
        sans = obs.get("cert_sans")
        if not isinstance(sans, list):
            return None

        for san in sans:
            if isinstance(san, str) and re.search(sig.pattern, san):
                return (f"tls_san:{sig.pattern}", entity_id)
        return None

    @staticmethod
    def _match_tls_issuer(
        sig: ProductSignature,
        obs: dict[str, Any],
        entity_id: str,
    ) -> tuple[str, str] | None:
        """Match a TLS issuer pattern against the observation's cert_issuer fields."""
        for field in ("cert_issuer_cn", "cert_issuer_org"):
            issuer = obs.get(field)
            if isinstance(issuer, str) and re.search(sig.pattern, issuer):
                return (f"tls_issuer:{sig.pattern}", entity_id)
        return None

    @staticmethod
    def _match_favicon_hash(
        sig: ProductSignature,
        obs: dict[str, Any],
        entity_id: str,
    ) -> tuple[str, str] | None:
        """Match a favicon hash against the observation's favicon_sha256."""
        favicon_hash = obs.get("favicon_sha256")
        if not isinstance(favicon_hash, str):
            return None

        # The pattern in the catalog may be prefixed with "sha256:".
        pattern_hash = sig.pattern
        if pattern_hash.startswith("sha256:"):
            pattern_hash = pattern_hash[7:]

        if favicon_hash == pattern_hash:
            return (f"favicon_hash:{sig.pattern}", entity_id)
        return None

    @staticmethod
    def _match_dns_cname(
        sig: ProductSignature,
        obs: dict[str, Any],
        entity_id: str,
    ) -> tuple[str, str] | None:
        """Match a DNS CNAME pattern against the observation's dns_cname or value field."""
        for field in ("dns_cname", "value", "cname"):
            cname = obs.get(field)
            if isinstance(cname, str) and re.search(sig.pattern, cname):
                return (f"dns_cname:{sig.pattern}", entity_id)
        return None


__all__ = [
    "AlignmentResult",
    "ProductCatalog",
    "ProductDefinition",
    "ProductMatch",
    "ProductSignature",
    "SaaSAlignmentAnalyzer",
    "SurfaceGap",
]
