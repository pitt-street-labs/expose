"""Tests for SaaS product-to-endpoint alignment (Issue #54).

Coverage:
- Catalog loading, querying, and error handling
- Fingerprinting (inbound mode) — URL path, header, TLS SAN, TLS issuer,
  favicon hash, DNS CNAME matching
- Expected surface validation (outbound mode) — gap detection
- Full analysis (fingerprint + gap)
- Pydantic model validation (frozen, bounds)
- Catalog content verification (15+ products, valid structure)
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from expose.pipeline.saas_alignment import (
    AlignmentResult,
    ProductCatalog,
    ProductDefinition,
    ProductMatch,
    ProductSignature,
    SaaSAlignmentAnalyzer,
    SurfaceGap,
)

# ---------------------------------------------------------------------------
# Path to the shipped catalog
# ---------------------------------------------------------------------------
_CATALOG_PATH = (
    Path(__file__).resolve().parents[1]
    / "examples"
    / "product-signatures"
    / "catalog.json"
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def catalog() -> ProductCatalog:
    """Load the shipped product catalog."""
    return ProductCatalog(catalog_path=_CATALOG_PATH)


@pytest.fixture()
def analyzer(catalog: ProductCatalog) -> SaaSAlignmentAnalyzer:
    """Analyzer backed by the shipped catalog."""
    return SaaSAlignmentAnalyzer(catalog)


@pytest.fixture()
def mini_catalog(tmp_path: Path) -> ProductCatalog:
    """A minimal two-product catalog for focused tests."""
    data = {
        "schema_version": "1.0",
        "products": [
            {
                "product_id": "test-product-a",
                "vendor": "TestVendor",
                "product_name": "Product A",
                "category": "testing",
                "signatures": [
                    {"type": "url_path", "pattern": "/product-a/.*", "confidence": 0.9},
                    {
                        "type": "header",
                        "pattern": ".*",
                        "name": "x-product-a",
                        "value_pattern": ".*",
                        "confidence": 0.8,
                    },
                ],
                "expected_ports": [443],
                "related_products": ["test-product-b"],
            },
            {
                "product_id": "test-product-b",
                "vendor": "TestVendor",
                "product_name": "Product B",
                "category": "testing",
                "signatures": [
                    {"type": "url_path", "pattern": "/product-b/.*", "confidence": 0.7},
                    {
                        "type": "tls_san",
                        "pattern": ".*\\.productb\\.com$",
                        "confidence": 0.85,
                    },
                ],
                "expected_ports": [443, 8443],
                "related_products": ["test-product-a"],
            },
        ],
    }
    path = tmp_path / "catalog.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return ProductCatalog(catalog_path=path)


# ===========================================================================
# Catalog tests
# ===========================================================================


class TestCatalogLoading:
    """Tests for ProductCatalog load / query operations."""

    def test_load_from_json_file(self, catalog: ProductCatalog) -> None:
        products = catalog.list_products()
        assert len(products) > 0

    def test_get_product_by_id(self, catalog: ProductCatalog) -> None:
        product = catalog.get_product("cyberark-pam")
        assert product is not None
        assert product.vendor == "CyberArk"
        assert product.product_name == "Privileged Access Manager"

    def test_get_product_unknown_returns_none(self, catalog: ProductCatalog) -> None:
        assert catalog.get_product("nonexistent-product") is None

    def test_search_by_vendor(self, catalog: ProductCatalog) -> None:
        results = catalog.search_by_vendor("CyberArk")
        assert len(results) >= 2
        ids = {p.product_id for p in results}
        assert "cyberark-pam" in ids
        assert "cyberark-conjur" in ids

    def test_search_by_vendor_case_insensitive(self, catalog: ProductCatalog) -> None:
        results_lower = catalog.search_by_vendor("cyberark")
        results_upper = catalog.search_by_vendor("CYBERARK")
        assert len(results_lower) == len(results_upper)

    def test_list_all_products(self, catalog: ProductCatalog) -> None:
        products = catalog.list_products()
        ids = {p.product_id for p in products}
        assert "cyberark-pam" in ids
        assert "okta" in ids

    def test_invalid_catalog_path_raises(self) -> None:
        with pytest.raises(FileNotFoundError):
            ProductCatalog(catalog_path=Path("/nonexistent/catalog.json"))

    def test_invalid_json_structure_raises(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.json"
        bad.write_text('{"not_products": []}', encoding="utf-8")
        with pytest.raises(ValueError, match="products"):
            ProductCatalog(catalog_path=bad)

    def test_empty_catalog_has_no_products(self) -> None:
        catalog = ProductCatalog()
        assert catalog.list_products() == []


# ===========================================================================
# Fingerprinting tests
# ===========================================================================


class TestFingerprinting:
    """Inbound mode — matching observations against product signatures."""

    def test_url_path_match_cyberark(self, analyzer: SaaSAlignmentAnalyzer) -> None:
        obs = [{"url": "https://pvwa.corp.example.com/PasswordVault/api/accounts"}]
        matches = analyzer.fingerprint(obs)
        ids = {m.product_id for m in matches}
        assert "cyberark-pam" in ids

    def test_header_match_conjur(self, analyzer: SaaSAlignmentAnalyzer) -> None:
        obs = [
            {
                "url": "https://conjur.corp.example.com/",
                "headers": {"x-conjur-version": "5.12.0"},
            }
        ]
        matches = analyzer.fingerprint(obs)
        ids = {m.product_id for m in matches}
        assert "cyberark-conjur" in ids

    def test_no_match_returns_empty(self, analyzer: SaaSAlignmentAnalyzer) -> None:
        obs = [{"url": "https://random.example.com/about"}]
        matches = analyzer.fingerprint(obs)
        assert matches == []

    def test_multiple_products_matched(self, analyzer: SaaSAlignmentAnalyzer) -> None:
        obs = [
            {"url": "https://pvwa.example.com/PasswordVault/api/accounts"},
            {"url": "https://vault.example.com/v1/sys/health"},
        ]
        matches = analyzer.fingerprint(obs)
        ids = {m.product_id for m in matches}
        assert "cyberark-pam" in ids
        assert "hashicorp-vault" in ids

    def test_confidence_aggregation_takes_max(self, mini_catalog: ProductCatalog) -> None:
        """Multiple signatures match — confidence is max, not sum."""
        analyzer = SaaSAlignmentAnalyzer(mini_catalog)
        obs = [
            {
                "url": "https://example.com/product-a/stuff",
                "headers": {"x-product-a": "v1"},
            }
        ]
        matches = analyzer.fingerprint(obs)
        match = next(m for m in matches if m.product_id == "test-product-a")
        # url_path confidence=0.9, header confidence=0.8 -> max=0.9
        assert match.confidence == pytest.approx(0.9)
        assert len(match.matched_signatures) == 2

    def test_low_confidence_filtered_out(self, tmp_path: Path) -> None:
        """Products with only low-confidence hits below threshold are excluded."""
        data = {
            "schema_version": "1.0",
            "products": [
                {
                    "product_id": "low-conf-product",
                    "vendor": "Test",
                    "product_name": "Low Confidence",
                    "category": "testing",
                    "signatures": [
                        {"type": "url_path", "pattern": "/weak/.*", "confidence": 0.2},
                    ],
                    "expected_ports": [],
                    "related_products": [],
                }
            ],
        }
        path = tmp_path / "catalog.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        catalog = ProductCatalog(catalog_path=path)
        analyzer = SaaSAlignmentAnalyzer(catalog)

        obs = [{"url": "https://example.com/weak/endpoint"}]
        matches = analyzer.fingerprint(obs)
        assert matches == []

    def test_tls_san_match(self, analyzer: SaaSAlignmentAnalyzer) -> None:
        obs = [{"cert_sans": ["app.okta.com", "login.okta.com"]}]
        matches = analyzer.fingerprint(obs)
        ids = {m.product_id for m in matches}
        assert "okta" in ids

    def test_tls_issuer_match(self, analyzer: SaaSAlignmentAnalyzer) -> None:
        obs = [{"cert_issuer_org": "Amazon"}]
        matches = analyzer.fingerprint(obs)
        ids = {m.product_id for m in matches}
        assert "aws-generic" in ids

    def test_dns_cname_match(self, analyzer: SaaSAlignmentAnalyzer) -> None:
        obs = [{"dns_cname": "myapp.slack.com"}]
        matches = analyzer.fingerprint(obs)
        ids = {m.product_id for m in matches}
        assert "slack" in ids

    def test_server_header_match_cloudflare(self, analyzer: SaaSAlignmentAnalyzer) -> None:
        obs = [{"url": "https://example.com/", "server_header": "cloudflare"}]
        matches = analyzer.fingerprint(obs)
        ids = {m.product_id for m in matches}
        assert "cloudflare" in ids

    def test_favicon_hash_match(self, tmp_path: Path) -> None:
        data = {
            "schema_version": "1.0",
            "products": [
                {
                    "product_id": "favicon-test",
                    "vendor": "Test",
                    "product_name": "Favicon Test Product",
                    "category": "testing",
                    "signatures": [
                        {
                            "type": "favicon_hash",
                            "pattern": "sha256:abcdef1234567890",
                            "confidence": 0.9,
                        }
                    ],
                    "expected_ports": [],
                    "related_products": [],
                }
            ],
        }
        path = tmp_path / "catalog.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        catalog = ProductCatalog(catalog_path=path)
        analyzer = SaaSAlignmentAnalyzer(catalog)

        obs = [{"favicon_sha256": "abcdef1234567890"}]
        matches = analyzer.fingerprint(obs)
        assert len(matches) == 1
        assert matches[0].product_id == "favicon-test"

    def test_empty_observations_returns_empty(
        self, analyzer: SaaSAlignmentAnalyzer
    ) -> None:
        assert analyzer.fingerprint([]) == []


# ===========================================================================
# Expected surface tests
# ===========================================================================


class TestExpectedSurface:
    """Outbound mode — checking expected products against observations."""

    def test_missing_expected_product_produces_gap(
        self, analyzer: SaaSAlignmentAnalyzer
    ) -> None:
        # No observations match CyberArk PAM.
        obs = [{"url": "https://random.example.com/about"}]
        gaps = analyzer.validate_expected_surface(
            expected_products=["cyberark-pam"],
            observations=obs,
        )
        assert any(g.gap_type == "missing_expected" for g in gaps)
        assert any(g.product_id == "cyberark-pam" for g in gaps)

    def test_all_expected_found_no_gaps(
        self, analyzer: SaaSAlignmentAnalyzer
    ) -> None:
        obs = [
            {"url": "https://pvwa.example.com/PasswordVault/api/accounts"},
        ]
        gaps = analyzer.validate_expected_surface(
            expected_products=["cyberark-pam"],
            observations=obs,
        )
        missing = [g for g in gaps if g.gap_type == "missing_expected"]
        assert missing == []

    def test_unexpected_product_detected(
        self, analyzer: SaaSAlignmentAnalyzer
    ) -> None:
        obs = [
            # Matches CyberArk PAM (expected).
            {"url": "https://pvwa.example.com/PasswordVault/api/accounts"},
            # Also matches HashiCorp Vault (NOT expected).
            {"url": "https://vault.example.com/v1/sys/health"},
        ]
        gaps = analyzer.validate_expected_surface(
            expected_products=["cyberark-pam"],
            observations=obs,
        )
        unexpected = [g for g in gaps if g.gap_type == "unexpected_product"]
        unexpected_ids = {g.product_id for g in unexpected}
        assert "hashicorp-vault" in unexpected_ids

    def test_unexpected_product_severity_is_medium(
        self, analyzer: SaaSAlignmentAnalyzer
    ) -> None:
        obs = [
            {"url": "https://vault.example.com/v1/sys/health"},
        ]
        gaps = analyzer.validate_expected_surface(
            expected_products=[],
            observations=obs,
        )
        unexpected = [g for g in gaps if g.gap_type == "unexpected_product"]
        assert all(g.severity == "medium" for g in unexpected)

    def test_unknown_expected_product_produces_gap(
        self, analyzer: SaaSAlignmentAnalyzer
    ) -> None:
        gaps = analyzer.validate_expected_surface(
            expected_products=["totally-fake-product"],
            observations=[{"url": "https://example.com/"}],
        )
        assert any(
            g.product_id == "totally-fake-product"
            and g.gap_type == "missing_expected"
            for g in gaps
        )


# ===========================================================================
# Full analysis tests
# ===========================================================================


class TestAnalyze:
    """Combined fingerprint + gap analysis."""

    def test_analyze_with_expected_products(
        self, analyzer: SaaSAlignmentAnalyzer
    ) -> None:
        obs = [
            {"url": "https://pvwa.example.com/PasswordVault/api/accounts"},
        ]
        result = analyzer.analyze(
            observations=obs,
            expected_products=["cyberark-pam", "hashicorp-vault"],
        )
        assert isinstance(result, AlignmentResult)
        # PAM should be matched.
        matched_ids = {m.product_id for m in result.matched_products}
        assert "cyberark-pam" in matched_ids
        # Vault should be a gap (missing).
        gap_ids = {g.product_id for g in result.surface_gaps if g.gap_type == "missing_expected"}
        assert "hashicorp-vault" in gap_ids
        assert result.products_checked > 0
        assert result.entities_checked == 1

    def test_analyze_without_expected_products(
        self, analyzer: SaaSAlignmentAnalyzer
    ) -> None:
        obs = [{"url": "https://pvwa.example.com/PasswordVault/api/accounts"}]
        result = analyzer.analyze(observations=obs)
        assert result.surface_gaps == []
        assert len(result.matched_products) >= 1


# ===========================================================================
# Model validation tests
# ===========================================================================


class TestModels:
    """Pydantic model validation for frozen and constrained fields."""

    def test_product_signature_frozen(self) -> None:
        sig = ProductSignature(type="url_path", pattern="/foo/.*", confidence=0.5)
        with pytest.raises(ValidationError):
            sig.type = "header"  # type: ignore[misc]

    def test_product_signature_confidence_bounds(self) -> None:
        with pytest.raises(ValidationError):
            ProductSignature(type="url_path", pattern="/foo/.*", confidence=1.5)
        with pytest.raises(ValidationError):
            ProductSignature(type="url_path", pattern="/foo/.*", confidence=-0.1)

    def test_product_signature_pattern_min_length(self) -> None:
        with pytest.raises(ValidationError):
            ProductSignature(type="url_path", pattern="", confidence=0.5)

    def test_product_match_confidence_bounds(self) -> None:
        with pytest.raises(ValidationError):
            ProductMatch(
                product_id="x",
                vendor="v",
                product_name="n",
                matched_signatures=["a"],
                confidence=2.0,
                entity_identifier="e",
            )

    def test_product_match_frozen(self) -> None:
        m = ProductMatch(
            product_id="x",
            vendor="v",
            product_name="n",
            matched_signatures=["a"],
            confidence=0.5,
            entity_identifier="e",
        )
        with pytest.raises(ValidationError):
            m.confidence = 0.9  # type: ignore[misc]

    def test_surface_gap_frozen(self) -> None:
        g = SurfaceGap(
            product_id="x",
            product_name="n",
            gap_type="missing_expected",
            description="d",
        )
        with pytest.raises(ValidationError):
            g.severity = "high"  # type: ignore[misc]

    def test_alignment_result_frozen(self) -> None:
        r = AlignmentResult(
            matched_products=[],
            surface_gaps=[],
            products_checked=0,
            entities_checked=0,
        )
        with pytest.raises(ValidationError):
            r.products_checked = 5  # type: ignore[misc]

    def test_product_definition_extra_forbid(self) -> None:
        with pytest.raises(ValidationError):
            ProductDefinition(
                product_id="x",
                vendor="v",
                product_name="n",
                category="c",
                signatures=[],
                bonus_field="extra",  # type: ignore[call-arg]
            )


# ===========================================================================
# Catalog content verification
# ===========================================================================


class TestCatalogContent:
    """Verify the shipped catalog.json meets requirements."""

    def test_catalog_has_at_least_15_products(self, catalog: ProductCatalog) -> None:
        products = catalog.list_products()
        assert len(products) >= 15

    def test_all_products_have_valid_signatures(self, catalog: ProductCatalog) -> None:
        for product in catalog.list_products():
            assert len(product.signatures) >= 1, (
                f"{product.product_id} has no signatures"
            )
            for sig in product.signatures:
                assert sig.type in (
                    "url_path",
                    "header",
                    "tls_san",
                    "tls_issuer",
                    "favicon_hash",
                    "dns_cname",
                ), f"{product.product_id} has invalid sig type: {sig.type}"
                assert 0.0 <= sig.confidence <= 1.0

    def test_schema_version_present(self) -> None:
        raw = json.loads(_CATALOG_PATH.read_text(encoding="utf-8"))
        assert "schema_version" in raw
        assert raw["schema_version"] == "1.0"

    def test_all_products_have_required_fields(self, catalog: ProductCatalog) -> None:
        for product in catalog.list_products():
            assert product.product_id
            assert product.vendor
            assert product.product_name
            assert product.category

    def test_catalog_covers_required_categories(self, catalog: ProductCatalog) -> None:
        categories = {p.category for p in catalog.list_products()}
        # Must cover identity, security, infrastructure, collaboration, devops.
        assert any("identity" in c or "sso" in c for c in categories)
        assert any("security" in c or "secrets" in c for c in categories)
        assert "infrastructure" in categories
        assert "collaboration" in categories
        assert "devops" in categories
