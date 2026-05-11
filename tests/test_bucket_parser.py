"""Tests for the bucket_parser module — listing parsers and classification.

Coverage:
1.  Parse S3 XML listing -> BucketObject list
2.  Parse S3 XML with namespace
3.  Parse Azure XML listing
4.  Parse GCP JSON listing
5.  Sensitive file detection: .env
6.  Sensitive file detection: .pem
7.  Sensitive file detection: .key
8.  Sensitive file detection: config.json
9.  Non-sensitive files not flagged
10. Multiple sensitive patterns match across objects
11. Git directory detected
12. SQL backup detected
13. Empty listing -> empty list
14. BucketAnalysis model validation
15. Malformed XML/JSON -> empty list
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from expose.pipeline.bucket_parser import (
    BucketAnalysis,
    BucketObject,
    classify_objects,
    parse_azure_listing,
    parse_gcp_listing,
    parse_s3_listing,
)

# === 1. Parse S3 XML listing =================================================


class TestParseS3Listing:
    def test_s3_listing_basic(self) -> None:
        """S3 XML without namespace produces BucketObject records."""
        xml = """<?xml version="1.0" encoding="UTF-8"?>
        <ListBucketResult>
          <Contents>
            <Key>data/report.csv</Key>
            <Size>1024</Size>
            <LastModified>2024-01-15T10:30:00.000Z</LastModified>
          </Contents>
          <Contents>
            <Key>images/logo.png</Key>
            <Size>2048</Size>
            <LastModified>2024-02-20T14:00:00.000Z</LastModified>
          </Contents>
        </ListBucketResult>"""

        objects = parse_s3_listing(xml)
        assert len(objects) == 2
        assert objects[0].key == "data/report.csv"
        assert objects[0].size_bytes == 1024
        assert objects[0].last_modified == "2024-01-15T10:30:00.000Z"
        assert objects[1].key == "images/logo.png"
        assert objects[1].size_bytes == 2048

    def test_s3_listing_with_namespace(self) -> None:
        """S3 XML with the standard namespace is parsed correctly."""
        xml = """<?xml version="1.0" encoding="UTF-8"?>
        <ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
          <Contents>
            <Key>readme.txt</Key>
            <Size>512</Size>
          </Contents>
        </ListBucketResult>"""

        objects = parse_s3_listing(xml)
        assert len(objects) == 1
        assert objects[0].key == "readme.txt"
        assert objects[0].size_bytes == 512
        assert objects[0].last_modified is None

    def test_s3_malformed_xml(self) -> None:
        """Malformed XML returns empty list, not an exception."""
        objects = parse_s3_listing("<not valid xml<<<")
        assert objects == []

    def test_s3_empty_contents(self) -> None:
        """S3 listing with no <Contents> elements yields empty list."""
        xml = """<?xml version="1.0" encoding="UTF-8"?>
        <ListBucketResult>
        </ListBucketResult>"""

        objects = parse_s3_listing(xml)
        assert objects == []


# === 2. Parse Azure XML listing ===============================================


class TestParseAzureListing:
    def test_azure_listing_basic(self) -> None:
        """Azure XML listing produces BucketObject records."""
        xml = """<?xml version="1.0" encoding="UTF-8"?>
        <EnumerationResults>
          <Blobs>
            <Blob>
              <Name>documents/report.pdf</Name>
              <Properties>
                <Content-Length>4096</Content-Length>
                <Last-Modified>Mon, 15 Jan 2024 10:30:00 GMT</Last-Modified>
              </Properties>
            </Blob>
            <Blob>
              <Name>images/photo.jpg</Name>
              <Properties>
                <Content-Length>8192</Content-Length>
              </Properties>
            </Blob>
          </Blobs>
        </EnumerationResults>"""

        objects = parse_azure_listing(xml)
        assert len(objects) == 2
        assert objects[0].key == "documents/report.pdf"
        assert objects[0].size_bytes == 4096
        assert objects[0].last_modified == "Mon, 15 Jan 2024 10:30:00 GMT"
        assert objects[1].key == "images/photo.jpg"
        assert objects[1].size_bytes == 8192
        assert objects[1].last_modified is None

    def test_azure_malformed_xml(self) -> None:
        """Malformed Azure XML returns empty list."""
        objects = parse_azure_listing("<broken>")
        assert objects == []

    def test_azure_no_blobs_element(self) -> None:
        """Azure XML without <Blobs> yields empty list."""
        xml = """<?xml version="1.0" encoding="UTF-8"?>
        <EnumerationResults>
        </EnumerationResults>"""

        objects = parse_azure_listing(xml)
        assert objects == []


# === 3. Parse GCP JSON listing ================================================


class TestParseGcpListing:
    def test_gcp_listing_basic(self) -> None:
        """GCP JSON listing produces BucketObject records."""
        json_content = """{
          "items": [
            {
              "name": "data/export.csv",
              "size": "3072",
              "updated": "2024-01-15T10:30:00.000Z"
            },
            {
              "name": "logs/access.log",
              "size": "1024"
            }
          ]
        }"""

        objects = parse_gcp_listing(json_content)
        assert len(objects) == 2
        assert objects[0].key == "data/export.csv"
        assert objects[0].size_bytes == 3072
        assert objects[0].last_modified == "2024-01-15T10:30:00.000Z"
        assert objects[1].key == "logs/access.log"
        assert objects[1].size_bytes == 1024
        assert objects[1].last_modified is None

    def test_gcp_malformed_json(self) -> None:
        """Malformed JSON returns empty list."""
        objects = parse_gcp_listing("{invalid json!!!")
        assert objects == []

    def test_gcp_empty_items(self) -> None:
        """GCP JSON with empty items array yields empty list."""
        objects = parse_gcp_listing('{"items": []}')
        assert objects == []

    def test_gcp_no_items_key(self) -> None:
        """GCP JSON without items key yields empty list."""
        objects = parse_gcp_listing('{"kind": "storage#objects"}')
        assert objects == []


# === 4. Sensitive file detection ==============================================


class TestClassifyObjects:
    def test_env_file_detected(self) -> None:
        """A .env file is flagged as sensitive."""
        objects = [BucketObject(key="app/.env", size_bytes=100)]
        classified = classify_objects(objects)
        assert classified[0].is_sensitive is True
        assert classified[0].sensitivity_reason == "Environment variables file"

    def test_pem_file_detected(self) -> None:
        """A .pem file is flagged as sensitive."""
        objects = [BucketObject(key="certs/server.pem", size_bytes=2048)]
        classified = classify_objects(objects)
        assert classified[0].is_sensitive is True
        assert classified[0].sensitivity_reason == "PEM certificate/key"

    def test_key_file_detected(self) -> None:
        """A .key file is flagged as sensitive."""
        objects = [BucketObject(key="certs/private.key", size_bytes=1024)]
        classified = classify_objects(objects)
        assert classified[0].is_sensitive is True
        assert classified[0].sensitivity_reason == "Private key file"

    def test_config_json_detected(self) -> None:
        """A config.json file is flagged as sensitive."""
        objects = [BucketObject(key="settings/config.json", size_bytes=512)]
        classified = classify_objects(objects)
        assert classified[0].is_sensitive is True
        assert classified[0].sensitivity_reason == "Configuration file"

    def test_config_yaml_detected(self) -> None:
        """A config.yaml file is flagged as sensitive."""
        objects = [BucketObject(key="config.yaml", size_bytes=256)]
        classified = classify_objects(objects)
        assert classified[0].is_sensitive is True
        assert classified[0].sensitivity_reason == "Configuration file"

    def test_non_sensitive_not_flagged(self) -> None:
        """Normal files are not flagged as sensitive."""
        objects = [
            BucketObject(key="images/logo.png", size_bytes=4096),
            BucketObject(key="index.html", size_bytes=512),
            BucketObject(key="style.css", size_bytes=256),
        ]
        classified = classify_objects(objects)
        for obj in classified:
            assert obj.is_sensitive is False
            assert obj.sensitivity_reason is None

    def test_multiple_sensitive_patterns(self) -> None:
        """Multiple sensitive files across different patterns are all flagged."""
        objects = [
            BucketObject(key=".env", size_bytes=100),
            BucketObject(key="cert.pem", size_bytes=2048),
            BucketObject(key="swagger.json", size_bytes=5000),
            BucketObject(key="normal-file.txt", size_bytes=200),
        ]
        classified = classify_objects(objects)
        assert classified[0].is_sensitive is True
        assert classified[1].is_sensitive is True
        assert classified[2].is_sensitive is True
        assert classified[3].is_sensitive is False

    def test_git_directory_detected(self) -> None:
        """Files under .git/ directory are flagged."""
        objects = [BucketObject(key=".git/config", size_bytes=256)]
        classified = classify_objects(objects)
        assert classified[0].is_sensitive is True
        assert classified[0].sensitivity_reason == "Git repository data"

    def test_sql_backup_detected(self) -> None:
        """SQL backup files are flagged."""
        objects = [BucketObject(key="backup_2024.sql", size_bytes=1_000_000)]
        classified = classify_objects(objects)
        assert classified[0].is_sensitive is True
        assert classified[0].sensitivity_reason == "Database backup"

    def test_terraform_state_detected(self) -> None:
        """Files under .terraform/ directory are flagged."""
        objects = [BucketObject(key=".terraform/terraform.tfstate", size_bytes=512)]
        classified = classify_objects(objects)
        assert classified[0].is_sensitive is True
        assert classified[0].sensitivity_reason == "Terraform state"

    def test_wp_config_detected(self) -> None:
        """wp-config.php is flagged."""
        objects = [BucketObject(key="wp-config.php", size_bytes=4096)]
        classified = classify_objects(objects)
        assert classified[0].is_sensitive is True
        assert classified[0].sensitivity_reason == "WordPress configuration"

    def test_id_rsa_detected(self) -> None:
        """id_rsa SSH key is flagged."""
        objects = [BucketObject(key=".ssh/id_rsa", size_bytes=1679)]
        classified = classify_objects(objects)
        assert classified[0].is_sensitive is True
        assert classified[0].sensitivity_reason == "SSH private key"

    def test_empty_objects_list(self) -> None:
        """Empty input yields empty output."""
        classified = classify_objects([])
        assert classified == []


# === 5. BucketAnalysis model validation =======================================


class TestBucketAnalysisModel:
    def test_valid_analysis(self) -> None:
        """A valid BucketAnalysis is constructed without error."""
        analysis = BucketAnalysis(
            cloud_provider="aws",
            bucket_name="acme-data",
            is_public=True,
            is_listable=True,
            total_objects=5,
            sensitive_objects=[
                BucketObject(
                    key=".env",
                    size_bytes=100,
                    is_sensitive=True,
                    sensitivity_reason="Environment variables file",
                )
            ],
            extracted_endpoints=["https://acme-data.s3.amazonaws.com/swagger.json"],
        )
        assert analysis.cloud_provider == "aws"
        assert analysis.bucket_name == "acme-data"
        assert analysis.total_objects == 5
        assert len(analysis.sensitive_objects) == 1

    def test_empty_bucket_name_rejected(self) -> None:
        """An empty bucket_name violates the min_length=1 constraint."""
        with pytest.raises(ValidationError):
            BucketAnalysis(
                cloud_provider="aws",
                bucket_name="",
                is_public=False,
                is_listable=False,
                total_objects=0,
            )

    def test_negative_total_objects_rejected(self) -> None:
        """Negative total_objects violates the ge=0 constraint."""
        with pytest.raises(ValidationError):
            BucketAnalysis(
                cloud_provider="aws",
                bucket_name="test",
                is_public=False,
                is_listable=False,
                total_objects=-1,
            )

    def test_extra_fields_rejected(self) -> None:
        """Extra fields are forbidden by ConfigDict."""
        with pytest.raises(ValidationError):
            BucketAnalysis(
                cloud_provider="aws",
                bucket_name="test",
                is_public=False,
                is_listable=False,
                total_objects=0,
                extra_field="not allowed",  # type: ignore[call-arg]
            )

    def test_frozen_analysis(self) -> None:
        """BucketAnalysis instances are immutable (frozen)."""
        analysis = BucketAnalysis(
            cloud_provider="aws",
            bucket_name="test",
            is_public=False,
            is_listable=False,
            total_objects=0,
        )
        with pytest.raises(ValidationError):
            analysis.is_public = True  # type: ignore[misc]

    def test_bucket_object_empty_key_rejected(self) -> None:
        """BucketObject with empty key is rejected."""
        with pytest.raises(ValidationError):
            BucketObject(key="", size_bytes=0)

    def test_bucket_object_negative_size_rejected(self) -> None:
        """BucketObject with negative size_bytes is rejected."""
        with pytest.raises(ValidationError):
            BucketObject(key="file.txt", size_bytes=-1)
