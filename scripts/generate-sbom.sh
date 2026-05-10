#!/usr/bin/env bash
# Generate SBOM for the EXPOSE container image using syft.
#
# Produces both CycloneDX (preferred for security tooling) and SPDX (for
# compliance reporting) formats.  When cosign is available, the CycloneDX
# SBOM is also attached to the image as an OCI artifact so consumers can
# retrieve it directly from the registry.
#
# Usage:
#   ./scripts/generate-sbom.sh <image:tag> [output-dir]
#
# Examples:
#   ./scripts/generate-sbom.sh expose:dev
#   ./scripts/generate-sbom.sh ghcr.io/korlogos/expose:v1.0.0 dist/sbom
#
# Prerequisites:
#   - syft v1.x+  (https://github.com/anchore/syft)
#   - cosign v2.x+ (optional, for SBOM attachment)
set -euo pipefail

IMAGE="${1:?Usage: generate-sbom.sh <image:tag> [output-dir]}"
OUTPUT_DIR="${2:-sbom}"

mkdir -p "$OUTPUT_DIR"

echo "Generating SBOMs for image: $IMAGE"

# CycloneDX format (recommended for security tools — Dependency-Track, Grype)
syft "$IMAGE" -o cyclonedx-json > "$OUTPUT_DIR/expose-sbom.cdx.json"

# SPDX format (for compliance — FedRAMP, NTIA minimum elements)
syft "$IMAGE" -o spdx-json > "$OUTPUT_DIR/expose-sbom.spdx.json"

echo "SBOMs generated in $OUTPUT_DIR/"
echo "  CycloneDX: expose-sbom.cdx.json"
echo "  SPDX:      expose-sbom.spdx.json"

# Optionally attach the CycloneDX SBOM to the image in the registry.
if command -v cosign &>/dev/null; then
    echo "Attaching SBOM to image..."
    cosign attach sbom --sbom "$OUTPUT_DIR/expose-sbom.cdx.json" "$IMAGE"
    echo "SBOM attached to $IMAGE"
else
    echo "cosign not found — skipping SBOM attachment to image."
    echo "Install cosign to attach SBOMs as OCI artifacts."
fi
