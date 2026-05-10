# EXPOSE Rule Packs

Rule packs are versioned, declarative JSON files that define how the EXPOSE
attribution engine classifies discovered entities. Each rule pack contains
attribution rules (boolean condition trees evaluated against an entity's graph
context) and a lead-score formula (weighted scoring that prioritizes entities
for analyst review). Rule packs are data, not code -- the engine consumes them
and applies them deterministically. They cannot extend the predicate vocabulary;
only engine updates can add new predicates.

Operators select a rule pack per tenant to tune attribution behavior for their
environment. Organizations with different risk postures, infrastructure
profiles, or compliance requirements can use different packs without modifying
the engine.

## Available Rule Packs

| Pack | File | Description |
|------|------|-------------|
| **Baseline** | `example-baseline.json` | Minimal starter pack demonstrating the rule format. Balanced thresholds suitable for general-purpose use. Not intended for production without review. |
| **Cloud-First** | `cloud-first.json` | Optimized for organizations with heavy cloud footprint (AWS, Azure, GCP). Lowers attribution thresholds for cloud-hosted assets, boosts confidence for cloud IP matches, and includes rules for cloud service naming patterns (S3, CloudFront, Azure Blob, GCP Storage). |
| **Conservative** | `conservative.json` | Designed for high-assurance and government environments. Raises attribution thresholds across the board, requires multiple independent signals for confirmed tier, penalizes single-source attributions, and flags ambiguous entities for mandatory analyst review. |

## Selecting a Rule Pack

Rule packs are assigned per tenant in the tenant configuration. The `pack_id`
field in the rule pack JSON matches the identifier referenced in the tenant's
`rulepack_id` setting:

```json
{
  "tenant_id": "...",
  "rulepack_id": "cloud-first"
}
```

The engine resolves the pack by `pack_id` at run time. Only one rule pack is
active per tenant per run.

## Creating Custom Rule Packs

1. Start from an existing pack (copy `example-baseline.json` as a template).
2. Set a unique `pack_id` (lowercase alphanumeric with dashes, e.g., `acme-prod`).
3. Set `pack_format_version` to `"v1"`.
4. Define attribution rules using the closed predicate vocabulary (see the
   schema for the full list of available predicates).
5. Configure `tier_thresholds` to control the confidence boundaries for
   `confirmed`, `high`, and `medium` tiers.
6. Define the `lead_score_formula` with weights and modifiers appropriate for
   your environment.
7. Validate the pack against the schema before deployment.

### Rule Structure

Each attribution rule has:

- **`rule_id`** -- unique identifier within the pack (lowercase slug).
- **`when`** -- a boolean condition tree (`all_of`, `any_of`, `not`, or a
  single `predicate`).
- **`then`** -- the action to take when the condition matches (`promote`,
  `demote`, `neutral`, or `reject`) with an optional `confidence_delta`.
- **`priority`** -- evaluation order (lower numbers first).
- **`category`** -- classification for reporting and analysis.

### Validation

Validate a rule pack against the JSON Schema:

```bash
check-jsonschema --schemafile schemas/rulepack-v1.json examples/rulepacks/my-pack.json
```

Or via the Pydantic model in Python:

```python
import json
from expose.types.rulepack import RulePack

with open("examples/rulepacks/my-pack.json") as f:
    data = json.load(f)

# Strip $schema (editor convention, not consumed by the model)
data.pop("$schema", None)
pack = RulePack.model_validate(data)
```

## Schema Reference

The authoritative schema is at `schemas/rulepack-v1.json` (JSON Schema Draft
2020-12). All rule packs must conform to this schema.
