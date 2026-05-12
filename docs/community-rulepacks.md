# Contributing Community Rule Packs

Community rule packs extend EXPOSE's attribution engine with domain-specific
logic. A rule pack is a declarative JSON file containing attribution rules
(boolean condition trees) and a lead-score formula. Rule packs are data, not
code -- the engine applies them deterministically using its fixed predicate
vocabulary. See `schemas/rulepack-v1.json` for the authoritative schema.

## Pack structure

Each community pack lives in its own directory under `community-rulepacks/`:

```
community-rulepacks/
  industry-healthcare/
    rules.json       # the rule pack (conforms to rulepack-v1 schema)
    README.md        # what this pack does, who it's for, known limitations
```

### Required metadata in `rules.json`

Every pack must set these top-level fields:

| Field | Format | Example |
|-------|--------|---------|
| `pack_id` | `^[a-z0-9][a-z0-9-]*[a-z0-9]$` | `industry-healthcare` |
| `pack_version` | semver (`X.Y.Z`) | `1.0.0` |
| `pack_format_version` | must be `"v1"` | `v1` |
| `description` | free text | `"Rules for healthcare orgs..."` |

The `pack_id` must match the directory name.

### Rule format

Each rule in `attribution_rules` requires `rule_id`, `rule_version`,
`description`, `when` (condition tree), and `then` (action). See the
`example-baseline.json` pack in `examples/rulepacks/` for a complete working
example, and `schemas/rulepack-v1.json` for the full condition/action schema.

Available predicates are listed in the schema's `PredicateCondition` enum.
Custom predicates cannot be added via rule packs -- they require engine changes.

## Contributing a rule pack

1. Fork the repository and create a branch.
2. Create your pack directory: `community-rulepacks/<pack-name>/`.
3. Write `rules.json` conforming to the rulepack-v1 schema.
4. Write a `README.md` explaining the pack's purpose, target audience, and any
   assumptions about the tenant's authorization scope.
5. Validate, test, and submit a PR.

### Naming conventions

Use these prefixes so packs are discoverable:

| Prefix | Use case | Examples |
|--------|----------|---------|
| `industry-{sector}` | Vertical/sector-specific | `industry-healthcare`, `industry-finserv` |
| `compliance-{framework}` | Regulatory framework rules | `compliance-fedramp`, `compliance-pci` |
| `technique-{category}` | TTP-based detection logic | `technique-typosquat`, `technique-subdomain-takeover` |

### Validation

Validate against the JSON Schema:

```bash
check-jsonschema --schemafile schemas/rulepack-v1.json \
  community-rulepacks/my-pack/rules.json
```

Or via Pydantic:

```python
import json
from expose.types.rulepack import RulePack

with open("community-rulepacks/my-pack/rules.json") as f:
    data = json.load(f)
data.pop("$schema", None)
RulePack.model_validate(data)
```

### Running the eval harness

Test your pack against the reference eval datasets:

```bash
python3 -m expose.eval.cli \
  --datasets examples/eval-datasets \
  --rulepack community-rulepacks/my-pack/rules.json \
  --output-format json \
  --output-file /tmp/eval-my-pack.json
```

This produces per-category precision/recall/F1 across four dataset categories:
`confirmed_yours`, `confirmed_not_yours`, `ambiguous`, and `adversarial`.

## Quality requirements

- **Minimum 5 rules** per pack.
- **Test cases required.** Include at least one test case per rule in eval
  dataset format (see `examples/eval-datasets/` for the structure). Place them
  in your pack directory as `test-cases.json`.
- **No duplicate coverage.** Your pack should address a domain not already
  covered by existing packs in `examples/rulepacks/` or `community-rulepacks/`.
  Extending an existing pack via `depends_on` is preferred over duplicating
  rules.
- **Schema validation must pass.** CI runs `check-jsonschema` on all packs
  automatically.
- **Document assumptions.** If your rules assume specific predicates or
  authorization scope patterns, state this in the pack's README.

## Review process

1. Open a pull request with your pack directory.
2. CI validates the pack against the schema and runs the eval harness.
3. A maintainer reviews for:
   - **Correctness** -- do the rules produce sensible outcomes?
   - **Security** -- do any rules weaken attribution guarantees (e.g.,
     over-aggressive promotion, disabled rejection rules)?
   - **Overlap** -- does this duplicate existing packs?
   - **Documentation** -- is the README clear about scope and limitations?
4. After approval, the pack is merged into `community-rulepacks/` and listed
   in the community pack index.

Packs that weaken the rejection rule layer or promote without sufficient
evidence signals will be asked to revise.
