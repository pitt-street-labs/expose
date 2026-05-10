# Evaluation Datasets

Sample evaluation datasets for the EXPOSE eval harness (issue #17).

## File format

Each JSON file represents an `EvalDataset` containing one or more `EvalCase` entries. The harness loads these via `expose.eval.load_dataset()` or `expose.eval.load_all_datasets()`.

## Categories

| Category | Description |
|---|---|
| `confirmed_yours` | Entities with strong ownership signals (cloud account match, WHOIS confirmation, multiple collectors) |
| `confirmed_not_yours` | Entities clearly belonging to another party (different registrant, no cloud match) |
| `ambiguous` | Entities with mixed signals requiring LLM enrichment to resolve |
| `adversarial` | Edge cases designed to test misattribution resistance |

## Dataset fields

| Field | Type | Description |
|---|---|---|
| `name` | string | Unique dataset name |
| `category` | string | One of the categories above |
| `cases` | array | List of `EvalCase` objects |

## EvalCase fields

| Field | Type | Description |
|---|---|---|
| `case_id` | string | Unique identifier within the dataset |
| `description` | string | Human-readable description of the scenario |
| `entity_type` | string | Target entity type (domain, ip, cidr, etc.) |
| `canonical_identifier` | string | The identifier under evaluation |
| `observations` | array | Synthetic collector observations (free-form dicts) |
| `expected_attribution` | string | Expected tier: confirmed, high, medium, not_yours |
| `expected_confidence_min` | float | Lower bound of acceptable confidence (0.0-1.0) |
| `expected_confidence_max` | float | Upper bound of acceptable confidence (0.0-1.0) |

## Usage

```python
from pathlib import Path
from expose.eval import load_all_datasets, EvalRunner

datasets = load_all_datasets(Path("examples/eval-datasets"))
runner = EvalRunner()  # uses stub attribution function
metrics = await runner.run_all(datasets)
for name, m in metrics.items():
    print(f"{name}: accuracy={m.attribution_accuracy:.0%}")
```
