"""Evaluation dataset models and loaders.

An evaluation dataset is a JSON file containing a list of :class:`EvalCase`
instances.  Each case carries synthetic observations plus the expected
attribution outcome so the harness can score an attribution function
without a live pipeline.

File format (JSON)::

    {
        "name": "confirmed_yours",
        "category": "confirmed_yours",
        "cases": [
            {
                "case_id": "cy-001",
                "description": "...",
                "entity_type": "domain",
                "canonical_identifier": "example.com",
                "observations": [...],
                "expected_attribution": "confirmed",
                "expected_confidence_min": 0.95,
                "expected_confidence_max": 1.0,
            }
        ],
    }
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class EvalResult(BaseModel):
    """Per-case result from running an attribution function on an eval case.

    Defined here (alongside :class:`EvalCase` / :class:`EvalDataset`) to
    avoid a circular import between ``runner`` and ``metrics``.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: str
    expected_attribution: str
    actual_attribution: str
    expected_confidence_range: tuple[float, float]
    actual_confidence: float = Field(ge=0.0, le=1.0)
    correct: bool
    duration_ms: float = Field(ge=0.0)


class EvalCase(BaseModel):
    """A single evaluation case with expected attribution outcome."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: str
    description: str
    entity_type: str
    canonical_identifier: str
    observations: list[dict[str, Any]]
    expected_attribution: str
    expected_confidence_min: float = Field(ge=0.0, le=1.0)
    expected_confidence_max: float = Field(ge=0.0, le=1.0)


class EvalDataset(BaseModel):
    """A named collection of evaluation cases in a single category."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    category: str
    cases: list[EvalCase]


def load_dataset(path: Path) -> EvalDataset:
    """Load a single evaluation dataset from a JSON file.

    Raises ``FileNotFoundError`` if *path* does not exist, or
    ``pydantic.ValidationError`` if the JSON does not match the schema.
    """
    raw = json.loads(path.read_text(encoding="utf-8"))
    return EvalDataset.model_validate(raw)


def load_all_datasets(directory: Path) -> list[EvalDataset]:
    """Load every ``*.json`` file in *directory* as an :class:`EvalDataset`.

    Returns an empty list if the directory contains no JSON files.

    Raises ``NotADirectoryError`` if *directory* is not a directory.
    """
    if not directory.is_dir():
        msg = f"Not a directory: {directory}"
        raise NotADirectoryError(msg)

    datasets: list[EvalDataset] = []
    for json_path in sorted(directory.glob("*.json")):
        datasets.append(load_dataset(json_path))
    return datasets


# The four canonical evaluation categories.
EVAL_CATEGORIES: tuple[str, ...] = (
    "confirmed_yours",
    "confirmed_not_yours",
    "ambiguous",
    "adversarial",
)


def load_dataset_by_category(
    directory: Path,
    category: str,
) -> EvalDataset:
    """Load the dataset file for a specific evaluation category.

    Looks for ``<category>.json`` inside *directory*.  Raises
    ``FileNotFoundError`` if the file does not exist, or
    ``ValueError`` if *category* is not one of the four canonical
    categories.
    """
    if category not in EVAL_CATEGORIES:
        msg = (
            f"Unknown eval category '{category}'. "
            f"Valid categories: {', '.join(EVAL_CATEGORIES)}"
        )
        raise ValueError(msg)

    path = directory / f"{category}.json"
    return load_dataset(path)


def load_datasets_by_categories(
    directory: Path,
    categories: list[str] | None = None,
) -> list[EvalDataset]:
    """Load datasets for the given categories (or all four if *categories* is ``None``).

    Returns datasets in the order of *categories*.  Raises ``ValueError``
    for unknown categories and ``FileNotFoundError`` for missing files.
    """
    targets = list(categories) if categories else list(EVAL_CATEGORIES)
    return [load_dataset_by_category(directory, cat) for cat in targets]
