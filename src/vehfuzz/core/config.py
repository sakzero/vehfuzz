from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class RunConfig:
    config_dir: Path
    target: dict[str, Any]
    campaign: dict[str, Any]
    oracle: dict[str, Any]


def merge_root_dicts(config_items: list[dict[str, Any]]) -> dict[str, Any]:
    merged: dict[str, Any] = {}
    for item in config_items:
        for key, value in item.items():
            if key in merged:
                raise ValueError(f"Duplicate top-level config key: {key}")
            merged[key] = value
    return merged


def parse_run_config(*, config_dir: Path, merged: dict[str, Any]) -> RunConfig:
    if "campaign" not in merged or not isinstance(merged["campaign"], dict):
        raise ValueError("Missing required config: campaign")
    if "target" not in merged or not isinstance(merged["target"], dict):
        raise ValueError("Missing required config: target")

    oracle = merged.get("oracle")
    if oracle is None:
        oracle = {}
    if not isinstance(oracle, dict):
        raise ValueError("Invalid config: oracle must be a mapping")

    return RunConfig(
        config_dir=config_dir,
        target=merged["target"],
        campaign=merged["campaign"],
        oracle=oracle,
    )


def resolve_path(config_dir: Path, maybe_path: str | None) -> Path | None:
    if maybe_path is None:
        return None
    path = Path(maybe_path)
    if path.is_absolute():
        return path
    return (config_dir / path).resolve()

