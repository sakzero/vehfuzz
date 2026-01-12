from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ArtifactPaths:
    run_dir: Path
    config_dir: Path
    artifacts_dir: Path
    events_path: Path
    report_path: Path
    manifest_path: Path


class EventLogger:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._fp = path.open("w", encoding="utf-8", newline="\n")

    def log(self, event: dict[str, Any]) -> None:
        self._fp.write(json.dumps(event, ensure_ascii=False) + "\n")
        self._fp.flush()

    def close(self) -> None:
        self._fp.close()


def create_run_dirs(run_dir: Path) -> ArtifactPaths:
    run_dir.mkdir(parents=True, exist_ok=False)
    config_dir = run_dir / "config"
    artifacts_dir = run_dir / "artifacts"
    config_dir.mkdir(parents=True, exist_ok=False)
    artifacts_dir.mkdir(parents=True, exist_ok=False)

    return ArtifactPaths(
        run_dir=run_dir,
        config_dir=config_dir,
        artifacts_dir=artifacts_dir,
        events_path=artifacts_dir / "events.jsonl",
        report_path=run_dir / "report.md",
        manifest_path=run_dir / "manifest.json",
    )

