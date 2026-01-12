from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from vehfuzz import __version__
from vehfuzz.core.artifacts import create_run_dirs
from vehfuzz.core.config import merge_root_dicts, parse_run_config
from vehfuzz.core.engine import run_campaign
from vehfuzz.core.plugins import load_builtin_plugins, list_plugins


@dataclass(frozen=True)
class LoadedConfig:
    name: str
    path: Path
    sha256: str
    data: Any


def _project_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _collect_config_files(config_dir: Path) -> list[Path]:
    if not config_dir.exists():
        return []

    patterns = ("*.yaml", "*.yml", "*.json")
    files: set[Path] = set()
    for pattern in patterns:
        files.update(config_dir.glob(pattern))
    return sorted(files, key=lambda p: p.name.lower())


def _load_config_file(path: Path) -> Any:
    suffix = path.suffix.lower()
    if suffix in (".yaml", ".yml"):
        with path.open("r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    if suffix == ".json":
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    raise ValueError(f"Unsupported config file type: {path.name}")


def _load_configs(config_dir: Path) -> list[LoadedConfig]:
    loaded: list[LoadedConfig] = []
    for path in _collect_config_files(config_dir):
        loaded.append(
            LoadedConfig(
                name=path.name,
                path=path.resolve(),
                sha256=_sha256_file(path),
                data=_load_config_file(path),
            )
        )
    return loaded


def _default_run_id(configs: list[LoadedConfig]) -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    digest = hashlib.sha256()
    for cfg in configs:
        digest.update(cfg.sha256.encode("utf-8"))
        digest.update(b"\n")
    return f"{timestamp}-{digest.hexdigest()[:8]}"


def _write_text(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8", newline="\n")


def _cmd_run(args: argparse.Namespace) -> int:
    config_dir = Path(args.config_dir).resolve()
    runs_dir = Path(args.runs_dir).resolve()

    configs = _load_configs(config_dir)
    if not configs:
        raise SystemExit(f"No config files found in: {config_dir}")

    run_id = args.run_id or _default_run_id(configs)
    run_dir = runs_dir / run_id

    if args.dry_run:
        print(f"run_id: {run_id}")
        print(f"config_dir: {config_dir}")
        print(f"runs_dir: {runs_dir}")
        print(f"run_dir: {run_dir}")
        for cfg in configs:
            print(f"- {cfg.name}  sha256={cfg.sha256}")
        return 0

    paths = create_run_dirs(run_dir)

    for cfg in configs:
        (paths.config_dir / cfg.name).write_bytes(cfg.path.read_bytes())

    merged = merge_root_dicts([cfg.data for cfg in configs])
    run_cfg = parse_run_config(config_dir=config_dir, merged=merged)

    manifest = {
        "tool": {"name": "vehfuzz", "version": __version__},
        "run_id": run_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "config_dir": str(config_dir),
        "runs_dir": str(runs_dir),
        "configs": [
            {
                "name": cfg.name,
                "path": str(cfg.path),
                "sha256": cfg.sha256,
            }
            for cfg in configs
        ],
        "notes": "vehfuzz run",
    }
    _write_text(
        paths.manifest_path,
        json.dumps(manifest, ensure_ascii=False, indent=2),
    )

    if args.no_exec:
        lines = [
            "# vehfuzz report (no-exec)",
            "",
            f"- run_id: `{run_id}`",
            f"- created_at: `{manifest['created_at']}`",
            "",
            "## Config Snapshot",
        ]
        for cfg in configs:
            lines.append(f"- `{cfg.name}` sha256 `{cfg.sha256}`")
        lines.extend(["", "## Status", "", "- Run created with `--no-exec`.", ""])
        _write_text(paths.report_path, "\n".join(lines))
        print(str(run_dir))
        return 0

    stats = run_campaign(
        run_id=run_id,
        config_dir=run_cfg.config_dir,
        target_cfg=run_cfg.target,
        campaign_cfg=run_cfg.campaign,
        oracle_cfg=run_cfg.oracle,
        paths=paths,
    )
    engine = str(run_cfg.campaign.get("engine", "vehfuzz")).lower()

    lines = [
        "# vehfuzz report",
        "",
        f"- run_id: `{run_id}`",
        f"- created_at: `{manifest['created_at']}`",
        f"- engine: `{engine}`",
        "",
        "## Config Snapshot",
    ]
    for cfg in configs:
        lines.append(f"- `{cfg.name}` sha256 `{cfg.sha256}`")
    lines.extend(
        [
            "",
            "## Summary",
            "",
            f"- cases: `{stats.cases}`",
            f"- tx: `{stats.tx}`",
            f"- rx: `{stats.rx}`",
            f"- errors: `{stats.errors}`",
            f"- anomalies: `{stats.anomalies}`",
            f"- duration_s: `{stats.duration_s:.3f}`",
            "",
            "## Artifacts",
            "",
            f"- events: `artifacts/events.jsonl`",
            f"- summary: `artifacts/summary.json`",
        ]
    )
    if engine == "boofuzz":
        lines.extend(
            [
                f"- boofuzz csv: `artifacts/boofuzz.csv`",
                f"- boofuzz stdout: `artifacts/boofuzz.stdout.log`",
                f"- boofuzz stderr: `artifacts/boofuzz.stderr.log`",
            ]
        )
    if engine != "boofuzz" and run_cfg.campaign.get("mode", "offline") == "offline" and stats.offline_artifact:
        lines.append(f"- mutated corpus: `artifacts/{stats.offline_artifact}`")
    lines.append("")
    _write_text(paths.report_path, "\n".join(lines))

    print(str(run_dir))
    return 0


def _cmd_plugins(_args: argparse.Namespace) -> int:
    load_builtin_plugins()
    print(json.dumps(list_plugins(), ensure_ascii=False, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    project_root = _project_root()
    default_config_dir = project_root / "configs"
    default_runs_dir = project_root / "runs"

    parser = argparse.ArgumentParser(
        prog="vehfuzz",
        description="vehfuzz - headless automotive fuzzing platform (skeleton)",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    subparsers = parser.add_subparsers(dest="command", required=True)

    run_p = subparsers.add_parser("run", help="Create a run directory from configs")
    run_p.add_argument(
        "--config-dir",
        default=str(default_config_dir),
        help="Directory containing *.yaml/*.yml/*.json configs (default: %(default)s)",
    )
    run_p.add_argument(
        "--runs-dir",
        default=str(default_runs_dir),
        help="Directory to place run artifacts (default: %(default)s)",
    )
    run_p.add_argument(
        "--run-id",
        default=None,
        help="Override run_id (default: generated from timestamp + config hash)",
    )
    run_p.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be done without creating files",
    )
    run_p.add_argument(
        "--no-exec",
        action="store_true",
        help="Create run directory and snapshots only (do not execute)",
    )
    run_p.set_defaults(func=_cmd_run)

    plugins_p = subparsers.add_parser("plugins", help="List built-in plugins")
    plugins_p.set_defaults(func=_cmd_plugins)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))
