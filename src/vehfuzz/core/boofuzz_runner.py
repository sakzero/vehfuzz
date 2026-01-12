from __future__ import annotations

import csv
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from vehfuzz.core.artifacts import ArtifactPaths, EventLogger
from vehfuzz.core.config import resolve_path


@dataclass(frozen=True)
class BoofuzzRun:
    returncode: int | None
    timed_out: bool
    duration_s: float
    cases: int
    tx: int
    rx: int
    errors: int
    fails: int
    passes: int
    csv_path: str | None
    stdout_path: str
    stderr_path: str


_TEST_CASE_ID_RE = re.compile(r"(?i)\btest\s*case\s*(?P<id>\d+)\b")


def _vehfuzz_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _maybe_add_pythonpath(env: dict[str, str], path: Path) -> None:
    if not path.exists():
        return
    cur = env.get("PYTHONPATH", "")
    prefix = str(path)
    env["PYTHONPATH"] = prefix if not cur else prefix + os.pathsep + cur


def _parse_boofuzz_csv(
    *,
    csv_path: Path,
    events: EventLogger,
    evt_base: dict[str, Any],
) -> tuple[int, int, int, int, int, int]:
    cases = tx = rx = errors = fails = passes = 0
    current_case: int | None = None

    with csv_path.open("r", encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.reader(f)
        for row in reader:
            if not row:
                continue

            ts = row[0] if len(row) >= 1 else ""
            kind = row[1] if len(row) >= 2 else ""
            # row format: [ts, kind, len, hexstr, repr/desc]
            col_len = row[2] if len(row) >= 3 else ""
            col_hex = row[3] if len(row) >= 4 else ""
            col_desc = row[4] if len(row) >= 5 else ""

            if kind == "open test case":
                m = _TEST_CASE_ID_RE.search(col_desc)
                if m:
                    current_case = int(m.group("id"))
                else:
                    current_case = current_case + 1 if current_case is not None else 0
                cases += 1
                events.log({**evt_base, "ts": ts, "event": "case", "case_id": current_case, "desc": col_desc})
                continue

            case_id = current_case if current_case is not None else -1

            if kind == "send":
                tx += 1
                try:
                    length = int(col_len)
                except Exception:
                    length = None
                events.log(
                    {
                        **evt_base,
                        "ts": ts,
                        "event": "tx",
                        "case_id": case_id,
                        "len": length,
                        "hex": col_hex.replace(" ", ""),
                        "raw": row,
                    }
                )
                continue

            if kind == "recv":
                rx += 1
                try:
                    length = int(col_len)
                except Exception:
                    length = None
                events.log(
                    {
                        **evt_base,
                        "ts": ts,
                        "event": "rx",
                        "case_id": case_id,
                        "len": length,
                        "hex": col_hex.replace(" ", ""),
                        "raw": row,
                    }
                )
                continue

            if kind == "error":
                errors += 1
                events.log({**evt_base, "ts": ts, "event": "error", "case_id": case_id, "error": col_desc, "raw": row})
                continue

            if kind == "fail":
                fails += 1
                events.log({**evt_base, "ts": ts, "event": "fail", "case_id": case_id, "desc": col_desc, "raw": row})
                continue

            if kind == "pass":
                passes += 1
                events.log({**evt_base, "ts": ts, "event": "pass", "case_id": case_id, "desc": col_desc, "raw": row})
                continue

            if kind in ("info", "check", "open step"):
                events.log({**evt_base, "ts": ts, "event": kind.replace(" ", "_"), "case_id": case_id, "desc": col_desc, "raw": row})
                continue

            # Unknown line type; keep it for debugging.
            events.log({**evt_base, "ts": ts, "event": "boofuzz_log", "case_id": case_id, "raw": row})

    return cases, tx, rx, errors, fails, passes


def run_boofuzz_campaign(
    *,
    run_id: str,
    config_dir: Path,
    target_cfg: dict[str, Any],
    campaign_cfg: dict[str, Any],
    oracle_cfg: dict[str, Any],
    paths: ArtifactPaths,
    events: EventLogger,
) -> tuple[BoofuzzRun, dict[str, Any]]:
    boofuzz_cfg = campaign_cfg.get("boofuzz", {})
    if boofuzz_cfg is None:
        boofuzz_cfg = {}
    if not isinstance(boofuzz_cfg, dict):
        raise ValueError("campaign.boofuzz must be a mapping")

    script = boofuzz_cfg.get("script")
    if not script or not isinstance(script, str):
        raise ValueError("campaign.boofuzz.script is required for engine=boofuzz")

    script_path = resolve_path(config_dir, script)
    if script_path is None:
        raise ValueError("campaign.boofuzz.script path could not be resolved")
    if not script_path.exists():
        raise FileNotFoundError(str(script_path))

    args = boofuzz_cfg.get("args", [])
    if args is None:
        args = []
    if not isinstance(args, list) or any(not isinstance(a, (str, int, float)) for a in args):
        raise ValueError("campaign.boofuzz.args must be a list of strings/numbers")
    args = [str(a) for a in args]

    timeout_s = boofuzz_cfg.get("timeout_s")
    timeout_s_f: float | None
    if timeout_s is None:
        timeout_s_f = None
    else:
        timeout_s_f = float(timeout_s)
        if timeout_s_f <= 0:
            timeout_s_f = None

    python_exe = boofuzz_cfg.get("python")
    if python_exe is None:
        python_exe = sys.executable
    python_exe = str(python_exe)

    stdout_path = paths.artifacts_dir / "boofuzz.stdout.log"
    stderr_path = paths.artifacts_dir / "boofuzz.stderr.log"
    csv_path = paths.artifacts_dir / "boofuzz.csv"

    env = dict(os.environ)
    env.update(
        {
            "VEHFUZZ_RUN_ID": run_id,
            "VEHFUZZ_RUN_DIR": str(paths.run_dir),
            "VEHFUZZ_CONFIG_DIR": str(config_dir),
            "VEHFUZZ_ARTIFACTS_DIR": str(paths.artifacts_dir),
            "VEHFUZZ_BOOFUZZ_CSV": str(csv_path),
            "VEHFUZZ_TARGET_JSON": json.dumps(target_cfg, ensure_ascii=False),
            "VEHFUZZ_CAMPAIGN_JSON": json.dumps(campaign_cfg, ensure_ascii=False),
            "VEHFUZZ_ORACLE_JSON": json.dumps(oracle_cfg or {}, ensure_ascii=False),
        }
    )

    extra_env = boofuzz_cfg.get("env", {})
    if extra_env is None:
        extra_env = {}
    if not isinstance(extra_env, dict) or any(not isinstance(k, str) for k in extra_env.keys()):
        raise ValueError("campaign.boofuzz.env must be a mapping of string keys")
    for k, v in extra_env.items():
        env[k] = str(v)

    # Convenience: allow importing vendored boofuzz without pip install.
    if bool(boofuzz_cfg.get("add_repo_boofuzz_to_pythonpath", True)):
        boofuzz_root = _vehfuzz_root().parent / "boofuzz"
        _maybe_add_pythonpath(env, boofuzz_root)

    cmd = [python_exe, str(script_path), *args]

    evt_base = {
        "run_id": run_id,
        "campaign": str(campaign_cfg.get("name", "campaign")),
        "protocol": str(campaign_cfg.get("protocol", "boofuzz")).lower(),
        "engine": "boofuzz",
    }
    events.log({**evt_base, "event": "boofuzz_start", "cmd": cmd, "cwd": str(config_dir), "timeout_s": timeout_s_f})

    start = time.time()
    timed_out = False
    returncode: int | None = None
    with stdout_path.open("wb") as out_fp, stderr_path.open("wb") as err_fp:
        try:
            proc = subprocess.run(
                cmd,
                cwd=str(config_dir),
                env=env,
                stdout=out_fp,
                stderr=err_fp,
                timeout=timeout_s_f,
                check=False,
            )
            returncode = int(proc.returncode)
        except subprocess.TimeoutExpired:
            timed_out = True
        except Exception as e:
            events.log({**evt_base, "event": "boofuzz_error", "error": str(e)})

    duration_s = max(0.0, time.time() - start)

    # Parse boofuzz CSV (if the script produced it).
    cases = tx = rx = errors = fails = passes = 0
    if csv_path.exists():
        try:
            cases, tx, rx, errors, fails, passes = _parse_boofuzz_csv(csv_path=csv_path, events=events, evt_base=evt_base)
        except Exception as e:
            events.log({**evt_base, "event": "boofuzz_csv_parse_error", "error": str(e)})
    else:
        events.log({**evt_base, "event": "boofuzz_csv_missing", "path": str(csv_path)})

    events.log(
        {
            **evt_base,
            "event": "boofuzz_done",
            "returncode": returncode,
            "timed_out": timed_out,
            "duration_s": duration_s,
            "cases": cases,
            "tx": tx,
            "rx": rx,
            "errors": errors,
            "fails": fails,
            "passes": passes,
        }
    )

    run = BoofuzzRun(
        returncode=returncode,
        timed_out=timed_out,
        duration_s=duration_s,
        cases=cases,
        tx=tx,
        rx=rx,
        errors=errors,
        fails=fails,
        passes=passes,
        csv_path=str(csv_path) if csv_path.exists() else None,
        stdout_path=str(stdout_path),
        stderr_path=str(stderr_path),
    )

    details = {
        "cmd": cmd,
        "cwd": str(config_dir),
        "timeout_s": timeout_s_f,
        "returncode": returncode,
        "timed_out": timed_out,
        "logs": {
            "csv": str(csv_path) if csv_path.exists() else None,
            "stdout": str(stdout_path),
            "stderr": str(stderr_path),
        },
    }
    return run, details

