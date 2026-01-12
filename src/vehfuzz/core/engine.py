from __future__ import annotations

import json
import random
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from vehfuzz.core.artifacts import ArtifactPaths, EventLogger
from vehfuzz.core.boofuzz_runner import run_boofuzz_campaign
from vehfuzz.core.corpus import load_seed_messages
from vehfuzz.core.offline import create_offline_sink
from vehfuzz.core.mutators import mutate_bytes
from vehfuzz.core.plugins import Message, create_adapter, create_oracle, create_protocol, load_builtin_plugins


@dataclass(frozen=True)
class RunStats:
    cases: int
    tx: int
    rx: int
    errors: int
    anomalies: int
    duration_s: float
    offline_artifact: str | None = None


def run_campaign(
    *,
    run_id: str,
    config_dir: Path,
    target_cfg: dict[str, Any],
    campaign_cfg: dict[str, Any],
    oracle_cfg: dict[str, Any],
    paths: ArtifactPaths,
) -> RunStats:
    load_builtin_plugins()

    campaign_name = str(campaign_cfg.get("name", "campaign"))
    engine_type = str(campaign_cfg.get("engine", "vehfuzz")).lower()
    mode = str(campaign_cfg.get("mode", "offline")).lower()
    protocol_type = str(campaign_cfg.get("protocol", "raw")).lower()

    if engine_type not in ("vehfuzz", "boofuzz"):
        raise ValueError(f"Unsupported campaign.engine: {engine_type}")

    if engine_type == "boofuzz":
        events = EventLogger(paths.events_path)
        try:
            boofuzz_run, boofuzz_details = run_boofuzz_campaign(
                run_id=run_id,
                config_dir=config_dir,
                target_cfg=target_cfg,
                campaign_cfg=campaign_cfg,
                oracle_cfg=oracle_cfg,
                paths=paths,
                events=events,
            )
        finally:
            events.close()

        anomalies = int(boofuzz_run.fails + boofuzz_run.errors)
        if boofuzz_run.timed_out:
            anomalies += 1
        if boofuzz_run.returncode not in (None, 0):
            anomalies += 1

        report = {
            "run_id": run_id,
            "campaign": campaign_name,
            "engine": engine_type,
            "mode": mode,
            "protocol": protocol_type,
            "stats": {
                "cases": boofuzz_run.cases,
                "tx": boofuzz_run.tx,
                "rx": boofuzz_run.rx,
                "errors": boofuzz_run.errors,
                "anomalies": anomalies,
                "duration_s": boofuzz_run.duration_s,
            },
            "boofuzz": boofuzz_details,
        }
        (paths.artifacts_dir / "summary.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

        return RunStats(
            cases=boofuzz_run.cases,
            tx=boofuzz_run.tx,
            rx=boofuzz_run.rx,
            errors=boofuzz_run.errors,
            anomalies=anomalies,
            duration_s=boofuzz_run.duration_s,
            offline_artifact=None,
        )

    seed_cfg = campaign_cfg.get("seed", {})
    if not isinstance(seed_cfg, dict):
        raise ValueError("campaign.seed must be a mapping")
    seed_type = str(seed_cfg.get("type", "hex")).lower()

    mutators_cfg = campaign_cfg.get("mutators", [])
    if not isinstance(mutators_cfg, list):
        raise ValueError("campaign.mutators must be a list")

    cases = int(campaign_cfg.get("cases", 100))
    if cases <= 0:
        raise ValueError("campaign.cases must be > 0")

    rng_seed = campaign_cfg.get("rng_seed")
    if rng_seed is None:
        rng_seed = int(time.time() * 1000) & 0xFFFFFFFF
    rng = random.Random(int(rng_seed))

    seeds = load_seed_messages(config_dir, seed_cfg)
    protocol_cfg = campaign_cfg.get("protocol_config", {}) or {}
    if not isinstance(protocol_cfg, dict):
        raise ValueError("campaign.protocol_config must be a mapping")
    protocol_cfg = dict(protocol_cfg)
    protocol_cfg.setdefault("__config_dir", str(config_dir))
    protocol = create_protocol(protocol_type, protocol_cfg)

    oracle_type = str(oracle_cfg.get("type", "basic")).lower() if oracle_cfg else "basic"
    oracle = create_oracle(oracle_type, oracle_cfg.get("config", {}) if oracle_cfg else {})

    events = EventLogger(paths.events_path)
    start = time.time()
    tx = rx = errors = anomalies = 0
    offline_sink = None
    offline_artifact_name = None

    adapter = None
    if mode != "offline":
        adapter_cfg = target_cfg.get("adapter", {})
        if not isinstance(adapter_cfg, dict):
            raise ValueError("target.adapter must be a mapping")
        adapter_type = str(adapter_cfg.get("type", "null")).lower()
        adapter = create_adapter(adapter_type, adapter_cfg)
        adapter.open()
    else:
        offline_sink, offline_artifact_name = create_offline_sink(
            seed_type, artifacts_dir=paths.artifacts_dir, seeds=seeds
        )

    try:
        for case_id in range(cases):
            seed = seeds[case_id % len(seeds)]
            mutation = mutate_bytes(seed.data, mutators_cfg, rng)
            tx_msg = protocol.build_tx(seed, mutation.mutated)

            evt_base = {
                "run_id": run_id,
                "campaign": campaign_name,
                "case_id": case_id,
                "ts": datetime.now(timezone.utc).isoformat(),
                "protocol": protocol_type,
            }
            events.log(
                {
                    **evt_base,
                    "event": "mutation",
                    "seed_len": len(seed.data),
                    "mutated_len": len(mutation.mutated),
                    "seed_hex": seed.data.hex(),
                    "mutated_hex": mutation.mutated.hex(),
                    "ops": mutation.ops,
                }
            )

            if adapter is None:
                assert offline_sink is not None
                offline_sink.emit(tx_msg)
                continue

            try:
                adapter.send(tx_msg)
                tx += 1
                oracle.on_tx(case_id=case_id, msg=tx_msg)
                events.log({**evt_base, "event": "tx", "len": len(tx_msg.data), "hex": tx_msg.data.hex(), "meta": tx_msg.meta})
            except Exception as e:
                errors += 1
                oracle.on_error(case_id=case_id, error=str(e))
                events.log({**evt_base, "event": "error", "stage": "send", "error": str(e)})
                continue

            rx_timeout_s = float(campaign_cfg.get("rx_timeout_s", 0.2))
            resp = None
            if rx_timeout_s > 0:
                try:
                    resp = adapter.recv(rx_timeout_s)
                except Exception as e:
                    errors += 1
                    oracle.on_error(case_id=case_id, error=str(e))
                    events.log({**evt_base, "event": "error", "stage": "recv", "error": str(e)})
                    continue
            if resp is not None:
                rx += 1
                oracle.on_rx(case_id=case_id, msg=resp)
                events.log({**evt_base, "event": "rx", "len": len(resp.data), "hex": resp.data.hex(), "meta": resp.meta})
            else:
                if bool(campaign_cfg.get("require_rx", False)) and rx_timeout_s > 0:
                    oracle.on_error(case_id=case_id, error="rx_timeout")
                    events.log({**evt_base, "event": "rx_timeout", "timeout_s": rx_timeout_s})

            interval_s = float(campaign_cfg.get("interval_s", 0.0))
            if interval_s > 0:
                time.sleep(interval_s)

    finally:
        if adapter is not None:
            adapter.close()
        if offline_sink is not None:
            offline_sink.close()
        events.close()

    oracle_summary = oracle.finalize() or {}
    anomalies = int(oracle_summary.get("anomalies", 0))
    duration_s = max(0.0, time.time() - start)

    report = {
        "run_id": run_id,
        "campaign": campaign_name,
        "engine": engine_type,
        "mode": mode,
        "protocol": protocol_type,
        "rng_seed": rng_seed,
        "seed_type": seed_type,
        "offline_artifact": offline_artifact_name,
        "stats": {"cases": cases, "tx": tx, "rx": rx, "errors": errors, "anomalies": anomalies, "duration_s": duration_s},
        "oracle": oracle_summary,
    }
    (paths.artifacts_dir / "summary.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    return RunStats(
        cases=cases,
        tx=tx,
        rx=rx,
        errors=errors,
        anomalies=anomalies,
        duration_s=duration_s,
        offline_artifact=offline_artifact_name,
    )
