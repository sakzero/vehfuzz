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
from vehfuzz.core.orchestrator import ChannelGenerator, ChannelRuntime, ContextStore, Orchestrator, Rule
from vehfuzz.core.parsed import ParsedMessage
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


def _safe_parse(protocol: Any, msg: Message) -> tuple[dict[str, Any] | None, str | None]:
    try:
        parsed = getattr(protocol, "parse", None)
        if parsed is None:
            return None, None
        out = parsed(msg)
        if out is None:
            return None, None
        if isinstance(out, ParsedMessage):
            return out.to_dict(), None
        if isinstance(out, dict):
            return out, None
        return {"protocol": "unknown", "ok": False, "reason": f"invalid_parse_return:{type(out).__name__}"}, None
    except Exception as e:
        return None, str(e)


def _payload_hex(msg: Message, parsed: dict[str, Any] | None) -> str | None:
    if not parsed:
        return None
    payload = parsed.get("payload")
    if not isinstance(payload, dict):
        return None
    try:
        off = int(payload.get("offset", 0))
        ln = int(payload.get("length", 0))
    except (TypeError, ValueError):
        return None
    if off < 0 or ln <= 0:
        return None
    data = bytes(msg.data)
    # Bounds check: ensure offset and length are within data
    if off >= len(data) or off + ln > len(data):
        return None
    return data[off : off + ln].hex()


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

    if engine_type not in ("vehfuzz", "boofuzz", "orchestrator"):
        raise ValueError(f"Unsupported campaign.engine: {engine_type}")

    if engine_type == "orchestrator":
        # Multi-channel orchestrator: channels define their own target/protocol/oracle/seed.
        events = EventLogger(paths.events_path)
        start = time.time()
        try:
            duration_s = float(campaign_cfg.get("duration_s", 30.0))
            channels_cfg = campaign_cfg.get("channels", [])
            if not isinstance(channels_cfg, list) or not channels_cfg:
                raise ValueError("orchestrator requires campaign.channels as a non-empty list")

            rules_cfg = campaign_cfg.get("rules", [])
            if rules_cfg is None:
                rules_cfg = []
            if not isinstance(rules_cfg, list):
                raise ValueError("orchestrator requires campaign.rules as a list")

            channels: list[ChannelRuntime] = []
            for ch in channels_cfg:
                if not isinstance(ch, dict):
                    raise ValueError("orchestrator channel must be a mapping")
                channel_id = str(ch.get("id") or ch.get("channel_id") or "").strip()
                if not channel_id:
                    raise ValueError("orchestrator channel requires id")

                # Protocol
                proto_type = str(ch.get("protocol", "raw")).lower()
                proto_cfg = ch.get("protocol_config", {}) or {}
                if not isinstance(proto_cfg, dict):
                    raise ValueError(f"channel {channel_id}: protocol_config must be a mapping")
                proto_cfg = dict(proto_cfg)
                proto_cfg.setdefault("__config_dir", str(config_dir))
                protocol = create_protocol(proto_type, proto_cfg)

                # Adapter
                target = ch.get("target", {}) or {}
                if not isinstance(target, dict):
                    raise ValueError(f"channel {channel_id}: target must be a mapping")
                adapter_cfg = target.get("adapter", {}) or {}
                if not isinstance(adapter_cfg, dict):
                    raise ValueError(f"channel {channel_id}: target.adapter must be a mapping")
                adapter_cfg = dict(adapter_cfg)
                adapter_cfg.setdefault("__config_dir", str(config_dir))
                adapter_type = str(adapter_cfg.get("type", "null")).lower()
                adapter = create_adapter(adapter_type, adapter_cfg)

                # Oracle
                oracle_obj: Any = ch.get("oracle")
                if oracle_obj is None:
                    oracle_type = "basic"
                    oracle_config: dict[str, Any] = {}
                else:
                    if not isinstance(oracle_obj, dict):
                        raise ValueError(f"channel {channel_id}: oracle must be a mapping")
                    oracle_type = str(oracle_obj.get("type", "basic")).lower()
                    oracle_config = oracle_obj.get("config", {}) or {}
                    if not isinstance(oracle_config, dict):
                        raise ValueError(f"channel {channel_id}: oracle.config must be a mapping")
                oracle_inst = create_oracle(oracle_type, oracle_config)

                # Seeds
                seed_cfg = ch.get("seed", {}) or {}
                if not isinstance(seed_cfg, dict):
                    raise ValueError(f"channel {channel_id}: seed must be a mapping")
                seeds = load_seed_messages(config_dir, seed_cfg) if seed_cfg else []
                if not seeds:
                    # Allow empty seeds for purely passive receive channels.
                    seeds = [Message(data=b"", meta={})]

                # Generator
                gen_cfg = ch.get("generator", {}) or {}
                if not isinstance(gen_cfg, dict):
                    raise ValueError(f"channel {channel_id}: generator must be a mapping")
                gen_type = str(gen_cfg.get("type", "none")).lower()
                enabled = gen_type == "fuzz"
                generator = ChannelGenerator(
                    enabled=enabled,
                    cases=int(gen_cfg.get("cases", 0)) if enabled else 0,
                    interval_s=float(gen_cfg.get("interval_s", 0.0)),
                    rx_timeout_s=float(gen_cfg.get("rx_timeout_s", 0.05)),
                    mutators=gen_cfg.get("mutators", ch.get("mutators", []) or []) if enabled else [],
                    rng_seed=gen_cfg.get("rng_seed"),
                )
                if enabled and not isinstance(generator.mutators, list):
                    raise ValueError(f"channel {channel_id}: generator.mutators must be a list")

                queue_maxsize = int(ch.get("queue_maxsize", 1000))
                if queue_maxsize <= 0:
                    queue_maxsize = 1000

                import queue as _queue

                channels.append(
                    ChannelRuntime(
                        channel_id=channel_id,
                        adapter=adapter,
                        protocol=protocol,
                        oracle=oracle_inst,
                        seeds=seeds,
                        protocol_type=proto_type,
                        generator=generator,
                        queue_maxsize=queue_maxsize,
                        cmd_q=_queue.Queue(maxsize=queue_maxsize),
                    )
                )

            rules: list[Rule] = []
            for r in rules_cfg:
                if not isinstance(r, dict):
                    raise ValueError("rule must be a mapping")
                rid = str(r.get("id") or r.get("rule_id") or "").strip()
                if not rid:
                    raise ValueError("rule requires id")
                when = r.get("when", {}) or {}
                then = r.get("then", []) or []
                cooldown_s = float(r.get("cooldown_s", 0.0))
                max_matches = r.get("max_matches")
                max_matches_i: int | None = None
                if max_matches is not None:
                    try:
                        max_matches_i = int(max_matches)
                    except Exception:
                        max_matches_i = None
                if not isinstance(when, dict):
                    raise ValueError(f"rule {rid}: when must be a mapping")
                if not isinstance(then, list):
                    raise ValueError(f"rule {rid}: then must be a list")
                rules.append(
                    Rule(
                        rule_id=rid,
                        when=when,
                        then=[t for t in then if isinstance(t, dict)],
                        cooldown_s=max(0.0, cooldown_s),
                        max_matches=(max_matches_i if max_matches_i is None or max_matches_i >= 0 else None),
                    )
                )

            orch = Orchestrator(
                run_id=run_id,
                campaign_name=campaign_name,
                channels=channels,
                rules=rules,
                events=events,
                context=ContextStore(),
            )
            summary = orch.run(duration_s=duration_s)
        finally:
            events.close()

        (paths.artifacts_dir / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
        duration = max(0.0, time.time() - start)
        stats = summary.get("stats", {}) if isinstance(summary, dict) else {}
        return RunStats(
            cases=int(stats.get("cases", 0)) if isinstance(stats, dict) else 0,
            tx=int(stats.get("tx", 0)) if isinstance(stats, dict) else 0,
            rx=int(stats.get("rx", 0)) if isinstance(stats, dict) else 0,
            errors=int(stats.get("errors", 0)) if isinstance(stats, dict) else 0,
            anomalies=0,
            duration_s=duration,
            offline_artifact=None,
        )

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
    if not seeds:
        raise ValueError("No seed messages loaded; check campaign.seed configuration")
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

            parsed_tx, parsed_tx_err = _safe_parse(protocol, tx_msg)
            tx_payload_hex = _payload_hex(tx_msg, parsed_tx)
            events.log(
                {
                    **evt_base,
                    "event": "mutation",
                    "seed_len": len(seed.data),
                    "mutated_len": len(mutation.mutated),
                    "seed_hex": seed.data.hex(),
                    "mutated_hex": mutation.mutated.hex(),
                    "ops": mutation.ops,
                    "tx_len": len(tx_msg.data),
                    "tx_hex": tx_msg.data.hex(),
                    "tx_meta": tx_msg.meta,
                    "tx_parsed": parsed_tx,
                    "tx_parse_error": parsed_tx_err,
                    "tx_payload_hex": tx_payload_hex,
                }
            )

            if adapter is None:
                assert offline_sink is not None
                offline_sink.emit(tx_msg)
                events.log(
                    {
                        **evt_base,
                        "event": "tx_offline",
                        "len": len(tx_msg.data),
                        "hex": tx_msg.data.hex(),
                        "meta": tx_msg.meta,
                        "parsed": parsed_tx,
                        "payload_hex": tx_payload_hex,
                    }
                )
                continue

            try:
                adapter.send(tx_msg)
                tx += 1
                oracle.on_tx(case_id=case_id, msg=tx_msg)
                events.log(
                    {
                        **evt_base,
                        "event": "tx",
                        "len": len(tx_msg.data),
                        "hex": tx_msg.data.hex(),
                        "meta": tx_msg.meta,
                        "parsed": parsed_tx,
                        "payload_hex": tx_payload_hex,
                    }
                )
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
                parsed_rx, parsed_rx_err = _safe_parse(protocol, resp)
                rx_payload_hex = _payload_hex(resp, parsed_rx)
                events.log(
                    {
                        **evt_base,
                        "event": "rx",
                        "len": len(resp.data),
                        "hex": resp.data.hex(),
                        "meta": resp.meta,
                        "parsed": parsed_rx,
                        "parse_error": parsed_rx_err,
                        "payload_hex": rx_payload_hex,
                    }
                )
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
