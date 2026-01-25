from __future__ import annotations

import queue
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal

from vehfuzz.core.artifacts import EventLogger
from vehfuzz.core.mutators import mutate_bytes
from vehfuzz.core.parsed import ParsedMessage
from vehfuzz.core.plugins import Adapter, Message, Oracle, Protocol


EventType = Literal[
    "mutation",
    "tx",
    "rx",
    "error",
    "rule_match",
    "action",
]


def _utc_ts() -> str:
    return datetime.now(timezone.utc).isoformat()


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
    if off >= len(data) or off + ln > len(data):
        return None
    return data[off : off + ln].hex()


def _match_subset(actual: Any, expected: Any) -> bool:
    """
    Recursive "expected is a subset of actual" matcher.

    - dict: all keys in expected must exist in actual and match recursively
    - list/tuple: expected must equal actual (keep it strict for now)
    - scalar: equality
    """
    if isinstance(expected, dict):
        if not isinstance(actual, dict):
            return False
        for k, v in expected.items():
            if k not in actual:
                return False
            if not _match_subset(actual[k], v):
                return False
        return True
    if isinstance(expected, (list, tuple)):
        return actual == expected
    return actual == expected


def _get_path(event: dict[str, Any], path: str) -> Any:
    """
    Safe dot-path lookup.

    Example: "parsed.fields.inner_uds.nrc"
    """
    cur: Any = event
    for part in path.split("."):
        if isinstance(cur, dict):
            if part in cur:
                cur = cur[part]
                continue
            return None
        if isinstance(cur, list):
            if part.isdigit():
                idx = int(part)
                if 0 <= idx < len(cur):
                    cur = cur[idx]
                    continue
            return None
        return None
    return cur


def _match_op(actual: Any, *, op: str, expected: Any | None = None) -> bool:
    op = str(op or "eq").lower().strip()
    if op == "exists":
        return actual is not None
    if op == "not_exists":
        return actual is None
    if op == "eq":
        return actual == expected
    if op == "ne":
        return actual != expected
    if op in ("gt", "gte", "lt", "lte"):
        try:
            a = float(actual)
            b = float(expected)
        except (TypeError, ValueError):
            return False
        if op == "gt":
            return a > b
        if op == "gte":
            return a >= b
        if op == "lt":
            return a < b
        return a <= b
    if op == "contains":
        if actual is None or expected is None:
            return False
        return str(expected) in str(actual)
    if op == "in":
        if expected is None:
            return False
        if isinstance(expected, (list, tuple, set)):
            return actual in expected
        return False
    return False


@dataclass(frozen=True)
class Rule:
    rule_id: str
    when: dict[str, Any]
    then: list[dict[str, Any]]
    cooldown_s: float = 0.0
    max_matches: int | None = None


@dataclass
class ContextStore:
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _data: dict[str, Any] = field(default_factory=dict)

    def get(self, key: str, default: Any = None) -> Any:
        with self._lock:
            return self._data.get(key, default)

    def set(self, key: str, value: Any) -> None:
        with self._lock:
            self._data[key] = value

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return dict(self._data)


@dataclass(frozen=True)
class SendCommand:
    correlation_id: str
    origin_rule_id: str | None
    mutated: bytes
    seed_index: int = 0
    meta_overrides: dict[str, Any] | None = None


@dataclass(frozen=True)
class StopCommand:
    reason: str = "stop"


Command = SendCommand | StopCommand


@dataclass
class ChannelGenerator:
    enabled: bool = False
    cases: int = 0
    interval_s: float = 0.0
    rx_timeout_s: float = 0.1
    mutators: list[dict[str, Any]] = field(default_factory=list)
    rng_seed: int | None = None


@dataclass
class ChannelRuntime:
    channel_id: str
    adapter: Adapter
    protocol: Protocol
    oracle: Oracle
    seeds: list[Message]
    protocol_type: str
    generator: ChannelGenerator = field(default_factory=ChannelGenerator)
    queue_maxsize: int = 1000

    cmd_q: queue.Queue[Command] = field(default_factory=queue.Queue)
    worker: threading.Thread | None = None
    stop_evt: threading.Event = field(default_factory=threading.Event)

    # stats
    cases_done: int = 0
    tx: int = 0
    rx: int = 0
    errors: int = 0
    rule_matches: int = 0
    actions: int = 0


class Orchestrator:
    """
    Multi-channel, event-triggered orchestrator.

    - Each channel runs in its own worker thread (Adapter+Protocol+Oracle are not shared across channels).
    - Workers emit events to a central queue.
    - The orchestrator processes events, evaluates rules, and dispatches actions back to channels.
    """

    def __init__(
        self,
        *,
        run_id: str,
        campaign_name: str,
        channels: list[ChannelRuntime],
        rules: list[Rule],
        events: EventLogger,
        context: ContextStore | None = None,
    ) -> None:
        self._run_id = run_id
        self._campaign_name = campaign_name
        self._channels = {c.channel_id: c for c in channels}
        self._rules = rules
        self._events = events
        self._context = context or ContextStore()

        self._bus: queue.Queue[dict[str, Any]] = queue.Queue()
        self._stop_evt = threading.Event()

        self._rule_last_fire: dict[str, float] = {}
        self._rule_matches: dict[str, int] = {}
        self._rule_suppressed: dict[str, int] = {}

    def _log(self, event: dict[str, Any]) -> None:
        self._events.log(event)

    def _emit(self, event: dict[str, Any]) -> None:
        self._bus.put(event)

    def _evt_base(self, *, channel: ChannelRuntime, event_type: EventType, correlation_id: str | None = None) -> dict[str, Any]:
        return {
            "run_id": self._run_id,
            "campaign": self._campaign_name,
            "ts": _utc_ts(),
            "event": event_type,
            "channel_id": channel.channel_id,
            "protocol": channel.protocol_type,
            "correlation_id": correlation_id,
        }

    def _worker_main(self, channel: ChannelRuntime) -> None:
        rng = None
        if channel.generator.enabled:
            import random

            seed = channel.generator.rng_seed
            if seed is None:
                seed = int(time.time() * 1000) & 0xFFFFFFFF
            rng = random.Random(int(seed))

        try:
            channel.adapter.open()
        except Exception as e:
            channel.errors += 1
            self._log({**self._evt_base(channel=channel, event_type="error"), "stage": "open", "error": str(e)})
            return

        next_send_at = time.time()
        case_id = 0

        try:
            while not channel.stop_evt.is_set() and not self._stop_evt.is_set():
                did_work = False
                # 1) process commands
                try:
                    cmd = channel.cmd_q.get_nowait()
                except queue.Empty:
                    cmd = None

                if isinstance(cmd, StopCommand):
                    break

                if isinstance(cmd, SendCommand):
                    try:
                        seed_msg = channel.seeds[cmd.seed_index % len(channel.seeds)]
                    except Exception:
                        seed_msg = channel.seeds[0] if channel.seeds else Message(data=b"", meta={})

                    meta = dict(getattr(seed_msg, "meta", {}) or {})
                    if cmd.meta_overrides:
                        meta.update(cmd.meta_overrides)
                    seed_for_tx = Message(data=bytes(seed_msg.data), meta=meta)
                    tx_msg = channel.protocol.build_tx(seed_for_tx, cmd.mutated)

                    parsed_tx, parsed_tx_err = _safe_parse(channel.protocol, tx_msg)
                    tx_payload_hex = _payload_hex(tx_msg, parsed_tx)

                    try:
                        channel.adapter.send(tx_msg)
                        channel.tx += 1
                        channel.oracle.on_tx(case_id=case_id, msg=tx_msg)
                        evt = {
                            **self._evt_base(channel=channel, event_type="tx", correlation_id=cmd.correlation_id),
                            "case_id": case_id,
                            "origin_rule_id": cmd.origin_rule_id,
                            "len": len(tx_msg.data),
                            "hex": tx_msg.data.hex(),
                            "meta": tx_msg.meta,
                            "parsed": parsed_tx,
                            "parse_error": parsed_tx_err,
                            "payload_hex": tx_payload_hex,
                        }
                        self._log(evt)
                        self._emit(evt)
                    except Exception as e:
                        channel.errors += 1
                        channel.oracle.on_error(case_id=case_id, error=str(e))
                        evt = {
                            **self._evt_base(channel=channel, event_type="error", correlation_id=cmd.correlation_id),
                            "case_id": case_id,
                            "stage": "send",
                            "error": str(e),
                        }
                        self._log(evt)
                        self._emit(evt)

                    channel.actions += 1
                    did_work = True
                    continue

                # 2) generator send (optional)
                if channel.generator.enabled and rng is not None and channel.generator.cases > 0 and case_id < channel.generator.cases:
                    now = time.time()
                    if now >= next_send_at:
                        if not channel.seeds:
                            channel.errors += 1
                            self._log(
                                {
                                    **self._evt_base(channel=channel, event_type="error"),
                                    "case_id": case_id,
                                    "stage": "seed",
                                    "error": "no_seeds",
                                }
                            )
                        else:
                            seed_msg = channel.seeds[case_id % len(channel.seeds)]
                            mutation = mutate_bytes(seed_msg.data, channel.generator.mutators, rng)
                            tx_msg = channel.protocol.build_tx(seed_msg, mutation.mutated)

                            correlation_id = str(uuid.uuid4())
                            parsed_tx, parsed_tx_err = _safe_parse(channel.protocol, tx_msg)
                            tx_payload_hex = _payload_hex(tx_msg, parsed_tx)

                            self._log(
                                {
                                    **self._evt_base(channel=channel, event_type="mutation", correlation_id=correlation_id),
                                    "case_id": case_id,
                                    "seed_len": len(seed_msg.data),
                                    "mutated_len": len(mutation.mutated),
                                    "seed_hex": seed_msg.data.hex(),
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

                            try:
                                channel.adapter.send(tx_msg)
                                channel.tx += 1
                                channel.oracle.on_tx(case_id=case_id, msg=tx_msg)
                                evt = {
                                    **self._evt_base(channel=channel, event_type="tx", correlation_id=correlation_id),
                                    "case_id": case_id,
                                    "len": len(tx_msg.data),
                                    "hex": tx_msg.data.hex(),
                                    "meta": tx_msg.meta,
                                    "parsed": parsed_tx,
                                    "parse_error": parsed_tx_err,
                                    "payload_hex": tx_payload_hex,
                                }
                                self._log(evt)
                                self._emit(evt)
                            except Exception as e:
                                channel.errors += 1
                                channel.oracle.on_error(case_id=case_id, error=str(e))
                                evt = {
                                    **self._evt_base(channel=channel, event_type="error", correlation_id=correlation_id),
                                    "case_id": case_id,
                                    "stage": "send",
                                    "error": str(e),
                                }
                                self._log(evt)
                                self._emit(evt)

                        channel.cases_done += 1
                        case_id += 1
                        next_send_at = now + max(0.0, float(channel.generator.interval_s))
                        did_work = True

                # 3) recv
                try:
                    resp = channel.adapter.recv(float(channel.generator.rx_timeout_s))
                except Exception as e:
                    channel.errors += 1
                    channel.oracle.on_error(case_id=case_id, error=str(e))
                    self._log({**self._evt_base(channel=channel, event_type="error"), "case_id": case_id, "stage": "recv", "error": str(e)})
                    resp = None

                if resp is None:
                    # Avoid a tight busy loop if adapter.recv() returns immediately.
                    if not did_work:
                        time.sleep(0.001)
                    continue

                channel.rx += 1
                channel.oracle.on_rx(case_id=case_id, msg=resp)
                parsed_rx, parsed_rx_err = _safe_parse(channel.protocol, resp)
                rx_payload_hex = _payload_hex(resp, parsed_rx)
                evt = {
                    **self._evt_base(channel=channel, event_type="rx"),
                    "case_id": case_id,
                    "len": len(resp.data),
                    "hex": resp.data.hex(),
                    "meta": resp.meta,
                    "parsed": parsed_rx,
                    "parse_error": parsed_rx_err,
                    "payload_hex": rx_payload_hex,
                }
                self._log(evt)
                self._emit(evt)

        finally:
            try:
                channel.adapter.close()
            except Exception:
                pass

    def _match_rule(self, rule: Rule, event: dict[str, Any]) -> bool:
        when = rule.when or {}
        # Basic selectors
        if "channel_id" in when and when["channel_id"] != event.get("channel_id"):
            return False
        if "event" in when and when["event"] != event.get("event"):
            return False
        if "protocol" in when and when["protocol"] != event.get("protocol"):
            return False

        # Parsed selectors
        parsed = event.get("parsed")
        if "parsed" in when:
            if not _match_subset(parsed, when["parsed"]):
                return False

        # Convenience: fields subset match under parsed.fields
        if "fields" in when:
            actual_fields = None
            if isinstance(parsed, dict):
                actual_fields = parsed.get("fields")
            if not _match_subset(actual_fields, when["fields"]):
                return False

        # Path-based matchers: list of {path, op, value}
        matchers = when.get("match")
        if matchers is not None:
            if not isinstance(matchers, list):
                return False
            for m in matchers:
                if not isinstance(m, dict):
                    return False
                path = str(m.get("path", "")).strip()
                if not path:
                    return False
                op = str(m.get("op", "eq")).strip()
                expected = m.get("value")
                actual = _get_path(event, path)
                if not _match_op(actual, op=op, expected=expected):
                    return False

        return True

    def _execute_action(self, *, rule: Rule, action: dict[str, Any], trigger_event: dict[str, Any], correlation_id: str) -> None:
        atype = str(action.get("action", "")).lower()
        if atype == "stop":
            self._log(
                {
                    "run_id": self._run_id,
                    "campaign": self._campaign_name,
                    "ts": _utc_ts(),
                    "event": "action",
                    "action": "stop",
                    "correlation_id": correlation_id,
                    "rule_id": rule.rule_id,
                    "reason": str(action.get("reason", "rule_stop")),
                }
            )
            self._stop_evt.set()
            return

        if atype == "set_context":
            key = str(action.get("key", "")).strip()
            if not key:
                return
            if "value_from" in action:
                path = str(action.get("value_from", "")).strip()
                value = _get_path(trigger_event, path) if path else None
            else:
                value = action.get("value")
            self._context.set(key, value)
            self._log(
                {
                    **{
                        "run_id": self._run_id,
                        "campaign": self._campaign_name,
                        "ts": _utc_ts(),
                        "event": "action",
                        "action": "set_context",
                        "correlation_id": correlation_id,
                    },
                    "rule_id": rule.rule_id,
                    "key": key,
                    "value": value,
                }
            )
            return

        if atype == "send":
            channel_id = str(action.get("channel_id", "")).strip()
            if not channel_id or channel_id not in self._channels:
                return
            target = self._channels[channel_id]

            mutated: bytes | None = None
            if "mutated_hex" in action:
                mutated_hex = str(action.get("mutated_hex", "")).strip()
                if mutated_hex:
                    try:
                        mutated = bytes.fromhex(mutated_hex)
                    except ValueError:
                        mutated = None
            elif "mutated_from_event" in action:
                path = str(action.get("mutated_from_event", "")).strip()
                v = _get_path(trigger_event, path) if path else None
                if isinstance(v, str):
                    try:
                        mutated = bytes.fromhex(v)
                    except ValueError:
                        mutated = None
                elif isinstance(v, bytes):
                    mutated = v
            elif "mutated_from_context" in action:
                k = str(action.get("mutated_from_context", "")).strip()
                v = self._context.get(k)
                if isinstance(v, str):
                    try:
                        mutated = bytes.fromhex(v)
                    except ValueError:
                        mutated = None
                elif isinstance(v, bytes):
                    mutated = v
            else:
                mutated = b""

            if mutated is None:
                return

            seed_index = int(action.get("seed_index", 0))
            meta_overrides = action.get("meta_overrides")
            if meta_overrides is not None and not isinstance(meta_overrides, dict):
                meta_overrides = None

            meta = dict(meta_overrides or {})
            meta_from_event = action.get("meta_overrides_from_event")
            if isinstance(meta_from_event, dict):
                for k, path in meta_from_event.items():
                    if not isinstance(k, str) or not isinstance(path, str):
                        continue
                    meta[k] = _get_path(trigger_event, path)
            meta_from_context = action.get("meta_overrides_from_context")
            if isinstance(meta_from_context, dict):
                for k, ctx_key in meta_from_context.items():
                    if not isinstance(k, str) or not isinstance(ctx_key, str):
                        continue
                    meta[k] = self._context.get(ctx_key)
            meta_overrides = meta or None

            try:
                if int(target.queue_maxsize) > 0 and target.cmd_q.qsize() >= int(target.queue_maxsize):
                    raise queue.Full
                target.cmd_q.put_nowait(
                    SendCommand(
                        correlation_id=correlation_id,
                        origin_rule_id=rule.rule_id,
                        mutated=mutated,
                        seed_index=seed_index,
                        meta_overrides=meta_overrides,
                    )
                )
            except queue.Full:
                self._log(
                    {
                        "run_id": self._run_id,
                        "campaign": self._campaign_name,
                        "ts": _utc_ts(),
                        "event": "action",
                        "action": "send",
                        "correlation_id": correlation_id,
                        "rule_id": rule.rule_id,
                        "target_channel_id": channel_id,
                        "mutated_len": len(mutated),
                        "mutated_hex": mutated.hex(),
                        "dropped": True,
                        "drop_reason": "channel_queue_full",
                    }
                )
                return
            self._log(
                {
                    "run_id": self._run_id,
                    "campaign": self._campaign_name,
                    "ts": _utc_ts(),
                    "event": "action",
                    "action": "send",
                    "correlation_id": correlation_id,
                    "rule_id": rule.rule_id,
                    "target_channel_id": channel_id,
                    "mutated_len": len(mutated),
                    "mutated_hex": mutated.hex(),
                }
            )
            return

    def run(self, *, duration_s: float) -> dict[str, Any]:
        start = time.time()
        # Start workers
        for c in self._channels.values():
            t = threading.Thread(target=self._worker_main, args=(c,), name=f"vehfuzz-worker-{c.channel_id}", daemon=True)
            c.worker = t
            t.start()

        triggers = 0
        try:
            while time.time() - start < max(0.0, float(duration_s)) and not self._stop_evt.is_set():
                try:
                    evt = self._bus.get(timeout=0.05)
                except queue.Empty:
                    continue

                for rule in self._rules:
                    if not self._match_rule(rule, evt):
                        continue

                    now = time.time()
                    last = self._rule_last_fire.get(rule.rule_id)
                    if last is not None and rule.cooldown_s and (now - last) < float(rule.cooldown_s):
                        self._rule_suppressed[rule.rule_id] = self._rule_suppressed.get(rule.rule_id, 0) + 1
                        continue
                    count = self._rule_matches.get(rule.rule_id, 0)
                    if rule.max_matches is not None and count >= int(rule.max_matches):
                        self._rule_suppressed[rule.rule_id] = self._rule_suppressed.get(rule.rule_id, 0) + 1
                        continue

                    triggers += 1
                    correlation_id = str(uuid.uuid4())
                    self._rule_last_fire[rule.rule_id] = now
                    self._rule_matches[rule.rule_id] = count + 1
                    # Log match
                    self._log(
                        {
                            "run_id": self._run_id,
                            "campaign": self._campaign_name,
                            "ts": _utc_ts(),
                            "event": "rule_match",
                            "rule_id": rule.rule_id,
                            "correlation_id": correlation_id,
                            "trigger_event": {
                                "channel_id": evt.get("channel_id"),
                                "event": evt.get("event"),
                                "protocol": evt.get("protocol"),
                                "flow_key": (evt.get("parsed") or {}).get("flow_key") if isinstance(evt.get("parsed"), dict) else None,
                            },
                        }
                    )
                    # Actions
                    for action in rule.then:
                        self._execute_action(rule=rule, action=action, trigger_event=evt, correlation_id=correlation_id)

        finally:
            self._stop_evt.set()
            for c in self._channels.values():
                c.stop_evt.set()
                try:
                    c.cmd_q.put_nowait(StopCommand())
                except queue.Full:
                    pass
            for c in self._channels.values():
                if c.worker is not None:
                    c.worker.join(timeout=2.0)

        # Collect per-channel oracle summaries
        channels_summary: dict[str, Any] = {}
        total_tx = total_rx = total_errors = total_cases = 0
        for cid, c in self._channels.items():
            summary = {}
            try:
                summary = c.oracle.finalize() or {}
            except Exception as e:
                summary = {"error": str(e)}
            channels_summary[cid] = {
                "protocol": c.protocol_type,
                "cases_done": c.cases_done,
                "tx": c.tx,
                "rx": c.rx,
                "errors": c.errors,
                "oracle": summary,
            }
            total_tx += c.tx
            total_rx += c.rx
            total_errors += c.errors
            total_cases += c.cases_done

        return {
            "run_id": self._run_id,
            "campaign": self._campaign_name,
            "engine": "orchestrator",
            "duration_s": max(0.0, time.time() - start),
            "rules": {"count": len(self._rules), "matches": triggers},
            "rules_detail": {
                "matches": dict(self._rule_matches),
                "suppressed": dict(self._rule_suppressed),
            },
            "channels": channels_summary,
            "context": self._context.snapshot(),
            "stats": {
                "cases": total_cases,
                "tx": total_tx,
                "rx": total_rx,
                "errors": total_errors,
            },
        }
