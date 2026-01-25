from __future__ import annotations

import queue
from pathlib import Path

import pytest

from vehfuzz.core.artifacts import EventLogger
from vehfuzz.core.orchestrator import ChannelGenerator, ChannelRuntime, ContextStore, Orchestrator, Rule, SendCommand
from vehfuzz.core.parsed import ByteRange, ParsedMessage
from vehfuzz.core.plugins import Message
from tests.mocks import MockAdapter, MockOracle, MockProtocol


@pytest.fixture
def logger(tmp_path: Path) -> EventLogger:
    path = tmp_path / "events.jsonl"
    return EventLogger(path)


def test_orchestrator_rule_triggers_send(logger: EventLogger) -> None:
    # Channel A receives a message, triggers a send on channel B.
    a_adapter = MockAdapter()
    b_adapter = MockAdapter()
    a_proto = MockProtocol()
    b_proto = MockProtocol()
    a_oracle = MockOracle()
    b_oracle = MockOracle()

    a_adapter.recv_queue.append(Message(data=b"hello", meta={}))

    seed = Message(data=b"", meta={})
    ch_a = ChannelRuntime(
        channel_id="a",
        adapter=a_adapter,
        protocol=a_proto,
        oracle=a_oracle,
        seeds=[seed],
        protocol_type="mock",
        generator=ChannelGenerator(enabled=False, rx_timeout_s=0.01),
    )
    ch_b = ChannelRuntime(
        channel_id="b",
        adapter=b_adapter,
        protocol=b_proto,
        oracle=b_oracle,
        seeds=[seed],
        protocol_type="mock",
        generator=ChannelGenerator(enabled=False, rx_timeout_s=0.01),
    )

    rule = Rule(
        rule_id="r1",
        when={
            "channel_id": "a",
            "event": "rx",
            "fields": {"len": 5},
        },
        then=[
            {"action": "send", "channel_id": "b", "mutated_hex": "deadbeef"},
            {"action": "set_context", "key": "last_len", "value_from": "parsed.fields.len"},
        ],
    )

    orch = Orchestrator(
        run_id="t1",
        campaign_name="test",
        channels=[ch_a, ch_b],
        rules=[rule],
        events=logger,
        context=ContextStore(),
    )

    summary = orch.run(duration_s=0.2)
    logger.close()

    assert summary["rules"]["matches"] >= 1
    assert summary["context"]["last_len"] == 5
    assert len(b_adapter.sent) >= 1
    assert b_adapter.sent[0].data == bytes.fromhex("deadbeef")


def test_orchestrator_rule_cooldown_suppresses_repeats(logger: EventLogger) -> None:
    a_adapter = MockAdapter()
    b_adapter = MockAdapter()
    a_proto = MockProtocol()
    b_proto = MockProtocol()
    a_oracle = MockOracle()
    b_oracle = MockOracle()

    # Two RX events, but rule has cooldown so only the first should trigger.
    a_adapter.recv_queue.append(Message(data=b"hello", meta={}))
    a_adapter.recv_queue.append(Message(data=b"hello", meta={}))

    seed = Message(data=b"", meta={})
    ch_a = ChannelRuntime(
        channel_id="a",
        adapter=a_adapter,
        protocol=a_proto,
        oracle=a_oracle,
        seeds=[seed],
        protocol_type="mock",
        generator=ChannelGenerator(enabled=False, rx_timeout_s=0.01),
    )
    ch_b = ChannelRuntime(
        channel_id="b",
        adapter=b_adapter,
        protocol=b_proto,
        oracle=b_oracle,
        seeds=[seed],
        protocol_type="mock",
        generator=ChannelGenerator(enabled=False, rx_timeout_s=0.01),
    )

    rule = Rule(
        rule_id="r1",
        when={"channel_id": "a", "event": "rx", "fields": {"len": 5}},
        then=[{"action": "send", "channel_id": "b", "mutated_hex": "aa"}],
        cooldown_s=10.0,
    )

    orch = Orchestrator(
        run_id="t2",
        campaign_name="test",
        channels=[ch_a, ch_b],
        rules=[rule],
        events=logger,
        context=ContextStore(),
    )
    summary = orch.run(duration_s=0.2)
    logger.close()

    assert summary["rules_detail"]["matches"].get("r1", 0) == 1
    assert len(b_adapter.sent) == 1


def test_orchestrator_send_dropped_when_channel_queue_full(logger: EventLogger) -> None:
    a_adapter = MockAdapter()
    b_adapter = MockAdapter()
    a_proto = MockProtocol()
    b_proto = MockProtocol()
    a_oracle = MockOracle()
    b_oracle = MockOracle()

    a_adapter.recv_queue.append(Message(data=b"hello", meta={}))

    seed = Message(data=b"", meta={})
    ch_a = ChannelRuntime(
        channel_id="a",
        adapter=a_adapter,
        protocol=a_proto,
        oracle=a_oracle,
        seeds=[seed],
        protocol_type="mock",
        generator=ChannelGenerator(enabled=False, rx_timeout_s=0.01),
    )

    # Channel B queue pre-filled and the worker stopped, so it stays full.
    q: queue.Queue = queue.Queue()
    q.put(
        SendCommand(
            correlation_id="x",
            origin_rule_id=None,
            mutated=b"\x00",
        )
    )
    ch_b = ChannelRuntime(
        channel_id="b",
        adapter=b_adapter,
        protocol=b_proto,
        oracle=b_oracle,
        seeds=[seed],
        protocol_type="mock",
        generator=ChannelGenerator(enabled=False, rx_timeout_s=0.01),
        queue_maxsize=1,
        cmd_q=q,
    )
    ch_b.stop_evt.set()

    rule = Rule(
        rule_id="r1",
        when={"channel_id": "a", "event": "rx", "fields": {"len": 5}},
        then=[{"action": "send", "channel_id": "b", "mutated_hex": "deadbeef"}],
    )

    orch = Orchestrator(
        run_id="t3",
        campaign_name="test",
        channels=[ch_a, ch_b],
        rules=[rule],
        events=logger,
        context=ContextStore(),
    )
    orch.run(duration_s=0.2)
    logger.close()

    assert len(b_adapter.sent) == 0


def test_orchestrator_path_matcher_supports_list_index(logger: EventLogger) -> None:
    class _ListProtocol(MockProtocol):
        def parse(self, msg: Message) -> ParsedMessage | None:  # type: ignore[override]
            return ParsedMessage(
                protocol="mock",
                level="app",
                ok=True,
                fields={"entries": [{"type_name": "OfferService"}]},
                payload=ByteRange(0, len(msg.data)),
            )

    a_adapter = MockAdapter()
    b_adapter = MockAdapter()
    a_proto = _ListProtocol()
    b_proto = MockProtocol()
    a_oracle = MockOracle()
    b_oracle = MockOracle()

    a_adapter.recv_queue.append(Message(data=b"x", meta={}))

    seed = Message(data=b"", meta={})
    ch_a = ChannelRuntime(
        channel_id="a",
        adapter=a_adapter,
        protocol=a_proto,
        oracle=a_oracle,
        seeds=[seed],
        protocol_type="mock",
        generator=ChannelGenerator(enabled=False, rx_timeout_s=0.01),
    )
    ch_b = ChannelRuntime(
        channel_id="b",
        adapter=b_adapter,
        protocol=b_proto,
        oracle=b_oracle,
        seeds=[seed],
        protocol_type="mock",
        generator=ChannelGenerator(enabled=False, rx_timeout_s=0.01),
    )

    rule = Rule(
        rule_id="r1",
        when={
            "channel_id": "a",
            "event": "rx",
            "match": [{"path": "parsed.fields.entries.0.type_name", "op": "eq", "value": "OfferService"}],
        },
        then=[{"action": "send", "channel_id": "b", "mutated_hex": "aa"}],
    )

    orch = Orchestrator(
        run_id="t4",
        campaign_name="test",
        channels=[ch_a, ch_b],
        rules=[rule],
        events=logger,
        context=ContextStore(),
    )
    summary = orch.run(duration_s=0.2)
    logger.close()

    assert summary["rules_detail"]["matches"].get("r1", 0) == 1
    assert len(b_adapter.sent) == 1
