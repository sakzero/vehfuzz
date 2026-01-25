from __future__ import annotations

from pathlib import Path

import pytest

from vehfuzz.core.artifacts import EventLogger
from vehfuzz.core.orchestrator import ChannelGenerator, ChannelRuntime, ContextStore, Orchestrator, Rule
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

