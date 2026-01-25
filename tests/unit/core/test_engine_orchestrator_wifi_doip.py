from __future__ import annotations

import json
from pathlib import Path

from vehfuzz.core.artifacts import create_run_dirs
from vehfuzz.core.engine import run_campaign


def test_engine_orchestrator_injects_config_dir_for_adapter(monkeypatch, tmp_path: Path, load_plugins) -> None:
    _ = load_plugins

    # Ensure relative paths would resolve incorrectly if engine didn't inject __config_dir.
    monkeypatch.chdir(tmp_path)

    repo_root = Path(__file__).resolve().parents[3]
    paths = create_run_dirs(tmp_path / "run")

    campaign_cfg = {
        "name": "test_orchestrator_wifi_doip",
        "engine": "orchestrator",
        "duration_s": 0.3,
        "channels": [
            {
                "id": "wifi",
                "protocol": "wifi",
                "target": {"adapter": {"type": "pcap_replay", "path": "samples/sample_eth.pcap", "max_packets": 2}},
                "generator": {"type": "none", "rx_timeout_s": 0.01},
            },
            {
                "id": "doip",
                "protocol": "uds",
                "target": {"adapter": {"type": "null"}},
                "seed": {"type": "inline_hex", "values": [""]},
                "generator": {"type": "none", "rx_timeout_s": 0.01},
            },
        ],
        "rules": [
            {
                "id": "wifi_ipv4_triggers_uds_send",
                "when": {
                    "channel_id": "wifi",
                    "event": "rx",
                    "match": [{"path": "parsed.flow_key", "op": "contains", "value": "ipv4:"}],
                },
                "then": [{"action": "send", "channel_id": "doip", "mutated_hex": "02f190"}],
            }
        ],
    }

    stats = run_campaign(
        run_id="t_wifi_doip",
        config_dir=repo_root,
        target_cfg={},
        campaign_cfg=campaign_cfg,
        oracle_cfg={},
        paths=paths,
    )

    assert stats.rx >= 1
    assert stats.tx >= 1

    summary = json.loads((paths.artifacts_dir / "summary.json").read_text(encoding="utf-8"))
    assert summary["rules_detail"]["matches"].get("wifi_ipv4_triggers_uds_send", 0) >= 1
