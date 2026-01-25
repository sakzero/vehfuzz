from __future__ import annotations

from pathlib import Path

from vehfuzz.core.plugins import create_adapter, list_plugins


def test_pcap_replay_adapter_replays_packets(load_plugins) -> None:
    _ = load_plugins

    assert "pcap_replay" in list_plugins()["adapters"]

    repo_root = Path(__file__).resolve().parents[3]
    sample = repo_root / "samples" / "sample_eth.pcap"
    assert sample.exists()

    adapter = create_adapter(
        "pcap_replay",
        {
            "__config_dir": str(repo_root),
            "path": "samples/sample_eth.pcap",
            "max_packets": 1,
        },
    )

    adapter.open()
    msg = adapter.recv(0.0)
    assert msg is not None
    assert isinstance(msg.meta.get("pcap_global"), dict)
    assert msg.meta["pcap_global"]
    assert adapter.recv(0.0) is None
    adapter.close()
