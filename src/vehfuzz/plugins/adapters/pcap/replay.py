from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from vehfuzz.core.corpus import load_seed_messages
from vehfuzz.core.plugins import Adapter, Message, register_adapter


class _PcapReplayAdapter(Adapter):
    """
    Replay packets from a pcap/pcapng file as incoming messages.

    This adapter is intended for event-triggered orchestrator scenarios where a channel
    "listens" to traffic and triggers actions on other channels.

    Config:
      - path: required, path to .pcap or .pcapng
      - loop: bool, default False (restart when EOF)
      - delay_s: float, default 0.0 (sleep after each emitted packet)
      - max_packets: int | None (stop emitting after N packets)

    Note:
      - send() is a no-op (records nothing) but still requires open().
      - recv() returns the next packet immediately; timeout_s is accepted for compatibility.
    """

    def __init__(self, config: dict[str, Any]) -> None:
        self._cfg = config
        self._open = False
        self._packets: list[Message] = []
        self._idx = 0
        self._emitted = 0

    def open(self) -> None:
        if self._open:
            return
        path_raw = self._cfg.get("path")
        if not isinstance(path_raw, str) or not path_raw:
            raise ValueError("pcap_replay adapter requires adapter.path")
        p = Path(path_raw)
        cfg_dir = self._cfg.get("__config_dir")
        if cfg_dir and isinstance(cfg_dir, str) and not p.is_absolute():
            p = (Path(cfg_dir) / p).resolve()
        else:
            p = p.resolve()
        if not p.exists():
            raise FileNotFoundError(str(p))

        # Use core seed loader for pcap/pcapng so meta includes pcap_global/linktype.
        suffix = p.suffix.lower()
        seed_type = "pcapng" if suffix == ".pcapng" else "pcap"
        self._packets = load_seed_messages(p.parent, {"type": seed_type, "path": str(p)})
        self._idx = 0
        self._emitted = 0
        self._open = True

    def close(self) -> None:
        self._open = False
        self._packets = []
        self._idx = 0
        self._emitted = 0

    def send(self, msg: Message) -> None:
        if not self._open:
            raise RuntimeError("pcap_replay adapter not open")
        # No-op: replay adapter is receive-focused.
        _ = msg

    def recv(self, timeout_s: float) -> Message | None:
        if not self._open:
            raise RuntimeError("pcap_replay adapter not open")

        max_packets = self._cfg.get("max_packets")
        if max_packets is not None:
            try:
                if self._emitted >= int(max_packets):
                    return None
            except Exception:
                pass

        if self._idx >= len(self._packets):
            if bool(self._cfg.get("loop", False)) and self._packets:
                self._idx = 0
            else:
                return None

        msg = self._packets[self._idx]
        self._idx += 1
        self._emitted += 1

        delay_s = float(self._cfg.get("delay_s", 0.0))
        if delay_s > 0:
            # Best-effort pacing; ignore timeout_s and let orchestrator manage its own loop.
            time.sleep(delay_s)

        _ = timeout_s
        return msg


@register_adapter("pcap_replay")
def pcap_replay_adapter(config: dict[str, Any]) -> Adapter:
    return _PcapReplayAdapter(config)

