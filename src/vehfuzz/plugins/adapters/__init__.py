from __future__ import annotations

# Import built-in adapters to register them.
from vehfuzz.plugins.adapters.ethernet.doip import doip_adapter  # noqa: F401
from vehfuzz.plugins.adapters.ethernet.tcp import tcp_adapter  # noqa: F401
from vehfuzz.plugins.adapters.ethernet.udp import udp_adapter  # noqa: F401
from vehfuzz.plugins.adapters.pcap.null import null_adapter  # noqa: F401
from vehfuzz.plugins.adapters.serial.adapter import serial_adapter  # noqa: F401
from vehfuzz.plugins.adapters.socketcan.adapter import socketcan_adapter  # noqa: F401
from vehfuzz.plugins.adapters.socketcan.isotp import isotp_adapter  # noqa: F401
