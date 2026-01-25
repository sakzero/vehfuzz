"""
Configuration schemas for adapters and protocols.

This module provides TypedDict schemas for configuration validation.
Using these schemas helps catch configuration errors early and provides
better IDE support.
"""

from __future__ import annotations

from typing import Any, TypedDict, Required, NotRequired


# ==================== Adapter Schemas ====================

class TcpAdapterConfig(TypedDict, total=False):
    """Configuration schema for TCP adapter."""
    host: str  # Default: "127.0.0.1"
    port: Required[int]  # Required, must be > 0
    connect_timeout_s: float  # Default: 5.0
    recv_buf: int  # Default: 65535


class UdpAdapterConfig(TypedDict, total=False):
    """Configuration schema for UDP adapter."""
    host: str  # Default: "127.0.0.1"
    port: Required[int]  # Required
    bind_port: int  # Local port to bind for receiving
    recv_buf: int  # Default: 65535


class SocketCanAdapterConfig(TypedDict, total=False):
    """Configuration schema for SocketCAN adapter."""
    channel: Required[str]  # e.g., "vcan0", "can0"
    is_fd: bool  # Default: False
    bitrate: int  # For real CAN interfaces
    data_bitrate: int  # For CAN FD


class SerialAdapterConfig(TypedDict, total=False):
    """Configuration schema for Serial adapter."""
    port: Required[str]  # e.g., "COM1", "/dev/ttyUSB0"
    baudrate: int  # Default: 115200
    bytesize: int  # Default: 8
    parity: str  # Default: "N"
    stopbits: float  # Default: 1
    timeout: float  # Read timeout


class DoipAdapterConfig(TypedDict, total=False):
    """Configuration schema for DoIP adapter."""
    host: str  # Target ECU IP
    port: int  # Default: 13400
    source_address: int  # Tester logical address
    target_address: int  # ECU logical address
    activation_type: int  # Default: 0x00


class NullAdapterConfig(TypedDict, total=False):
    """Configuration schema for Null/PCAP adapter (offline mode)."""
    pass  # No configuration needed


# ==================== Protocol Schemas ====================

class RawProtocolConfig(TypedDict, total=False):
    """Configuration schema for Raw protocol."""
    max_len: int  # Maximum message length


class CanProtocolConfig(TypedDict, total=False):
    """Configuration schema for CAN protocol."""
    can_id: int  # Default CAN ID for TX
    is_extended: bool  # Use extended (29-bit) IDs
    is_fd: bool  # CAN FD mode
    bitrate_switch: bool  # BRS flag for CAN FD
    max_len: int  # Max payload length
    pad_to_len: int  # Pad frames to this length
    pad_byte: int  # Padding byte value (default: 0x00)
    parse_isotp: bool  # Parse ISO-TP frames (default: True)


class UdsProtocolConfig(TypedDict, total=False):
    """Configuration schema for UDS protocol."""
    max_len: int  # Maximum UDS message length


class DoipProtocolConfig(TypedDict, total=False):
    """Configuration schema for DoIP protocol."""
    version: int  # DoIP version (default: 0x02)
    inverse_version: int  # Inverse version byte
    payload_type: int  # Default: 0x8001 (diagnostic message)


class SomeipProtocolConfig(TypedDict, total=False):
    """Configuration schema for SOME/IP protocol."""
    service_id: Required[int]
    method_id: Required[int]
    client_id: int  # Default: 0x0001
    session_id: int  # Default: 0x0001
    protocol_version: int  # Default: 0x01
    interface_version: int  # Default: 0x01
    message_type: int  # Default: 0x00 (request)
    return_code: int  # Default: 0x00


class J1939ProtocolConfig(TypedDict, total=False):
    """Configuration schema for J1939 protocol."""
    source_address: int  # SA for TX messages
    priority: int  # Default: 6


class NmeaProtocolConfig(TypedDict, total=False):
    """Configuration schema for NMEA protocol."""
    max_body_len: int  # Max NMEA sentence body length
    scenario: dict[str, Any]  # Simulation scenario config


class WifiProtocolConfig(TypedDict, total=False):
    """Configuration schema for WiFi protocol."""
    decrypt: dict[str, str]  # Decryption config (ccmp_tk_hex, etc.)


class BluetoothProtocolConfig(TypedDict, total=False):
    """Configuration schema for Bluetooth protocol."""
    pass  # No specific config yet


# ==================== Oracle Schemas ====================

class BasicOracleConfig(TypedDict, total=False):
    """Configuration schema for Basic oracle."""
    pass  # No configuration needed


# ==================== Orchestrator Schemas ====================

class OrchestratorChannelConfig(TypedDict, total=False):
    """Configuration schema for one orchestrator channel."""
    id: Required[str]
    protocol: str
    protocol_config: dict[str, Any]
    target: dict[str, Any]  # target.adapter = {...}
    oracle: dict[str, Any]  # oracle.type / oracle.config
    seed: dict[str, Any]
    generator: dict[str, Any]  # generator.type=fuzz etc


class OrchestratorRuleConfig(TypedDict, total=False):
    """Configuration schema for one orchestrator rule."""
    id: Required[str]
    when: dict[str, Any]
    then: list[dict[str, Any]]
    cooldown_s: float
    max_matches: int


class OrchestratorCampaignConfig(TypedDict, total=False):
    """Configuration schema for orchestrator campaign."""
    engine: Required[str]  # must be "orchestrator"
    duration_s: float
    channels: Required[list[OrchestratorChannelConfig]]
    rules: list[OrchestratorRuleConfig]


# ==================== Schema Registry ====================

ADAPTER_SCHEMAS: dict[str, type[TypedDict]] = {
    "tcp": TcpAdapterConfig,
    "udp": UdpAdapterConfig,
    "socketcan": SocketCanAdapterConfig,
    "serial": SerialAdapterConfig,
    "doip": DoipAdapterConfig,
    "null": NullAdapterConfig,
}

PROTOCOL_SCHEMAS: dict[str, type[TypedDict]] = {
    "raw": RawProtocolConfig,
    "can": CanProtocolConfig,
    "uds": UdsProtocolConfig,
    "doip": DoipProtocolConfig,
    "someip": SomeipProtocolConfig,
    "j1939": J1939ProtocolConfig,
    "nmea": NmeaProtocolConfig,
    "wifi": WifiProtocolConfig,
    "bluetooth": BluetoothProtocolConfig,
}

ORACLE_SCHEMAS: dict[str, type[TypedDict]] = {
    "basic": BasicOracleConfig,
}


def get_adapter_schema(adapter_type: str) -> type[TypedDict] | None:
    """Get the configuration schema for an adapter type."""
    return ADAPTER_SCHEMAS.get(adapter_type)


def get_protocol_schema(protocol_type: str) -> type[TypedDict] | None:
    """Get the configuration schema for a protocol type."""
    return PROTOCOL_SCHEMAS.get(protocol_type)


def get_oracle_schema(oracle_type: str) -> type[TypedDict] | None:
    """Get the configuration schema for an oracle type."""
    return ORACLE_SCHEMAS.get(oracle_type)
