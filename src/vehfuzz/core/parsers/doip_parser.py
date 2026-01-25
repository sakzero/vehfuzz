"""
DoIP (Diagnostics over IP) header parser.

This is a pure parsing function with no dependencies on protocol plugins.
"""

from __future__ import annotations

import struct
from typing import Any


# Valid DoIP protocol versions
DOIP_VALID_VERSIONS = {0x01, 0x02, 0x03}  # ISO 13400-2:2012, 2019, etc.

DOIP_PAYLOAD_TYPE_NAMES: dict[int, str] = {
    0x0000: "generic_negative_ack",
    0x0001: "vehicle_identification_request",
    0x0002: "vehicle_identification_response",
    0x0003: "vehicle_identification_request_eid",
    0x0004: "vehicle_identification_request_vin",
    0x0005: "routing_activation_request",
    0x0006: "routing_activation_response",
    0x0007: "alive_check_request",
    0x0008: "alive_check_response",
    0x4001: "entity_status_request",
    0x4002: "entity_status_response",
    0x4003: "power_mode_request",
    0x4004: "power_mode_response",
    0x8001: "diagnostic_message",
    0x8002: "diagnostic_message_positive_ack",
    0x8003: "diagnostic_message_negative_ack",
}

# Routing Activation Response codes
DOIP_ROUTING_ACTIVATION_RESPONSE: dict[int, str] = {
    0x00: "routing_successfully_activated",
    0x01: "routing_will_be_activated_confirmation_required",
    0x02: "routing_will_be_activated_oem_specific",
    0x10: "denied_unknown_source_address",
    0x11: "denied_all_sockets_registered",
    0x12: "denied_source_address_mismatch",
    0x13: "denied_source_address_already_activated",
    0x14: "denied_missing_authentication",
    0x15: "denied_rejected_confirmation",
    0x16: "denied_unsupported_activation_type",
}

# Diagnostic Message Negative Ack codes
DOIP_DIAG_NACK: dict[int, str] = {
    0x02: "invalid_source_address",
    0x03: "unknown_target_address",
    0x04: "diagnostic_message_too_large",
    0x05: "out_of_memory",
    0x06: "target_unreachable",
    0x07: "unknown_network",
    0x08: "transport_protocol_error",
}


def parse_doip_header(data: bytes) -> tuple[dict[str, Any], int | None]:
    """
    Parse a DoIP header and extract fields.

    Args:
        data: Raw DoIP packet bytes

    Returns:
        Tuple of (fields_dict, payload_offset).
        payload_offset is None if parsing failed.
    """
    if len(data) < 8:
        return {"ok": False, "reason": "too_short", "len": len(data)}, None

    version, inv, payload_type, payload_len = struct.unpack(">BBHI", data[:8])
    payload_len_i = int(payload_len)
    available = max(0, len(data) - 8)

    # Validate version
    version_valid = version in DOIP_VALID_VERSIONS
    inverse_ok = ((version ^ inv) & 0xFF) == 0xFF
    payload_type_valid = payload_type in DOIP_PAYLOAD_TYPE_NAMES
    payload_len_matches = payload_len_i <= available

    # Determine overall validity
    ok = inverse_ok and payload_len_matches
    reason = None
    if not inverse_ok:
        reason = "inverse_version_mismatch"
    elif not payload_len_matches:
        reason = f"payload_len_mismatch: declared {payload_len_i}, available {available}"

    fields: dict[str, Any] = {
        "ok": ok,
        "reason": reason,
        "version": int(version),
        "version_valid": version_valid,
        "inverse_version": int(inv),
        "inverse_ok": inverse_ok,
        "payload_type": int(payload_type),
        "payload_type_name": DOIP_PAYLOAD_TYPE_NAMES.get(int(payload_type), "unknown"),
        "payload_type_valid": payload_type_valid,
        "payload_len": payload_len_i,
        "payload_len_available": available,
        "payload_len_matches": payload_len_matches,
    }

    payload = data[8 : 8 + min(payload_len_i, available)]

    # Generic Negative Ack (0x0000)
    if int(payload_type) == 0x0000 and len(payload) >= 1:
        nack_code = int(payload[0])
        fields.update({
            "nack_code": nack_code,
        })

    # Routing Activation Request (0x0005): tester addr + activation_type + reserved + oem.
    if int(payload_type) == 0x0005 and len(payload) >= 4:
        tester_addr = int.from_bytes(payload[0:2], "big")
        activation_type = int(payload[2])
        # ISO 13400-2: byte 3 is reserved (ISO), bytes 4-7 are reserved (OEM)
        fields.update({
            "tester_addr": tester_addr,
            "activation_type": activation_type,
            "oem_len": max(0, len(payload) - 4) if len(payload) > 4 else 0,
        })

    # Routing Activation Response (0x0006)
    if int(payload_type) == 0x0006 and len(payload) >= 5:
        tester_addr = int.from_bytes(payload[0:2], "big")
        entity_addr = int.from_bytes(payload[2:4], "big")
        response_code = int(payload[4])
        fields.update({
            "tester_addr": tester_addr,
            "entity_addr": entity_addr,
            "activation_response_code": response_code,
            "activation_response_name": DOIP_ROUTING_ACTIVATION_RESPONSE.get(
                response_code, f"unknown_0x{response_code:02X}"
            ),
        })

    # Alive Check Request (0x0007): no payload
    # Alive Check Response (0x0008): logical address.
    if int(payload_type) == 0x0008 and len(payload) >= 2:
        logical_addr = int.from_bytes(payload[0:2], "big")
        fields.update({"logical_addr": logical_addr})

    # Diagnostic Message (0x8001): src/dst + UDS payload.
    if int(payload_type) == 0x8001 and len(payload) >= 4:
        src = int.from_bytes(payload[0:2], "big")
        dst = int.from_bytes(payload[2:4], "big")
        uds = payload[4:]
        fields.update({
            "diag_src": src,
            "diag_dst": dst,
            "uds_len": len(uds),
            "uds_payload": uds,  # Raw bytes for caller to parse
            "uds_empty": len(uds) == 0,
        })

    # Diagnostic Positive Ack (0x8002)
    if int(payload_type) == 0x8002 and len(payload) >= 5:
        src = int.from_bytes(payload[0:2], "big")
        dst = int.from_bytes(payload[2:4], "big")
        ack = int(payload[4])
        fields.update({
            "diag_src": src,
            "diag_dst": dst,
            "ack_code": ack,
        })

    # Diagnostic Negative Ack (0x8003)
    if int(payload_type) == 0x8003 and len(payload) >= 5:
        src = int.from_bytes(payload[0:2], "big")
        dst = int.from_bytes(payload[2:4], "big")
        nack = int(payload[4])
        fields.update({
            "diag_src": src,
            "diag_dst": dst,
            "nack_code": nack,
            "nack_name": DOIP_DIAG_NACK.get(nack, f"unknown_0x{nack:02X}"),
        })

    return fields, 8
