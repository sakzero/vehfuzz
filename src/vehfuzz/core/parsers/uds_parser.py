"""
UDS (Unified Diagnostic Services) payload parser.

This is a pure parsing function with no dependencies on protocol plugins.
It can be used by any protocol that carries UDS payloads (CAN, DoIP, etc.).
"""

from __future__ import annotations

from typing import Any


# UDS Service IDs (request SIDs)
UDS_SERVICES: dict[int, str] = {
    0x10: "DiagnosticSessionControl",
    0x11: "ECUReset",
    0x14: "ClearDiagnosticInformation",
    0x19: "ReadDTCInformation",
    0x22: "ReadDataByIdentifier",
    0x23: "ReadMemoryByAddress",
    0x24: "ReadScalingDataByIdentifier",
    0x27: "SecurityAccess",
    0x28: "CommunicationControl",
    0x2A: "ReadDataByPeriodicIdentifier",
    0x2C: "DynamicallyDefineDataIdentifier",
    0x2E: "WriteDataByIdentifier",
    0x2F: "InputOutputControlByIdentifier",
    0x31: "RoutineControl",
    0x34: "RequestDownload",
    0x35: "RequestUpload",
    0x36: "TransferData",
    0x37: "RequestTransferExit",
    0x38: "RequestFileTransfer",
    0x3D: "WriteMemoryByAddress",
    0x3E: "TesterPresent",
    0x83: "AccessTimingParameter",
    0x84: "SecuredDataTransmission",
    0x85: "ControlDTCSetting",
    0x86: "ResponseOnEvent",
    0x87: "LinkControl",
}

# Negative Response Codes
UDS_NRC: dict[int, str] = {
    0x10: "generalReject",
    0x11: "serviceNotSupported",
    0x12: "subFunctionNotSupported",
    0x13: "incorrectMessageLengthOrInvalidFormat",
    0x14: "responseTooLong",
    0x21: "busyRepeatRequest",
    0x22: "conditionsNotCorrect",
    0x24: "requestSequenceError",
    0x25: "noResponseFromSubnetComponent",
    0x26: "failurePreventsExecutionOfRequestedAction",
    0x31: "requestOutOfRange",
    0x33: "securityAccessDenied",
    0x35: "invalidKey",
    0x36: "exceededNumberOfAttempts",
    0x37: "requiredTimeDelayNotExpired",
    0x70: "uploadDownloadNotAccepted",
    0x71: "transferDataSuspended",
    0x72: "generalProgrammingFailure",
    0x73: "wrongBlockSequenceCounter",
    0x78: "requestCorrectlyReceivedResponsePending",
    0x7E: "subFunctionNotSupportedInActiveSession",
    0x7F: "serviceNotSupportedInActiveSession",
}

# DiagnosticSessionControl session types
UDS_SESSION_TYPES: dict[int, str] = {
    0x01: "defaultSession",
    0x02: "programmingSession",
    0x03: "extendedDiagnosticSession",
    0x04: "safetySystemDiagnosticSession",
}

# ECUReset reset types
UDS_RESET_TYPES: dict[int, str] = {
    0x01: "hardReset",
    0x02: "keyOffOnReset",
    0x03: "softReset",
    0x04: "enableRapidPowerShutDown",
    0x05: "disableRapidPowerShutDown",
}

# RoutineControl sub-functions
UDS_ROUTINE_CONTROL: dict[int, str] = {
    0x01: "startRoutine",
    0x02: "stopRoutine",
    0x03: "requestRoutineResults",
}

# CommunicationControl sub-functions
UDS_COMM_CONTROL: dict[int, str] = {
    0x00: "enableRxAndTx",
    0x01: "enableRxAndDisableTx",
    0x02: "disableRxAndEnableTx",
    0x03: "disableRxAndTx",
}

# ControlDTCSetting sub-functions
UDS_DTC_SETTING: dict[int, str] = {
    0x01: "on",
    0x02: "off",
}


def parse_uds_payload(data: bytes) -> dict[str, Any]:
    """
    Parse a UDS payload and extract service information.

    Args:
        data: Raw UDS payload bytes

    Returns:
        Dictionary containing parsed UDS fields:
        - kind: "empty", "negative_response", "positive_response", or "request"
        - sid: Service ID byte
        - request_sid: Original request SID (for responses)
        - service_name: Human-readable service name
        - nrc: Negative Response Code (for negative responses)
        - nrc_name: Human-readable NRC name
        - Additional service-specific fields
    """
    if not data:
        return {"kind": "empty"}

    sid = int(data[0])

    # Negative response: 0x7F + request_sid + NRC
    if sid == 0x7F and len(data) >= 3:
        req_sid = int(data[1])
        nrc = int(data[2])
        return {
            "kind": "negative_response",
            "sid": sid,
            "request_sid": req_sid,
            "service_name": UDS_SERVICES.get(req_sid, f"Unknown_0x{req_sid:02X}"),
            "nrc": nrc,
            "nrc_name": UDS_NRC.get(nrc, f"Unknown_0x{nrc:02X}"),
        }

    # Positive response SID is request SID + 0x40 in many services.
    is_positive = sid >= 0x40 and sid != 0x7F
    req_sid = (sid - 0x40) & 0xFF if is_positive else sid

    # Validate that req_sid is a known service
    service_name = UDS_SERVICES.get(req_sid, f"Unknown_0x{req_sid:02X}")

    out: dict[str, Any] = {
        "kind": "positive_response" if is_positive else "request",
        "sid": sid,
        "request_sid": req_sid,
        "service_name": service_name,
    }

    # Service-specific parsing
    _parse_service_specific(out, req_sid, data, is_positive)

    return out


def _parse_service_specific(out: dict[str, Any], req_sid: int, data: bytes, is_positive: bool) -> None:
    """Parse service-specific fields."""

    if req_sid == 0x10:  # DiagnosticSessionControl
        if len(data) >= 2:
            session = int(data[1]) & 0x7F
            out["session_type"] = session
            out["session_name"] = UDS_SESSION_TYPES.get(session, f"vendorSpecific_0x{session:02X}")
            out["suppress_response"] = bool(data[1] & 0x80)

    elif req_sid == 0x11:  # ECUReset
        if len(data) >= 2:
            reset_type = int(data[1]) & 0x7F
            out["reset_type"] = reset_type
            out["reset_name"] = UDS_RESET_TYPES.get(reset_type, f"vendorSpecific_0x{reset_type:02X}")
            out["suppress_response"] = bool(data[1] & 0x80)

    elif req_sid == 0x14:  # ClearDiagnosticInformation
        if len(data) >= 4:
            # 3-byte group of DTC
            group = (int(data[1]) << 16) | (int(data[2]) << 8) | int(data[3])
            out["dtc_group"] = group
            out["dtc_group_hex"] = f"0x{group:06X}"

    elif req_sid == 0x19:  # ReadDTCInformation
        if len(data) >= 2:
            subfunction = int(data[1])
            out["subfunction"] = subfunction
            # Parse DTC status mask if present
            if len(data) >= 3 and subfunction in (0x02, 0x0A, 0x0F, 0x13, 0x15):
                out["dtc_status_mask"] = int(data[2])

    elif req_sid == 0x22:  # ReadDataByIdentifier
        if len(data) >= 3:
            did = (int(data[1]) << 8) | int(data[2])
            out["did"] = did
            out["did_hex"] = f"0x{did:04X}"
            # Can have multiple DIDs
            if len(data) >= 5:
                dids = []
                for i in range(1, len(data) - 1, 2):
                    if i + 1 < len(data):
                        d = (int(data[i]) << 8) | int(data[i + 1])
                        dids.append(d)
                if len(dids) > 1:
                    out["dids"] = dids

    elif req_sid == 0x23:  # ReadMemoryByAddress
        if len(data) >= 2:
            addr_len_format = int(data[1])
            mem_size_len = (addr_len_format >> 4) & 0x0F
            addr_len = addr_len_format & 0x0F
            out["address_length"] = addr_len
            out["memory_size_length"] = mem_size_len
            if len(data) >= 2 + addr_len:
                addr = int.from_bytes(data[2:2 + addr_len], "big")
                out["address"] = addr
                out["address_hex"] = f"0x{addr:X}"

    elif req_sid == 0x27:  # SecurityAccess
        if len(data) >= 2:
            subfunction = int(data[1])
            out["security_subfunction"] = subfunction
            out["is_request_seed"] = (subfunction % 2) == 1
            out["is_send_key"] = (subfunction % 2) == 0
            out["security_level"] = (subfunction + 1) // 2
            out["payload_len"] = max(0, len(data) - 2)

    elif req_sid == 0x28:  # CommunicationControl
        if len(data) >= 2:
            subfunction = int(data[1]) & 0x7F
            out["subfunction"] = subfunction
            out["control_type"] = UDS_COMM_CONTROL.get(subfunction, f"vendorSpecific_0x{subfunction:02X}")
            out["suppress_response"] = bool(data[1] & 0x80)
            if len(data) >= 3:
                out["communication_type"] = int(data[2])

    elif req_sid == 0x2E:  # WriteDataByIdentifier
        if len(data) >= 3:
            did = (int(data[1]) << 8) | int(data[2])
            out["did"] = did
            out["did_hex"] = f"0x{did:04X}"
            out["payload_len"] = max(0, len(data) - 3)

    elif req_sid == 0x2F:  # InputOutputControlByIdentifier
        if len(data) >= 3:
            did = (int(data[1]) << 8) | int(data[2])
            out["did"] = did
            out["did_hex"] = f"0x{did:04X}"
            if len(data) >= 4:
                out["control_option"] = int(data[3])

    elif req_sid == 0x31:  # RoutineControl
        if len(data) >= 2:
            subfunction = int(data[1]) & 0x7F
            out["subfunction"] = subfunction
            out["routine_control"] = UDS_ROUTINE_CONTROL.get(subfunction, f"unknown_0x{subfunction:02X}")
            out["suppress_response"] = bool(data[1] & 0x80)
            if len(data) >= 4:
                rid = (int(data[2]) << 8) | int(data[3])
                out["routine_id"] = rid
                out["routine_id_hex"] = f"0x{rid:04X}"
                out["option_record_len"] = max(0, len(data) - 4)

    elif req_sid == 0x34:  # RequestDownload
        if len(data) >= 2:
            out["data_format"] = int(data[1])
            out["compression"] = (int(data[1]) >> 4) & 0x0F
            out["encryption"] = int(data[1]) & 0x0F

    elif req_sid == 0x36:  # TransferData
        if len(data) >= 2:
            out["block_sequence_counter"] = int(data[1])
            out["transfer_data_len"] = max(0, len(data) - 2)

    elif req_sid == 0x3E:  # TesterPresent
        if len(data) >= 2:
            out["subfunction"] = int(data[1]) & 0x7F
            out["suppress_response"] = bool(data[1] & 0x80)

    elif req_sid == 0x85:  # ControlDTCSetting
        if len(data) >= 2:
            subfunction = int(data[1]) & 0x7F
            out["subfunction"] = subfunction
            out["dtc_setting"] = UDS_DTC_SETTING.get(subfunction, f"unknown_0x{subfunction:02X}")
            out["suppress_response"] = bool(data[1] & 0x80)

    else:
        # Generic subfunction extraction for unknown services
        if len(data) >= 2:
            out["subfunction"] = int(data[1])
