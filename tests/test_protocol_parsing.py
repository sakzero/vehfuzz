from __future__ import annotations

import sys
import unittest
from pathlib import Path


def _bootstrap_src_path() -> None:
    project_root = Path(__file__).resolve().parents[1]
    src_dir = project_root / "src"
    sys.path.insert(0, str(src_dir))


_bootstrap_src_path()

from vehfuzz.core.plugins import Message, create_protocol, load_builtin_plugins  # noqa: E402
from vehfuzz.core.isotp import build_sf  # noqa: E402
from vehfuzz.plugins.protocols.j1939 import J1939Id  # noqa: E402


class ProtocolParsingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        load_builtin_plugins()

    def test_someip_parse(self) -> None:
        proto = create_protocol(
            "someip",
            {
                "service_id": 0x1234,
                "method_id": 0x0001,
                "client_id": 0x0001,
                "session_id": 0x0001,
            },
        )
        seed = Message(data=b"", meta={})
        tx = proto.build_tx(seed, b"hello")
        parsed = proto.parse(tx)
        self.assertIsNotNone(parsed)
        assert parsed is not None
        d = parsed.to_dict()
        self.assertEqual(d["protocol"], "someip")
        self.assertEqual(d["payload"]["offset"], 16)
        self.assertEqual(d["payload"]["length"], 5)
        self.assertTrue(d["fields"]["length_matches"])

    def test_someip_method_correlation(self) -> None:
        proto = create_protocol(
            "someip",
            {
                "service_id": 0x1234,
                "method_id": 0x0001,
                "client_id": 0x1111,
                "session_id": 0x2222,
                "message_type": 0x00,
                "return_code": 0x00,
            },
        )
        seed = Message(data=b"", meta={})
        req = proto.build_tx(seed, b"\x01\x02")
        _ = proto.parse(req)

        # Craft a response with same ids and message_type=0x80.
        import struct

        payload = b"\x99"
        length = len(payload) + 8
        hdr = struct.pack(">HHIHHBBBB", 0x1234, 0x0001, length, 0x1111, 0x2222, 1, 1, 0x80, 0x00)
        resp = Message(data=hdr + payload, meta={})
        parsed = proto.parse(resp)
        self.assertIsNotNone(parsed)
        assert parsed is not None
        d = parsed.to_dict()
        self.assertIn("correlates_to", d["fields"])

    def test_uds_parse_negative_response(self) -> None:
        proto = create_protocol("uds", {"max_len": 64})
        msg = Message(data=bytes([0x7F, 0x10, 0x11]), meta={})
        parsed = proto.parse(msg)
        self.assertIsNotNone(parsed)
        assert parsed is not None
        d = parsed.to_dict()
        self.assertEqual(d["protocol"], "uds")
        self.assertEqual(d["fields"]["kind"], "negative_response")
        self.assertEqual(d["fields"]["request_sid"], 0x10)
        self.assertEqual(d["fields"]["nrc"], 0x11)

    def test_can_isotp_nested_uds(self) -> None:
        proto = create_protocol("can", {"parse_isotp": True})
        isotp = build_sf(b"\x22\xf1\x90", frame_len=8, pad_byte=0x00)
        msg = Message(data=isotp, meta={"can_id": 0x7E0, "is_extended": False, "is_fd": False, "dlc": 8})
        parsed = proto.parse(msg)
        self.assertIsNotNone(parsed)
        assert parsed is not None
        d = parsed.to_dict()
        self.assertIsNotNone(d["fields"]["isotp"])
        self.assertIsNotNone(d["fields"]["inner_uds"])
        self.assertEqual(d["fields"]["inner_uds"]["request_sid"], 0x22)

    def test_can_parse(self) -> None:
        proto = create_protocol("can", {"can_id": 0x7DF})
        msg = Message(data=b"\x01\x02\x03", meta={"can_id": 0x123, "is_extended": False, "is_fd": False, "dlc": 3})
        parsed = proto.parse(msg)
        self.assertIsNotNone(parsed)
        assert parsed is not None
        d = parsed.to_dict()
        self.assertEqual(d["protocol"], "can")
        self.assertEqual(d["fields"]["can_id"], 0x123)
        self.assertEqual(d["payload"]["offset"], 0)
        self.assertEqual(d["payload"]["length"], 3)

    def test_j1939_tp_reassembly(self) -> None:
        proto = create_protocol("j1939", {})
        sa = 0xAA
        da = 0xFF
        # TP.CM BAM for target PGN 0x00FEE9, total_len=10, total_packets=2.
        target_pgn = 0x00FEE9
        cm_id = J1939Id(priority=6, reserved=0, data_page=0, pdu_format=0xEC, pdu_specific=da, source_address=sa).to_can_id()
        cm_payload = bytes([0x20]) + (10).to_bytes(2, "little") + bytes([2, 0xFF]) + target_pgn.to_bytes(3, "little")
        _ = proto.parse(Message(data=cm_payload, meta={"can_id": cm_id}))

        dt_id = J1939Id(priority=6, reserved=0, data_page=0, pdu_format=0xEB, pdu_specific=da, source_address=sa).to_can_id()
        dt1 = bytes([1]) + b"ABCDEFG"
        _ = proto.parse(Message(data=dt1, meta={"can_id": dt_id}))
        dt2 = bytes([2]) + b"HIJxxxx"
        parsed = proto.parse(Message(data=dt2, meta={"can_id": dt_id}))
        self.assertIsNotNone(parsed)
        assert parsed is not None
        d = parsed.to_dict()
        self.assertTrue(d["fields"]["tp"]["reassembly_complete"])
        self.assertEqual(d["fields"]["tp_payload_hex"], b"ABCDEFGHIJ".hex())

    def test_nmea_parse_checksum(self) -> None:
        proto = create_protocol("nmea", {"max_body_len": 120})
        seed = Message(data=b"", meta={})
        tx = proto.build_tx(seed, b"GPGLL,4916.45,N,12311.12,W,225444,A")
        parsed = proto.parse(tx)
        self.assertIsNotNone(parsed)
        assert parsed is not None
        d = parsed.to_dict()
        self.assertEqual(d["protocol"], "nmea")
        self.assertTrue(d["fields"].get("checksum_matches"))

    def test_nmea_scenario_simulation(self) -> None:
        proto = create_protocol(
            "nmea",
            {
                "scenario": {
                    "type": "circle",
                    "lat": 31.0,
                    "lon": 121.0,
                    "radius_m": 10.0,
                    "angular_speed_deg_per_step": 30.0,
                    "jitter_deg": 0.0,
                    "drop_fix_prob": 0.0,
                }
            },
        )
        seed = Message(data=b"", meta={})
        tx1 = proto.build_tx(seed, b"\x00")
        tx2 = proto.build_tx(seed, b"\x00")
        self.assertNotEqual(tx1.data, tx2.data)
        p1 = proto.parse(tx1)
        p2 = proto.parse(tx2)
        self.assertIsNotNone(p1)
        self.assertIsNotNone(p2)

    def test_wifi_parse_ethernet_ipv4_udp(self) -> None:
        proto = create_protocol("wifi", {})
        eth = b"\xaa\xbb\xcc\xdd\xee\xff" + b"\x11\x22\x33\x44\x55\x66" + b"\x08\x00"
        ip = bytearray(20)
        ip[0] = 0x45  # v4, ihl=5
        ip[2:4] = (28).to_bytes(2, "big")
        ip[8] = 64
        ip[9] = 17  # UDP
        ip[12:16] = bytes([1, 2, 3, 4])
        ip[16:20] = bytes([5, 6, 7, 8])
        udp = bytearray(8)
        udp[0:2] = (1234).to_bytes(2, "big")
        udp[2:4] = (80).to_bytes(2, "big")
        udp[4:6] = (8).to_bytes(2, "big")
        pkt = eth + bytes(ip) + bytes(udp)
        msg = Message(
            data=pkt,
            meta={
                "pcap_global": {"linktype": 1},
                "pcap": {"linktype": 1},
            },
        )
        parsed = proto.parse(msg)
        self.assertIsNotNone(parsed)
        assert parsed is not None
        d = parsed.to_dict()
        self.assertEqual(d["protocol"], "wifi")
        self.assertEqual(d["fields"]["l4"], "udp")
        self.assertEqual(d["payload"]["offset"], 14 + 20 + 8)
        self.assertEqual(d["payload"]["length"], 0)

    def test_wifi_protected_frame_without_decrypt(self) -> None:
        try:
            import Cryptodome  # type: ignore  # noqa: F401
        except Exception:
            with self.assertRaises(RuntimeError):
                _ = create_protocol("wifi", {"decrypt": {"ccmp_tk_hex": "00" * 16}})
            return

        proto = create_protocol("wifi", {"decrypt": {"ccmp_tk_hex": "00" * 16}})
        fc = (0x4000 | 0x0008).to_bytes(2, "little")  # protected + data
        dur = b"\x00\x00"
        addr1 = b"\x00\x11\x22\x33\x44\x55"
        addr2 = b"\x66\x77\x88\x99\xaa\xbb"
        addr3 = b"\xcc\xdd\xee\xff\x00\x01"
        seq = b"\x00\x00"
        hdr = fc + dur + addr1 + addr2 + addr3 + seq
        ccmp = b"\x00" * 8
        mic = b"\x00" * 8
        frame = hdr + ccmp + mic
        msg = Message(data=frame, meta={"pcap_global": {"linktype": 105}, "pcap": {"linktype": 105}})
        parsed = proto.parse(msg)
        self.assertIsNotNone(parsed)
        assert parsed is not None
        self.assertTrue(parsed.encrypted)

    def test_bluetooth_parse_hci_h4_acl_sdp(self) -> None:
        proto = create_protocol("bluetooth", {})
        ptype = bytes([0x02])
        handle_flags = (0x0001).to_bytes(2, "little")
        l2_payload = bytes([0x01]) + (0x0001).to_bytes(2, "big") + (0x0000).to_bytes(2, "big")
        l2_len = (len(l2_payload)).to_bytes(2, "little")
        cid = (0x0040).to_bytes(2, "little")
        acl_payload = l2_len + cid + l2_payload
        acl_len = (len(acl_payload)).to_bytes(2, "little")
        h4 = ptype + handle_flags + acl_len + acl_payload
        msg = Message(
            data=h4,
            meta={
                "pcap_global": {"linktype": 187},
                "pcap": {"linktype": 187},
            },
        )
        parsed = proto.parse(msg)
        self.assertIsNotNone(parsed)
        assert parsed is not None
        d = parsed.to_dict()
        self.assertEqual(d["protocol"], "bluetooth")
        self.assertEqual(d["fields"]["layer"], "sdp")
        self.assertEqual(d["payload"]["offset"], 1 + 4 + 4)
        self.assertEqual(d["payload"]["length"], len(l2_payload))

    def test_someip_sd_parse_entries(self) -> None:
        proto = create_protocol("someip_sd", {})
        # One Service Entry (16 bytes): type=OfferService(0x01)
        entry = bytearray(16)
        entry[0] = 0x01
        entry[1] = 0x00  # index1
        entry[2] = 0x00  # index2
        entry[3] = 0x00  # num options
        entry[4:6] = (0x1234).to_bytes(2, "big")  # service_id
        entry[6:8] = (0x5678).to_bytes(2, "big")  # instance_id
        entry[8] = 0x01  # major
        entry[9:12] = (0x000001).to_bytes(3, "big")  # ttl
        entry[12:16] = (0x00000002).to_bytes(4, "big")  # minor

        seed = Message(data=b"", meta={})
        tx = proto.build_tx(seed, bytes(entry))
        parsed = proto.parse(tx)
        self.assertIsNotNone(parsed)
        assert parsed is not None
        d = parsed.to_dict()
        self.assertEqual(d["protocol"], "someip_sd")
        self.assertEqual(d["fields"]["sd_entries_count"], 1)
        e0 = d["fields"]["sd_entries"][0]
        self.assertEqual(e0["type"], 0x01)
        self.assertEqual(e0["service_id"], 0x1234)
        self.assertEqual(e0["instance_id"], 0x5678)
        self.assertEqual(e0["major_version"], 1)
        self.assertEqual(e0["minor_version"], 2)


if __name__ == "__main__":
    unittest.main()
