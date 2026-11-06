"""Regression coverage for protocol encoders, parsers, and dispatch."""
import io
import struct
import unittest
from unittest.mock import patch

import SpectraScan
from modules import network_services
from modules.database_enum import MySQLEnumerator, PostgreSQLEnumerator
from modules.mongodb_enum import MongoDBEnumerator
from modules.nfs_enum import _parse_exports, _parse_portmap_dump
from modules.rdp_enum import _parse_negotiation
from modules.redis_enum import _read_resp
from modules.rtsp_enum import _parse_response
from modules.smtp_enum import _recv_response
from modules.snmp_enum import SNMPEnumerator, SNMPError, _decode_oid, _integer, _oid, _parse_response, _tlv

class FakeSocket:
    def __init__(self, payload):
        self.payload = bytearray(payload)
    def settimeout(self, _timeout):
        pass
    def sendall(self, _data):
        pass
    def recv(self, size):
        chunk = bytes(self.payload[:size])
        del self.payload[:size]
        return chunk

def xdr_string(value):
    raw = value.encode()
    return struct.pack(">I", len(raw)) + raw + (b"\x00" * ((-len(raw)) % 4))

def build_snmp_response(request_id=7, community="public", oid="1.3.6.1.2.1.1.1.0"):
    binding = _tlv(0x30, _oid(oid) + _tlv(0x04, b"test-agent"))
    bindings = _tlv(0x30, binding)
    pdu = _tlv(0xA2, _integer(request_id) + _integer(0) + _integer(0) + bindings)
    return _tlv(0x30, _integer(1) + _tlv(0x04, community.encode()) + pdu)


def build_rdp_confirm(selected_protocol):
    x224 = b"\x06\xd0\x00\x00\x00\x00\x00"
    negotiation = struct.pack("<BBHI", 2, 0, 8, selected_protocol)
    payload = x224 + negotiation
    return b"\x03\x00" + struct.pack(">H", len(payload) + 4) + payload

class TestSNMPEncoding(unittest.TestCase):
    def test_oid_uses_base128_arc_encoding(self):
        encoded = _oid("1.3.6.1.4.1.8072.3.2.10")
        self.assertEqual(encoded[0], 0x06)
        self.assertEqual(_decode_oid(encoded[2:2 + encoded[1]]), "1.3.6.1.4.1.8072.3.2.10")
    def test_integer_128_is_positive_and_canonical(self):
        self.assertEqual(SNMPEnumerator._ber_encode_integer(128), b"\x02\x02\x00\x80")
    def test_get_request_builds_valid_sequence(self):
        packet = SNMPEnumerator._build_get_request("public", "1.3.6.1.2.1.1.1.0", 7)
        self.assertEqual(packet[0], 0x30)
        self.assertEqual(packet[2], 0x02)

    def test_response_requires_matching_request_id_and_community(self):
        response = build_snmp_response()
        self.assertEqual(_parse_response(response, expected_request_id=7, expected_community="public"), "test-agent")
        with self.assertRaises(SNMPError):
            _parse_response(response, expected_request_id=8, expected_community="public")
        with self.assertRaises(SNMPError):
            _parse_response(response, expected_request_id=7, expected_community="private")

class TestMongoDBBson(unittest.TestCase):
    def test_bool_is_encoded_as_boolean_not_int32(self):
        encoded = MongoDBEnumerator._bson_encode({"enabled": True, "count": 3})
        self.assertIn(b"\x08enabled\x00\x01", encoded)
        self.assertEqual(MongoDBEnumerator._parse_bson(encoded), {"enabled": True, "count": 3})
    def test_arrays_and_nested_documents_round_trip(self):
        value = {"names": ["one", "two"], "meta": {"ok": True}}
        self.assertEqual(MongoDBEnumerator._parse_bson(MongoDBEnumerator._bson_encode(value)), value)
    def test_invalid_document_length_is_rejected(self):
        with self.assertRaises(ValueError):
            MongoDBEnumerator._parse_bson(b"\x04\x00\x00\x00\x00")

    def test_op_msg_requires_exact_response_to_correlation(self):
        document = MongoDBEnumerator._bson_encode({"ok": 1})
        payload = struct.pack("<I", 0) + b"\x00" + document
        response = struct.pack("<iiii", 16 + len(payload), 99, 5, 2013) + payload
        self.assertEqual(MongoDBEnumerator._send_op_msg(FakeSocket(response), b"request", request_id=5), document)
        wrong = struct.pack("<iiii", 16 + len(payload), 99, 0, 2013) + payload
        with self.assertRaisesRegex(ValueError, "response id mismatch"):
            MongoDBEnumerator._send_op_msg(FakeSocket(wrong), b"request", request_id=5)

class TestRedisResp(unittest.TestCase):
    def test_simple_bulk_integer_and_array_responses(self):
        self.assertEqual(_read_resp(io.BytesIO(b"+PONG\r\n")), "PONG")
        self.assertEqual(_read_resp(io.BytesIO(b"$3\r\nfoo\r\n")), "foo")
        self.assertEqual(_read_resp(io.BytesIO(b":12\r\n")), 12)
        self.assertEqual(_read_resp(io.BytesIO(b"*2\r\n+one\r\n:2\r\n")), ["one", 2])

class TestDatabaseProtocols(unittest.TestCase):
    def test_mysql_handshake_version_parsing(self):
        self.assertEqual(MySQLEnumerator.parse_handshake(b"\x0a8.0.36\x00rest"), "8.0.36")
    def test_postgresql_ssl_request_is_exactly_eight_bytes(self):
        request = struct.pack(">II", 8, 80877103)
        self.assertEqual(len(request), 8)
        self.assertEqual(struct.unpack(">II", request), (8, 80877103))
    def test_postgresql_startup_message_length_matches_packet(self):
        packet = PostgreSQLEnumerator.startup_message()
        self.assertEqual(struct.unpack(">I", packet[:4])[0], len(packet))

class TestNFSXdr(unittest.TestCase):
    def test_portmapper_dump_parses_mountd_tuple(self):
        header = struct.pack(">6I", 1, 1, 0, 0, 0, 0)
        payload = header + struct.pack(">I4I", 1, 100005, 1, 6, 20048) + struct.pack(">I", 0)
        self.assertEqual(_parse_portmap_dump(payload)["mountd"]["port"], 20048)
        self.assertEqual(_parse_portmap_dump(payload)["mountd"]["protocol"], 6)
    def test_mountd_export_groups_are_parsed(self):
        header = struct.pack(">6I", 1, 1, 0, 0, 0, 0)
        payload = header + struct.pack(">I", 1) + xdr_string("/srv/share")
        payload += struct.pack(">I", 1) + xdr_string("*") + struct.pack(">I", 0) + struct.pack(">I", 0)
        self.assertEqual(_parse_exports(payload), [{"path": "/srv/share", "allowed_clients": ["*"]}])

class TestRDPAndRTSP(unittest.TestCase):
    def test_rdp_hybrid_response_is_nla_capable(self):
        parsed = _parse_negotiation(build_rdp_confirm(2))
        self.assertTrue(parsed["nla"])
        self.assertEqual(parsed["selected_protocol"], 2)
    def test_rdp_ssl_response_is_not_nla(self):
        self.assertFalse(_parse_negotiation(build_rdp_confirm(1))["nla"])
    def test_rdp_rejects_bad_tpkt_and_negotiation_lengths(self):
        packet = build_rdp_confirm(2)
        self.assertFalse(_parse_negotiation(packet[:-1])["responds"])
        malformed = packet[:2] + struct.pack(">H", len(packet) + 1) + packet[4:]
        self.assertFalse(_parse_negotiation(malformed)["responds"])
        malformed = packet[:-8] + struct.pack("<BBHI", 2, 0, 7, 2)
        malformed = malformed[:2] + struct.pack(">H", len(malformed)) + malformed[4:]
        self.assertFalse(_parse_negotiation(malformed)["responds"])
    def test_rtsp_headers_and_sdp_are_separate(self):
        body = b"v=0\r\nm=video 5004 RTP/AVP 96\r\n"
        raw = (b"RTSP/1.0 200 OK\r\nServer: camera-test\r\nContent-Type: application/sdp\r\n"
               + f"Content-Length: {len(body)}".encode() + b"\r\n\r\n" + body)
        parsed = _parse_response(raw)
        self.assertEqual(parsed["status_code"], 200)
        self.assertEqual(parsed["server"], "camera-test")
        self.assertEqual(parsed["streams"][0]["port"], 5004)
        self.assertEqual(parsed["streams"][0]["type"], "video")
    def test_rtsp_rejects_malformed_status_and_content_length(self):
        with self.assertRaises(ValueError):
            _parse_response(b"RTSP/1.0 200OK\r\n\r\n")
        with self.assertRaises(ValueError):
            _parse_response(b"RTSP/1.0 200 OK\r\nContent-Length: 8\r\n\r\nshort")
        with self.assertRaises(ValueError):
            _parse_response(b"RTSP/1.0 200 OK\r\nContent-Length: 0\r\ncontent-length: 0\r\n\r\n")

class TestSMTPResponses(unittest.TestCase):
    def test_multiline_ehlo_is_consumed_until_final_code_line(self):
        sock = FakeSocket(b"250-mail.example\r\n250-STARTTLS\r\n250 SIZE 100\r\n220 Ready\r\n")
        response = _recv_response(sock)
        self.assertEqual(len(response), 3)
        self.assertTrue(any("STARTTLS" in line for line in response))
        self.assertEqual(_recv_response(sock), ["220 Ready"])

    def test_malformed_multiline_and_inconsistent_codes_are_rejected(self):
        with self.assertRaises(ValueError):
            _recv_response(FakeSocket(b"250-first\r\n550 final\r\n))
        with self.assertRaises(ValueError):
            _recv_response(FakeSocket(b"250-first\r\n250-final\r\n))
        with self.assertRaises(ValueError):
            _recv_response(FakeSocket(b"25x malformed\r\n))

class TestDispatchAndCli(unittest.TestCase):
    def test_protocol_results_do_not_overwrite_same_service(self):
        fake = lambda _ip, port: {"port": port}
        patched = {139: ("smb", fake), 445: ("smb", fake), 389: ("ldap", fake), 636: ("ldap", fake)}
        with patch.dict(network_services.SERVICE_MAP, patched, clear=False):
            result = network_services.deep_scan("127.0.0.1", [139, 445, 389, 636], max_workers=2)
        self.assertEqual(set(result["scans"]), {"smb:139", "smb:445", "ldap:389", "ldap:636"})
    def test_legacy_target_resolution_accepts_http_url(self):
        self.assertEqual(SpectraScan.resolve_host("https://127.0.0.1:8443/admin?q=1"), "127.0.0.1")
    def test_legacy_target_resolution_accepts_bare_host_port(self):
        self.assertEqual(SpectraScan.resolve_host("127.0.0.1:8080"), "127.0.0.1")
    def test_interactive_protocol_menu_uses_real_module_adapter(self):
        fake = {"module": "mongodb", "open": True}
        with patch("modules.mongodb_enum.MongoDBEnumerator.scan", return_value=fake) as scan:
            self.assertEqual(SpectraScan.ProtocolModuleScanner.run_mongodb("127.0.0.1"), fake)
        scan.assert_called_once_with("127.0.0.1", port=27017)

if __name__ == "__main__":
    unittest.main()
