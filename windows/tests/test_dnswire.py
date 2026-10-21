"""Ports of the Android DnsPacketTest: parsing discipline and the
sinkhole byte layout."""
import struct

from sphinx_win.core import dnswire
from dnsutil import build_query, encode_name


class TestParse:
    def test_parses_basic_query(self):
        packet = build_query("Ads.Example.COM", qtype=28, qid=0xBEEF)
        parsed = dnswire.parse_query(packet)
        assert parsed is not None
        assert parsed.id == 0xBEEF
        assert parsed.question_name == "ads.example.com"
        assert parsed.question_type == 28
        assert parsed.question_class == 1
        assert not parsed.is_response
        assert parsed.recursion_desired

    def test_truncated_is_none(self):
        assert dnswire.parse_query(b"") is None
        assert dnswire.parse_query(b"\x00" * 11) is None
        assert dnswire.parse_query(build_query("a.example.com")[:14]) is None

    def test_zero_questions_is_none(self):
        packet = struct.pack(">HHHHHH", 1, 0x0100, 0, 0, 0, 0)
        assert dnswire.parse_query(packet) is None

    def test_compression_pointer_name(self):
        # Question name at 12 is a label + a pointer to a suffix at the
        # end of the packet (a shape real resolvers produce in some
        # messages); the parser must follow it and report the stream
        # end just past the pointer.
        suffix_offset = 12 + 1 + 3 + 2 + 4  # after label, pointer, qtype/qclass
        packet = (
            struct.pack(">HHHHHH", 7, 0x0100, 1, 0, 0, 0)
            + b"\x03www"
            + bytes([0xC0, suffix_offset])
            + struct.pack(">HH", 1, 1)
            + encode_name("example.com")
        )
        parsed = dnswire.parse_query(packet)
        assert parsed is not None
        assert parsed.question_name == "www.example.com"
        assert parsed.question_end == suffix_offset

    def test_pointer_loop_rejected(self):
        packet = (
            struct.pack(">HHHHHH", 7, 0x0100, 1, 0, 0, 0)
            + bytes([0xC0, 12])
            + struct.pack(">HH", 1, 1)
        )
        assert dnswire.parse_query(packet) is None

    def test_response_flag_seen(self):
        packet = bytearray(build_query("a.example.com"))
        packet[2] |= 0x80
        parsed = dnswire.parse_query(bytes(packet))
        assert parsed is not None and parsed.is_response


class TestSinkhole:
    def _sinkhole(self, name="ads.example.com", qtype=1, qid=0x4242):
        query = dnswire.parse_query(build_query(name, qtype=qtype, qid=qid))
        assert query is not None
        return query, dnswire.build_sinkhole_response(query)

    def test_a_query_gets_zero_address(self):
        _, response = self._sinkhole(qtype=1)
        parsed = dnswire.parse_query(response)
        # The answer section: pointer, type, class, TTL 60, rdlen 4, 0.0.0.0
        _, q, response_bytes = self._sinkhole_with_bytes(qtype=1)
        answer = response_bytes[q.question_end:]
        assert answer[0:2] == b"\xc0\x0c"
        assert struct.unpack(">H", answer[2:4])[0] == 1
        assert struct.unpack(">H", answer[4:6])[0] == 1
        assert struct.unpack(">I", answer[6:10])[0] == 60
        assert struct.unpack(">H", answer[10:12])[0] == 4
        assert answer[12:16] == b"\x00\x00\x00\x00"
        assert parsed is not None and parsed.is_response

    def _sinkhole_with_bytes(self, qtype):
        query = dnswire.parse_query(build_query("ads.example.com", qtype=qtype))
        return None, query, dnswire.build_sinkhole_response(query)

    def test_aaaa_query_gets_ipv6_zero(self):
        _, query, response = self._sinkhole_with_bytes(qtype=28)
        answer = response[query.question_end:]
        assert struct.unpack(">H", answer[10:12])[0] == 16
        assert answer[12:28] == b"\x00" * 16

    def test_other_type_gets_noerror_no_answers(self):
        _, query, response = self._sinkhole_with_bytes(qtype=15)  # MX
        assert struct.unpack(">H", response[6:8])[0] == 0  # ANCOUNT
        assert len(response) == query.question_end
        # RCODE stays NOERROR and QR is set.
        assert response[2] & 0x80
        assert response[3] & 0x0F == 0

    def test_id_and_question_echoed_exactly(self):
        query, response = self._sinkhole(qid=0x99AA)
        assert response[0:2] == b"\x99\xaa"
        original = build_query("ads.example.com", qtype=1, qid=0x99AA)
        assert response[12 : query.question_end] == original[12 : query.question_end]
