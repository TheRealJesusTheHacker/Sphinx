"""DNS wire handling: parse, sinkhole construction, malformed-input
survival. The sinkhole figures are FILTER-SPEC's, exactly."""
from sphinx_deb.core.dnswire import (
    TYPE_A,
    TYPE_AAAA,
    build_query,
    build_sinkhole_response,
    parse_query,
)


def test_build_and_parse_round_trip():
    query = parse_query(build_query("Ads.Example.COM", query_id=0x1234))
    assert query is not None
    assert query.id == 0x1234
    assert query.question_name == "ads.example.com"
    assert query.question_type == TYPE_A
    assert not query.is_response


def test_sinkhole_a_is_zero_quad_with_ttl_60_and_echoed_question():
    raw = build_query("ads.example.com", qtype=TYPE_A, query_id=7)
    query = parse_query(raw)
    response = build_sinkhole_response(query)
    parsed = parse_query(response)
    assert parsed is not None and parsed.is_response and parsed.id == 7
    # The question section is echoed exactly.
    assert response[12 : query.question_end] == raw[12 : query.question_end]
    p = query.question_end
    assert response[p : p + 2] == b"\xc0\x0c"  # name pointer to the question
    assert int.from_bytes(response[p + 6 : p + 10], "big") == 60  # TTL
    assert response[p + 12 : p + 16] == b"\x00\x00\x00\x00"  # 0.0.0.0


def test_sinkhole_aaaa_is_the_unspecified_address():
    raw = build_query("ads.example.com", qtype=TYPE_AAAA, query_id=8)
    query = parse_query(raw)
    response = build_sinkhole_response(query)
    p = query.question_end
    assert int.from_bytes(response[p + 10 : p + 12], "big") == 16
    assert response[p + 12 : p + 28] == b"\x00" * 16  # ::


def test_sinkhole_other_types_are_valid_noerror_with_no_answers():
    raw = build_query("ads.example.com", qtype=15, query_id=9)  # MX
    query = parse_query(raw)
    response = build_sinkhole_response(query)
    assert int.from_bytes(response[6:8], "big") == 0  # ANCOUNT
    assert response[2] & 0x80  # QR set
    assert response[3] & 0x0F == 0  # RCODE NOERROR


def test_malformed_packets_parse_to_none_never_raise():
    assert parse_query(b"") is None
    assert parse_query(b"\x00" * 11) is None
    assert parse_query(b"\x00" * 12) is None  # no question
    # A name that runs off the end.
    bad = bytearray(build_query("example.com"))
    bad[12] = 63
    assert parse_query(bytes(bad)) is None
    # A compression pointer loop.
    loop = (
        (1).to_bytes(2, "big") + (0x0100).to_bytes(2, "big")
        + (1).to_bytes(2, "big") + (0).to_bytes(2, "big") * 3
        + b"\xc0\x0c" + (1).to_bytes(2, "big") + (1).to_bytes(2, "big")
    )
    assert parse_query(loop) is None
