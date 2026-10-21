"""Minimal DNS wire handling for the Sphinx filter: parse the first
question of a query, and build a sinkhole response for blocked names.

A port of the Android edition's ``core/DnsPacket.kt`` — every edition
implements the same brain (docs/FILTER-SPEC.md).

Sinkhole behavior per the spec:
  - A queries are answered with 0.0.0.0
  - AAAA queries are answered with ::
  - Any other type gets a NOERROR response with no answer records
  - TTL is 60 seconds; the ID and question section are echoed exactly
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple

TYPE_A = 1
TYPE_AAAA = 28
CLASS_IN = 1
HEADER_SIZE = 12
SINKHOLE_TTL_SECONDS = 60

_MAX_NAME_JUMPS = 32  # compression-pointer loop guard


def _u16(data: bytes, offset: int) -> int:
    return (data[offset] << 8) | data[offset + 1]


def _read_name(data: bytes, start: int, limit: int) -> Optional[Tuple[str, int]]:
    """Read a possibly-compressed domain name starting at ``start``.

    Returns the decoded name (lowercased, no trailing dot) and the
    offset just past the name *in the original stream* — for a name
    ending in a compression pointer, that is just past the pointer.
    """
    labels = []
    offset = start
    stream_end = -1
    jumps = 0
    while True:
        if offset >= limit:
            return None
        length = data[offset]
        if length == 0:
            if stream_end < 0:
                stream_end = offset + 1
            return ".".join(labels), stream_end
        if length & 0xC0 == 0xC0:
            if offset + 1 >= limit:
                return None
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if stream_end < 0:
                stream_end = offset + 2
            jumps += 1
            if jumps > _MAX_NAME_JUMPS:
                return None  # compression loop guard
            offset = pointer
        elif length & 0xC0 == 0:
            if offset + 1 + length > limit:
                return None
            try:
                label = data[offset + 1 : offset + 1 + length].decode("ascii")
            except UnicodeDecodeError:
                return None
            labels.append(label.lower())
            offset += 1 + length
        else:
            return None  # 0x40 / 0x80 label types are not valid here


@dataclass(frozen=True)
class DnsQuery:
    id: int
    is_response: bool
    opcode: int
    recursion_desired: bool
    #: Decoded question name, lowercased, no trailing dot. Root is "".
    question_name: str
    question_type: int
    question_class: int
    #: Offset just past the end of the question section.
    question_end: int
    raw: bytes


def parse_query(data: bytes) -> Optional[DnsQuery]:
    """Parse the header and first question of a DNS message.

    Returns None on any malformation — a filter must never crash on
    hostile input.
    """
    length = len(data)
    if length < HEADER_SIZE:
        return None
    qid = _u16(data, 0)
    flags = _u16(data, 2)
    qd_count = _u16(data, 4)
    if qd_count < 1:
        return None
    result = _read_name(data, HEADER_SIZE, length)
    if result is None:
        return None
    name, after_name = result
    if after_name + 4 > length:
        return None
    return DnsQuery(
        id=qid,
        is_response=bool(flags & 0x8000),
        opcode=(flags >> 11) & 0x0F,
        recursion_desired=bool(flags & 0x0100),
        question_name=name,
        question_type=_u16(data, after_name),
        question_class=_u16(data, after_name + 2),
        question_end=after_name + 4,
        raw=data,
    )


def build_sinkhole_response(query: DnsQuery) -> bytes:
    """Build the sinkhole response for this query, per FILTER-SPEC.

    Only valid for queries (``is_response`` False).
    """
    if query.question_type == TYPE_A:
        rdata_length = 4
    elif query.question_type == TYPE_AAAA:
        rdata_length = 16
    else:
        rdata_length = 0
    answer_length = 12 + rdata_length if rdata_length > 0 else 0

    out = bytearray(query.question_end + answer_length)
    # Header + question, echoed from the original packet.
    out[0 : query.question_end] = query.raw[0 : query.question_end]

    # Flags: QR=1, opcode copied, RD copied, RA=1, RCODE=0 (NOERROR).
    flags = 0x8000 | 0x0080 | ((query.opcode & 0x0F) << 11)
    if query.recursion_desired:
        flags |= 0x0100
    out[2:4] = flags.to_bytes(2, "big")

    # Counts: one question; one answer for A/AAAA, none otherwise.
    out[4:6] = (1).to_bytes(2, "big")
    out[6:8] = (1 if rdata_length > 0 else 0).to_bytes(2, "big")
    out[8:10] = (0).to_bytes(2, "big")
    out[10:12] = (0).to_bytes(2, "big")

    if rdata_length > 0:
        p = query.question_end
        # Name: compression pointer back to the question name at 12.
        out[p] = 0xC0
        out[p + 1] = 0x0C
        p += 2
        out[p : p + 2] = query.question_type.to_bytes(2, "big")
        p += 2
        out[p : p + 2] = CLASS_IN.to_bytes(2, "big")
        p += 2
        out[p : p + 4] = SINKHOLE_TTL_SECONDS.to_bytes(4, "big")
        p += 4
        out[p : p + 2] = rdata_length.to_bytes(2, "big")
        # RDATA stays all zeros: 0.0.0.0 for A, :: for AAAA.
    return bytes(out)
