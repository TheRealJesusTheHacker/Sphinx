"""Helpers for building raw DNS packets in tests."""
import struct


def encode_name(name: str) -> bytes:
    out = bytearray()
    for label in name.rstrip(".").split("."):
        encoded = label.encode("ascii")
        out.append(len(encoded))
        out.extend(encoded)
    out.append(0)
    return bytes(out)


def build_query(name: str, qtype: int = 1, qid: int = 0x1234, rd: bool = True) -> bytes:
    flags = 0x0100 if rd else 0x0000
    header = struct.pack(">HHHHHH", qid, flags, 1, 0, 0, 0)
    return header + encode_name(name) + struct.pack(">HH", qtype, 1)


def build_response_for(query: bytes, answers: int = 1) -> bytes:
    """A minimal valid response echoing the query's question."""
    qid = struct.unpack(">H", query[0:2])[0]
    flags = 0x8180
    header = struct.pack(">HHHHHH", qid, flags, 1, answers, 0, 0)
    question = query[12:]
    if answers == 0:
        return header + question
    answer = (
        b"\xc0\x0c"
        + struct.pack(">HHIH", 1, 1, 300, 4)
        + bytes([93, 184, 216, 34])
    )
    return header + question + answer
