#!/usr/bin/env python3
"""Generate small synthetic pcap fixtures for dissector edge cases that real
captures don't exercise: box.NULL in tuples, uint64 rendering, TCP reassembly of
a PDU split across segments, and the insert_arrow/nop decoders.

Frames are DLT_RAW (IPv4 + TCP, no link layer). Modern IPROTO PDUs are decoded on
the default port 3301, so the tests need no `-d` mapping. Regenerate with:

    python3 tests/gen_synthetic_pcaps.py

Output: tests/pcap/synthetic-*.pcap
"""

import os
import struct


class Ext:
    """A MsgPack extension value (e.g. MP_DATETIME type 4)."""

    def __init__(self, ext_type, data):
        self.ext_type = ext_type
        self.data = data


def mp(o):
    if isinstance(o, Ext):
        n = len(o.data)
        if n == 8:
            return b"\xd7" + bytes([o.ext_type]) + o.data  # fixext8
        if n == 16:
            return b"\xd8" + bytes([o.ext_type]) + o.data  # fixext16
        return b"\xc7" + bytes([n, o.ext_type]) + o.data  # ext8
    if o is None:
        return b"\xc0"
    if isinstance(o, bool):
        return b"\xc3" if o else b"\xc2"
    if isinstance(o, int):
        if 0 <= o <= 0x7F:
            return bytes([o])
        if -32 <= o < 0:
            return bytes([0xE0 | (o + 32)])
        if 0 <= o <= 0xFF:
            return b"\xcc" + bytes([o])
        if 0 <= o <= 0xFFFF:
            return b"\xcd" + o.to_bytes(2, "big")
        if 0 <= o <= 0xFFFFFFFF:
            return b"\xce" + o.to_bytes(4, "big")
        if 0 <= o <= 0xFFFFFFFFFFFFFFFF:
            return b"\xcf" + o.to_bytes(8, "big")
        if -128 <= o:
            return b"\xd0" + struct.pack(">b", o)
        if -32768 <= o:
            return b"\xd1" + struct.pack(">h", o)
        if -(2**31) <= o:
            return b"\xd2" + struct.pack(">i", o)
        return b"\xd3" + struct.pack(">q", o)
    if isinstance(o, str):
        b = o.encode()
        if len(b) <= 31:
            return bytes([0xA0 | len(b)]) + b
        if len(b) <= 0xFF:
            return b"\xd9" + bytes([len(b)]) + b
        if len(b) <= 0xFFFF:
            return b"\xda" + len(b).to_bytes(2, "big") + b
        return b"\xdb" + len(b).to_bytes(4, "big") + b
    if isinstance(o, list):
        if len(o) <= 15:
            h = bytes([0x90 | len(o)])
        elif len(o) <= 0xFFFF:
            h = b"\xdc" + len(o).to_bytes(2, "big")
        else:
            h = b"\xdd" + len(o).to_bytes(4, "big")
        return h + b"".join(mp(x) for x in o)
    if isinstance(o, dict):
        if len(o) <= 15:
            h = bytes([0x80 | len(o)])
        elif len(o) <= 0xFFFF:
            h = b"\xde" + len(o).to_bytes(2, "big")
        else:
            h = b"\xdf" + len(o).to_bytes(4, "big")
        return h + b"".join(mp(k) + mp(v) for k, v in o.items())
    raise TypeError(type(o))


def pdu(rtype, sync, body):
    """A modern IPROTO PDU: 0xce <u32 len> <header map> <body map>."""
    payload = mp({0x00: rtype, 0x01: sync}) + mp(body)
    return b"\xce" + len(payload).to_bytes(4, "big") + payload


def ip_checksum(hdr):
    s = 0
    for i in range(0, len(hdr), 2):
        s += (hdr[i] << 8) + hdr[i + 1]
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


def ipv4_tcp(src_ip, dst_ip, src_port, dst_port, seq, payload):
    tcp = struct.pack(
        ">HHIIBBHHH",
        src_port,
        dst_port,
        seq,
        0,  # ack
        0x50,  # data offset (5 words), no flags in this nibble
        0x18,  # PSH|ACK
        65535,  # window
        0,  # checksum (tshark does not require it for dissection)
        0,  # urgent
    )
    total = 20 + len(tcp) + len(payload)
    ip = struct.pack(
        ">BBHHHBBH4s4s",
        0x45,
        0,
        total,
        0,
        0x4000,  # DF
        64,
        6,  # TCP
        0,
        bytes(int(x) for x in src_ip.split(".")),
        bytes(int(x) for x in dst_ip.split(".")),
    )
    ip = ip[:10] + struct.pack(">H", ip_checksum(ip)) + ip[12:]
    return ip + tcp + payload


CLIENT_IP, SERVER_IP = "10.0.0.1", "10.0.0.2"
CLIENT_PORT, SERVER_PORT = 50000, 3301


class Stream:
    """Tracks per-direction TCP seq so multi-segment PDUs reassemble."""

    def __init__(self):
        self.cseq = 1000
        self.sseq = 2000
        self.frames = []

    def c2s(self, data):  # client -> server (request)
        self.frames.append(ipv4_tcp(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT, self.cseq, data))
        self.cseq += len(data)

    def s2c(self, data):  # server -> client (response)
        self.frames.append(ipv4_tcp(SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT, self.sseq, data))
        self.sseq += len(data)


def write_pcap(path, frames):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101))  # DLT_RAW
        for n, fr in enumerate(frames):
            f.write(struct.pack("<IIII", n, 0, len(fr), len(fr)))
            f.write(fr)


HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "pcap")

# IPROTO opcodes / keys
OK, SELECT, INSERT, EVAL, NOP, INSERT_ARROW = 0x00, 0x01, 0x02, 0x08, 0x0C, 0x11
PING, RAFT_CONFIRM, CHUNK = 0x40, 0x28, 0x80
SPACE_ID, TUPLE, EXPRESSION, DATA = 0x10, 0x21, 0x27, 0x30
REPLICA_ID, LSN, TERM = 0x02, 0x03, 0x53

U64_MAX = 2**64 - 1
I64_MIN_AS_U = 2**63  # 9223372036854775808, the value 0xcf 80 00 .. 00


def gen_null():
    s = Stream()
    s.c2s(pdu(INSERT, 1, {SPACE_ID: 512, TUPLE: [1, None, 3]}))  # NULL mid-tuple
    s.s2c(pdu(OK, 1, {DATA: [[1, None, 3]]}))  # NULL mid-row
    write_pcap(os.path.join(OUT, "synthetic-null.pcap"), s.frames)


def gen_uint64():
    s = Stream()
    # uint64 in a tuple (escape_call_arg path)
    s.c2s(pdu(INSERT, 1, {SPACE_ID: 512, TUPLE: [U64_MAX, I64_MIN_AS_U]}))
    # uint64 in a bare-rendered synchro body field (LSN >= 2^32): guards the
    # regression where the uint64 marker printed as "table: 0x...".
    s.c2s(pdu(RAFT_CONFIRM, 1, {REPLICA_ID: 1, LSN: 5000000000, TERM: 2}))
    # uint64 >= 2^63 in the HEADER sync (exact_uint / tvb path).
    s.c2s(pdu(PING, I64_MIN_AS_U, {}))
    write_pcap(os.path.join(OUT, "synthetic-uint64.pcap"), s.frames)


def gen_datetime():
    s = Stream()
    # MP_DATETIME (fixext8) with a NEGATIVE (pre-1970) epoch: guards the signed
    # 64-bit seconds decode.
    import struct as _s

    dt = Ext(4, _s.pack("<q", -100000000))
    s.c2s(pdu(INSERT, 1, {SPACE_ID: 512, TUPLE: [1, dt]}))
    write_pcap(os.path.join(OUT, "synthetic-datetime.pcap"), s.frames)


def gen_reassembly():
    s = Stream()
    big = pdu(EVAL, 1, {EXPRESSION: "return " + "A" * 400, TUPLE: []})
    cut = 100
    s.c2s(big[:cut])  # segment 1: partial PDU -> dissector requests more
    s.c2s(big[cut:])  # segment 2: remainder -> reassembles into one PDU
    write_pcap(os.path.join(OUT, "synthetic-reassembly.pcap"), s.frames)


def gen_misc():
    s = Stream()
    s.c2s(pdu(INSERT_ARROW, 1, {SPACE_ID: 512}))
    s.c2s(pdu(NOP, 2, {}))
    # A well-framed PDU whose payload is invalid MsgPack (0xc1 is "never used"):
    # the dissector must catch it, render a note, consume it, and carry on.
    s.c2s(b"\xce" + (1).to_bytes(4, "big") + b"\xc1")
    # A CHUNK (0x80, box.session.push) response — a wired-in response opcode.
    s.s2c(pdu(CHUNK, 1, {DATA: [["push-payload"]]}))
    # An opaque MP_EXT (type 3 = error) in a tuple -> the labelled-blob fallback.
    s.c2s(pdu(INSERT, 3, {SPACE_ID: 512, TUPLE: [Ext(3, b"abc")]}))
    write_pcap(os.path.join(OUT, "synthetic-misc.pcap"), s.frames)


if __name__ == "__main__":
    gen_null()
    gen_uint64()
    gen_datetime()
    gen_reassembly()
    gen_misc()
    print("wrote synthetic-{null,uint64,datetime,reassembly,misc}.pcap to", OUT)
