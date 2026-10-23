# Copyright (C) 2026 dondch (gpl-3.0-or-later)
"""Decoder tests for rfcat_wmbus, driven by telegrams with their DLL CRCs still inside
(from wmbusmeters' simulations/simulation_dll_crcs.txt) and a telegram captured off the air
with an RfCat Chronos dongle."""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "wmbusmeters-ha-addon-edge"))

import rfcat_wmbus as rw

# wmbusmeters simulation_dll_crcs.txt: format A telegram, CRCs after the 10 byte header and each 16 byte block.
A_WITH_CRCS = bytes.fromhex(
    "3444EE4D813929271608" "811D" "7A51000000046D1912A62B036E000000" "5170"
    "426CE1F1436E00000002FF2C00000259" "D6D0" "D4090265FC0902FD66A000" "44C4")
A_PAYLOAD = bytes.fromhex(
    "3444EE4D813929271608" "7A51000000046D1912A62B036E000000"
    "426CE1F1436E00000002FF2C00000259" "D4090265FC0902FD66A000")

# Received 2026-10-23 on mini from an EFE heat cost allocator (T1, unencrypted, CRCs removed).
EFE_PAYLOAD = bytes.fromhex(
    "2d44c5149964014331087a330000202f2f046d0435573a036e040000426c413a436e000000317f00346d00200000")

ENCODE_3OF6 = {v: k for k, v in rw.THREE_OF_SIX.items()}


def with_format_a_crcs(payload):
    out = bytearray(payload[:10]) + rw.crc16(payload[:10]).to_bytes(2, "big")
    for pos in range(10, len(payload), 16):
        block = payload[pos:pos + 16]
        out += block + rw.crc16(block).to_bytes(2, "big")
    return bytes(out)


def encode_3of6(data):
    bits = "".join(f"{ENCODE_3OF6[n]:06b}" for b in data for n in (b >> 4, b & 0xF))
    bits += "0" * (-len(bits) % 8)
    return bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))


def encode_manchester(data, one="10"):
    zero = "01" if one == "10" else "10"
    bits = "".join(one if c == "1" else zero for b in data for c in f"{b:08b}")
    return bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))


def test_crc16_matches_wmbusmeters_vectors():
    assert rw.crc16(A_WITH_CRCS[:10]) == 0x811D
    assert rw.crc_ok(A_WITH_CRCS[:12])
    assert with_format_a_crcs(A_PAYLOAD) == A_WITH_CRCS


def test_format_a_strips_crcs():
    assert rw.parse_format_a(A_WITH_CRCS) == (A_PAYLOAD, True)


def test_format_a_damaged_tail_reports_incomplete():
    damaged = bytearray(A_WITH_CRCS)
    damaged[-1] ^= 0xFF
    payload, complete = rw.parse_format_a(bytes(damaged))
    assert complete is False
    assert payload == A_PAYLOAD[:42]


def test_format_a_bad_header_is_rejected():
    damaged = bytearray(A_WITH_CRCS)
    damaged[3] ^= 0x01
    assert rw.parse_format_a(bytes(damaged)) is None


def test_t1_three_of_six_roundtrip_with_trailing_noise():
    raw = encode_3of6(with_format_a_crcs(EFE_PAYLOAD)) + bytes(range(0, 200))
    frame = rw.decode_tc(raw[:255])
    assert frame == rw.Frame("T1", EFE_PAYLOAD, True)
    assert rw.meter_id(frame.payload) == "43016499"


def test_c1_format_a():
    raw = b"\x54\xCD" + A_WITH_CRCS + b"\x00" * 50
    assert rw.decode_tc(raw) == rw.Frame("C1", A_PAYLOAD, True)


def test_c1_format_b():
    body = A_PAYLOAD[:40]
    length = len(body) + 1  # the L field counts the CRC as well in format B
    frame_b = bytes([length]) + body[1:]
    frame_b += rw.crc16(frame_b).to_bytes(2, "big")
    raw = b"\x54\x3D" + frame_b + b"\xAA" * 20
    assert rw.decode_tc(raw) == rw.Frame("C1", bytes([length]) + body[1:], True)


def test_s1_manchester_both_polarities():
    for one in ("10", "01"):
        raw = encode_manchester(with_format_a_crcs(A_PAYLOAD), one) + b"\x00" * 30
        assert rw.decode_s(raw) == rw.Frame("S1", A_PAYLOAD, True)


def test_noise_decodes_to_nothing():
    assert rw.decode_tc(bytes(255)) is None
    assert rw.decode_tc(bytes([0xFF] * 255)) is None
    assert rw.decode_s(bytes([0x55] * 100)) is None


def test_rssi_conversion():
    assert rw.rssi_dbm(0x80) == -138
    assert rw.rssi_dbm(0x00) == -74
    assert rw.rssi_dbm(0x14) == -64


def test_line_format_is_what_wmbusmeters_parses():
    when = time.mktime((2026, 10, 23, 21, 4, 0, 0, 0, -1))
    line = rw.format_line(rw.Frame("T1", EFE_PAYLOAD, True), when, rssi=-71.5)
    assert line == ("T1;1;1;2026-10-23 21:04:00.000;-72;;43016499;0x" + EFE_PAYLOAD.hex())
    line = rw.format_line(rw.Frame("C1", A_PAYLOAD, False), when)
    assert line.startswith("C1;0;1;2026-10-23 21:04:00.000;;;27293981;0x3444ee4d")


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
    print(f"{len(tests)} rfcat_wmbus tests passed")
