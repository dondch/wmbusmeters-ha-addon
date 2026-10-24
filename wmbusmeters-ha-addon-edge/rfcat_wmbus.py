#!/usr/bin/env python3
# Copyright (C) 2026 dondch (gpl-3.0-or-later)
"""Wireless M-Bus receiver for RfCat dongles (CC1111: YARD Stick One, Chronos, EMK).

Prints one line per telegram in the rtl_wmbus format, so wmbusmeters reads it with

    device=rtlwmbus:CMD(rfcat_wmbus tc)

    MODE;CRC_OK;3OUTOF6_OK;TIMESTAMP;PACKET_RSSI;CURRENT_RSSI;ID;0xTELEGRAM_WITHOUT_CRCS

usage: rfcat_wmbus [tc|s] [--pktlen N]

tc listens on 868.95 MHz for T1 and C1 telegrams (the common case), s on 868.3 MHz for S1.
Exit status 3 means the dongle stopped delivering packets; the caller restarts the receiver
and the next start drains the dongle, which is what unblocks its firmware.
"""
import argparse
import collections
import os
import sys
import threading
import time

Frame = collections.namedtuple("Frame", "mode payload complete")
RadioProfile = collections.namedtuple("RadioProfile", "freq drate sync registers")

# Receiver tuning for 100 kbps T/C mode from TI AN067 (T-mode meters run fast and drift).
TC_REGISTERS = (("FSCTRL1", 0x08), ("FOCCFG", 0x2E), ("BSCFG", 0x6D),
                ("AGCCTRL2", 0x43), ("AGCCTRL1", 0x09), ("AGCCTRL0", 0xB5))

PROFILES = {
    "tc": RadioProfile(freq=868_950_000, drate=103_000, sync=0x543D, registers=TC_REGISTERS),
    "s": RadioProfile(freq=868_300_000, drate=32_768, sync=0x7696, registers=()),
}

THREE_OF_SIX = {
    0x16: 0x0, 0x0D: 0x1, 0x0E: 0x2, 0x0B: 0x3, 0x1C: 0x4, 0x19: 0x5,
    0x1A: 0x6, 0x13: 0x7, 0x2C: 0x8, 0x25: 0x9, 0x26: 0xA, 0x23: 0xB,
    0x34: 0xC, 0x31: 0xD, 0x32: 0xE, 0x29: 0xF,
}

RFCAT_IDS = {(0x1D50, 0x6047), (0x1D50, 0x6048), (0x1D50, 0x605B), (0x1D50, 0xECC1), (0x0451, 0x4715)}
EP5_IN, EP5_OUT = 0x85, 5
SET_IDLE = b"\xff\x88\x01\x00\x04"  # APP_SYSTEM, SYS_CMD_RFMODE, len=1, RFST_SIDLE

# Noise matches the sync word every few seconds, so a longer silence means the dongle is stuck.
STALL_SECONDS = 60
# A counter line on stderr this often; wmbusmeters shows it at loglevel debug.
STATS_SECONDS = 300
# The dongle can reboot (it then re-enumerates with default radio settings) and rflib reconnects
# to it without a word, so the configuration is read back this often.
VERIFY_SECONDS = 60


def crc16(data):
    crc = 0
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x3D65) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc ^ 0xFFFF


def crc_ok(block):
    return len(block) > 2 and crc16(block[:-2]) == (block[-2] << 8 | block[-1])


def decode_3of6(raw):
    """Decode until the first invalid symbol; returns the bytes recovered."""
    bits = "".join(f"{b:08b}" for b in raw)
    nibbles = []
    for i in range(0, len(bits) - 5, 6):
        n = THREE_OF_SIX.get(int(bits[i:i + 6], 2))
        if n is None:
            break
        nibbles.append(n)
    return bytes(nibbles[i] << 4 | nibbles[i + 1] for i in range(0, len(nibbles) - 1, 2))


def decode_manchester(raw, one):
    bits = "".join(f"{b:08b}" for b in raw)
    out = []
    for i in range(0, len(bits) - 1, 2):
        pair = bits[i:i + 2]
        if pair not in ("01", "10"):
            break
        out.append("1" if pair == one else "0")
    s = "".join(out)
    return bytes(int(s[i:i + 8], 2) for i in range(0, len(s) - 7, 8))


def parse_format_a(data):
    """Frame format A: a 10 byte block and 16 byte blocks, each followed by its CRC.
    Returns (payload without CRCs, complete) or None when the first block is bad."""
    if len(data) < 12 or data[0] < 9 or not crc_ok(data[:12]):
        return None
    payload = bytearray(data[:10])
    pos, remaining = 12, data[0] - 9
    while remaining > 0:
        n = min(16, remaining)
        block = data[pos:pos + n + 2]
        if len(block) < n + 2 or not crc_ok(block):
            return bytes(payload), False
        payload += block[:-2]
        pos += n + 2
        remaining -= n
    return bytes(payload), True


def parse_format_b(data):
    """Frame format B: one CRC after the first 128 bytes and one after the rest."""
    if len(data) < 12 or data[0] < 11:
        return None
    total = data[0] + 1
    if len(data) < total:
        return None
    first = min(total, 128)
    if not crc_ok(data[:first]):
        return None
    payload = bytearray(data[:first - 2])
    if total > 128:
        if not crc_ok(data[128:total]):
            return bytes(payload), False
        payload += data[128:total - 2]
    return bytes(payload), True


def decode_tc(raw):
    """Raw bytes after the 0x543D sync word on 868.95 MHz: C mode announces itself with a
    second sync word, everything else is tried as 3-of-6 coded T mode."""
    if raw[:2] == b"\x54\xCD":
        r = parse_format_a(raw[2:])
        return Frame("C1", *r) if r else None
    if raw[:2] == b"\x54\x3D":
        r = parse_format_b(raw[2:])
        return Frame("C1", *r) if r else None
    r = parse_format_a(decode_3of6(raw))
    return Frame("T1", *r) if r else None


def decode_s(raw):
    for one in ("10", "01"):
        r = parse_format_a(decode_manchester(raw, one))
        if r:
            return Frame("S1", *r)
    return None


DECODERS = {"tc": decode_tc, "s": decode_s}


def meter_id(payload):
    return payload[4:8][::-1].hex()


def rssi_dbm(status_byte):
    """CC1111 RSSI status byte to dBm (offset for 868 MHz from the data sheet)."""
    v = status_byte - 256 if status_byte >= 128 else status_byte
    return v / 2 - 74


def format_line(frame, when, rssi=None):
    """One rtl_wmbus line. Length byte first, then no CRCs, which is what wmbusmeters expects."""
    stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(when)) + ".000"
    rssi_s = "" if rssi is None else f"{rssi:.0f}"
    return f"{frame.mode};{int(frame.complete)};1;{stamp};{rssi_s};;{meter_id(frame.payload)};0x{frame.payload.hex()}"


LOG_FILE = os.environ.get("RFCAT_WMBUS_LOG", "/data/rfcat_wmbus.log" if os.path.isdir("/data") else "")


def log(msg):
    """stderr reaches wmbusmeters (shown at loglevel debug); the file keeps a record regardless."""
    print(f"(rfcat_wmbus) {msg}", file=sys.stderr, flush=True)
    if LOG_FILE:
        try:
            with open(LOG_FILE, "a") as f:
                f.write(time.strftime("%Y-%m-%d %H:%M:%S ") + msg + "\n")
        except OSError:
            pass


def drain_dongle():
    """Read endpoint 5 before rflib opens the dongle.

    The firmware's txdata() spins until the host collects every chunk of a packet, and it only
    answers control requests from that same loop. rflib needs a control request before it starts
    reading, so after a crash or restart the two wait on each other forever unless the pending
    packet is drained first."""
    import usb

    devs = [d for bus in usb.busses() for d in bus.devices if (d.idVendor, d.idProduct) in RFCAT_IDS]
    if not devs:
        return False
    handle = devs[0].open()
    try:
        handle.claimInterface(0)
        got, end = 0, time.time() + 1.5
        while time.time() < end:
            try:
                got += len(handle.bulkRead(EP5_IN, 512, 200))
            except usb.USBError:
                pass
        if got:
            log(f"drained {got} bytes left in the dongle")
            try:
                handle.bulkWrite(EP5_OUT, SET_IDLE, 1000)
            except usb.USBError:
                pass
        handle.releaseInterface()
    finally:
        del handle
    return True


def open_dongle():
    import usb
    from rflib import RfCat, RFST_SIDLE

    d = RfCat(RfMode=RFST_SIDLE)
    read_ep5 = d._recvEP5

    def read_ep5_tolerant(timeout=100):
        # rflib re-opens the device on a USB I/O error and the blocked firmware cannot answer
        # that; treating the error as an empty read keeps the packet flow alive.
        try:
            return read_ep5(timeout=timeout)
        except usb.USBError as e:
            if "Input/output error" not in repr(e):
                raise
            return b""

    d._recvEP5 = read_ep5_tolerant
    return d


def configure(d, profile, pktlen):
    import rflib

    d.setModeIDLE()
    d.setMdmModulation(rflib.MOD_2FSK)
    d.setMdmDeviatn(50_000)
    d.setMdmChanBW(325_000)
    d.setEnablePktCRC(False)
    d.setEnablePktDataWhitening(False)
    d.setEnableMdmManchester(False)
    d.setPktPQT(0)
    # RSSI and LQI follow each packet; the stock firmware drops them, a patched one forwards them.
    d.setEnablePktAppendStatus(True)
    d.setMdmSyncMode(rflib.SYNCM_16_of_16)
    d.makePktFLEN(pktlen)
    d.setFreq(profile.freq)
    d.setMdmDRate(profile.drate)
    d.setMdmSyncWord(profile.sync)
    for name, value in profile.registers:
        d.setRFRegister(getattr(rflib, name), value)
    d.setModeRX()


def config_mismatches(d, profile, pktlen):
    """Read the radio configuration back and list what differs from what was asked.

    Every setting goes through the dongle as a separate USB round trip; a reply lost or
    misparsed on the way leaves a radio that receives noise but never a telegram."""
    import rflib

    d.getRadioConfig()
    cfg = d.radiocfg
    expected = [
        ("sync word", f"0x{profile.sync:04X}", f"0x{d.getMdmSyncWord(cfg):04X}"),
        ("sync mode", rflib.SYNCM_16_of_16, d.getMdmSyncMode(cfg)),
        ("modulation", rflib.MOD_2FSK, d.getMdmModulation(cfg)),
        ("packet length", (pktlen & 0xFF, 0), d.getPktLEN()),
        ("append status", 1, d.getEnablePktAppendStatus(cfg)),
    ]
    for name, value in profile.registers:
        expected.append((name, value, getattr(cfg, name.lower())))
    within = [
        ("frequency", profile.freq, d.getFreq(radiocfg=cfg)[0], 0.001),
        ("data rate", profile.drate, d.getMdmDRate(radiocfg=cfg), 0.05),
        ("deviation", 50_000, d.getMdmDeviatn(radiocfg=cfg), 0.1),
    ]
    bad = [f"{n}: wanted {w}, got {g}" for n, w, g in expected if w != g]
    bad += [f"{n}: wanted {w}, got {g:.0f}" for n, w, g, tol in within if abs(g - w) > tol * w]
    return bad


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("mode", nargs="?", default="tc", choices=sorted(PROFILES))
    ap.add_argument("--pktlen", type=int, default=255,
                    help="encoded bytes captured after the sync word (default 255)")
    args = ap.parse_args(argv)

    if not drain_dongle():
        log("no RfCat dongle on the USB bus")
        return 1

    last_packet = time.time()

    def watchdog():
        while True:
            time.sleep(5)
            if time.time() - last_packet > STALL_SECONDS:
                log(f"no packets for {STALL_SECONDS}s, dongle stalled, exiting")
                sys.stdout.flush()
                os._exit(3)

    threading.Thread(target=watchdog, daemon=True).start()

    from rflib import ChipconUsbTimeoutException

    d = open_dongle()
    profile = PROFILES[args.mode]
    configure(d, profile, args.pktlen)
    bad = config_mismatches(d, profile, args.pktlen)
    if bad:
        log("radio configuration did not apply, exiting: " + "; ".join(bad))
        return 2
    decode = DECODERS[args.mode]
    log(f"listening mode={args.mode} freq={d.getFreq()[0] / 1e6:.3f}MHz drate={d.getMdmDRate():.0f} pktlen={args.pktlen}")

    stats = collections.Counter()
    next_stats = time.time() + STATS_SECONDS
    next_verify = time.time() + VERIFY_SECONDS
    usb_handle = d._do
    while True:
        now = time.time()
        if d._do is not usb_handle:
            # rflib re-opened the dongle after a USB error, which it only reports on stderr
            log(f"rflib reconnected to the dongle; mode {d.getMARCSTATE()}")
            usb_handle = d._do
        if now >= next_stats:
            log(f"last {STATS_SECONDS}s: {stats['sync']} sync matches, {stats['telegram']} telegrams, "
                f"{stats['partial']} with a damaged tail; dongle {d.reprDebugCodes().replace(chr(10), ', ')}")
            stats.clear()
            next_stats = now + STATS_SECONDS
        if now >= next_verify:
            try:
                bad = config_mismatches(d, profile, args.pktlen)
            except ChipconUsbTimeoutException:
                bad = ["dongle did not answer"]
            if bad:
                log("radio configuration lost, exiting: " + "; ".join(bad))
                return 2
            next_verify = now + VERIFY_SECONDS
        try:
            raw, _ = d.RFrecv(timeout=1000, blocksize=args.pktlen if args.pktlen > 255 else None)
        except ChipconUsbTimeoutException:
            continue
        last_packet = time.time()
        stats["sync"] += 1
        frame = decode(raw)
        if frame is None:
            continue
        stats["telegram" if frame.complete else "partial"] += 1
        # The stock firmware forwards exactly pktlen bytes and the RSSI field stays empty; a
        # patched one appends the RSSI and LQI status bytes.
        rssi = rssi_dbm(raw[args.pktlen]) if len(raw) >= args.pktlen + 2 else None
        raw = raw[:args.pktlen]
        line = format_line(frame, last_packet, rssi)
        print(line, flush=True)
        log("emitted " + line[:60])


if __name__ == "__main__":
    try:
        rc = main()
    except KeyboardInterrupt:
        rc = 0
    sys.stdout.flush()
    # rflib's USB threads crash inside libusb during interpreter teardown; skip teardown.
    os._exit(rc)
