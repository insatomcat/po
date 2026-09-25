#!/usr/bin/env python3
# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""Decode the IEC 61869-9 / 61850-9-2 reference frame (2 ASDUs) and explain every byte."""

import struct

# Reference frame (hex)
REF = bytes.fromhex(
    "403000d3000000006081c8800102a281c2305f800e49454430315f4d5530315f535631820211b88304000027108501028740"
    + "00" * 32 * 2  # 64 zeros
    + "305f800e49454430315f4d5530315f535631820211b98304000027108501028740"
    + "00" * 32 * 2  # 64 zeros
    + "00"
)


def read_ber_tag_len(data, off):
    """(tag, length, next_offset)."""
    if off >= len(data):
        return None, 0, off
    tag = data[off]
    off += 1
    L = data[off]
    off += 1
    if L & 0x80:
        n = L & 0x7F
        L = 0
        for _ in range(n):
            L = (L << 8) | data[off]
            off += 1
    return tag, L, off


def main():
    print("=== Header (8 bytes) – explication byte par byte ===\n")
    print("  Offset  Hex      Signification")
    print("  ------  -------  ----------------------------------------")
    print("  0-1     40 30    APPID (big-endian) = 0x4030")
    print("  2-3     00 d3    Length (big-endian) = 211 bytes (savPdu)")
    print("  4-7     00 00 00 00  Reserved (4 bytes)")
    print()

    off = 8
    print("=== savPdu (BER, after the header) ===\n")

    sav_start = off
    tag, sav_len, off = read_ber_tag_len(REF, off)
    print("  [0x60] savPdu (APPLICATION 0, tag 0x60)")
    print(f"    Bytes: {REF[sav_start:off].hex()}  ->  tag=0x60, length={sav_len} (>=128 => 0x81 then len)")
    print()

    no_start = off
    tag, no_len, off = read_ber_tag_len(REF, off)
    no_asdu = REF[off]
    off += no_len
    print("  [0x80] noASDU (INTEGER) = number of ASDUs")
    print(f"    Bytes: {REF[no_start:off].hex()}  ->  tag=0x80, len=1, value={no_asdu}")
    print()

    seq_start = off
    tag, seq_len, off = read_ber_tag_len(REF, off)
    print("  [0xA2] seqASDU (context [2], sequence)")
    print(f"    Bytes: {REF[seq_start:off].hex()}  ->  tag=0xA2, length={seq_len}")
    seq_end = off + seq_len
    print()

    for i in range(no_asdu):
        tag, asdu_len, off = read_ber_tag_len(REF, off)
        asdu_start = off - (2 if asdu_len < 128 else 3)

        print(f"  --- ASDU {i} (starts at offset {asdu_start}) ---")
        pre = REF[asdu_start : asdu_start + 3].hex()
        print(f"    Prefix before the first field: {pre}")
        print()
        print("    The \"30 XX 80\" prefix in front of each ASDU:")
        print("      30       = Tag ASDU (SEQUENCE, 0x30)")
        print(f"      XX      = ASDU length (1 byte when < 128): {asdu_len} (0x{asdu_len:02x})")
        print("      80      = tag of the first field (svID, [0] 0x80)")
        print()
        if asdu_len == 95:
            print("    Here XX = 0x5f (95). The reference uses a 64-byte seqData (0x87 0x40 ...).")
        elif asdu_len == 103:
            print("    Here XX = 0x67 (103). rt_sender 6I3U uses a 72-byte seqData: 95 + 8 = 103.")
        print("    So 305f80 (reference) and 306780 (rt_sender) share the structure; ASDU length 95 vs 103.")
        print()

        asdu_end = off + asdu_len
        while off < asdu_end:
            start = off
            t, L, off = read_ber_tag_len(REF, off)
            val = REF[off : off + L]
            val_hex = val.hex() if L <= 8 else val[:4].hex() + "..." + val[-4:].hex()
            off += L
            if t == 0x80:
                s = val.decode("utf-8")
                print(f"    [0x80] svID: \"{s}\"  ({L} bytes)  hex={val.hex()}")
            elif t == 0x82:
                v = struct.unpack("!H", val)[0]
                print(f"    [0x82] smpCnt: {v}  (2 bytes BE)  hex={val.hex()}")
            elif t == 0x83:
                v = struct.unpack("!I", val)[0]
                print(f"    [0x83] confRev: {v}  (4 bytes BE)  hex={val.hex()}")
            elif t == 0x85:
                print(f"    [0x85] smpSynch: {val[0]}  (1 byte)  hex={val.hex()}")
            elif t == 0x87:
                len_hex = f"0x{L:02x}" if L < 128 else f"0x81 0x{L:02x}"
                print(f"    [0x87] seqData: {L} bytes  (tag 0x87 len {len_hex})  hex={val[:24].hex()}...")
                if L == 64:
                    print("           Ref 64 bytes; rt_sender 6I3U=72 -> ASDU +8 -> 103 (0x67) vs 95 (0x5f).")

        print()

    print("--- Summary: 30 5f 80 vs 30 67 80 ---")
    print("  Reference: 30 5f 80  → ASDU length 95 (0x5f), seqData 64 bytes.")
    print("  rt_sender: 30 67 80  → ASDU length 103 (0x67), seqData 72 bytes (6I3U).")
    print("  Difference 8 bytes = 72 - 64 (seqData).")
    print()
    print(f"Total packet: {len(REF)} bytes")
    if seq_end < len(REF):
        print(f"Bytes after seqASDU: {REF[seq_end:].hex()!r}")


if __name__ == "__main__":
    main()
