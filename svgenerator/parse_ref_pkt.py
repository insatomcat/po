#!/usr/bin/env python3
"""Parse le paquet de référence IEC 61869-9 / 61850-9-2 (2 ASDUs) et explique chaque octet."""

import struct

# Paquet de référence (hex)
REF = bytes.fromhex(
    "403000d3000000006081c8800102a281c2305f800e4c44544d315f5356495f44455033820211b88304000027108501028740"
    + "00" * 32 * 2  # 64 zeros
    + "305f800e4c44544d315f5356495f44455033820211b98304000027108501028740"
    + "00" * 32 * 2  # 64 zeros
    + "00"
)


def read_ber_tag_len(data, off):
    """Retourne (tag, length, next_offset)."""
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
    print("=== Header (8 bytes) – explication octet par octet ===\n")
    print("  Offset  Hex      Signification")
    print("  ------  -------  ----------------------------------------")
    print("  0-1     40 30    APPID (big-endian) = 0x4030")
    print("  2-3     00 d3    Length (big-endian) = 211 octets (savPdu)")
    print("  4-7     00 00 00 00  Reserved (4 octets)")
    print()

    off = 8
    print("=== savPdu (BER, après le header) ===\n")

    sav_start = off
    tag, sav_len, off = read_ber_tag_len(REF, off)
    print("  [0x60] savPdu (APPLICATION 0, tag 0x60)")
    print(f"    Octets: {REF[sav_start:off].hex()}  ->  tag=0x60, length={sav_len} (>=128 => 0x81 puis len)")
    print()

    no_start = off
    tag, no_len, off = read_ber_tag_len(REF, off)
    no_asdu = REF[off]
    off += no_len
    print("  [0x80] noASDU (INTEGER) = nombre d’ASDU")
    print(f"    Octets: {REF[no_start:off].hex()}  ->  tag=0x80, len=1, value={no_asdu}")
    print()

    seq_start = off
    tag, seq_len, off = read_ber_tag_len(REF, off)
    print("  [0xA2] seqASDU (context [2], sequence)")
    print(f"    Octets: {REF[seq_start:off].hex()}  ->  tag=0xA2, length={seq_len}")
    seq_end = off + seq_len
    print()

    for i in range(no_asdu):
        tag, asdu_len, off = read_ber_tag_len(REF, off)
        asdu_start = off - (2 if asdu_len < 128 else 3)

        print(f"  --- ASDU {i} (début offset {asdu_start}) ---")
        pre = REF[asdu_start : asdu_start + 3].hex()
        print(f"    Préfixe avant premier champ: {pre}")
        print()
        print("    Explication du préfixe « 30 XX 80 » devant chaque ASDU:")
        print("      30       = Tag ASDU (SEQUENCE, 0x30)")
        print(f"      XX      = Longueur de l’ASDU (1 octet si <128): {asdu_len} (0x{asdu_len:02x})")
        print("      80      = Tag du premier champ (svID, [0] 0x80)")
        print()
        if asdu_len == 95:
            print("    Ici XX = 0x5f (95). Réf utilise seqData 64 octets (0x87 0x40 ...).")
        elif asdu_len == 103:
            print("    Ici XX = 0x67 (103). rt_sender 6I3U utilise seqData 72 octets → +8 → 95+8=103.")
        print("    Donc « 305f80 » (réf) vs « 306780 » (rt_sender): même structure, longueur ASDU 95 vs 103.")
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
                print(f"    [0x80] svID: \"{s}\"  ({L} octets)  hex={val.hex()}")
            elif t == 0x82:
                v = struct.unpack("!H", val)[0]
                print(f"    [0x82] smpCnt: {v}  (2 octets BE)  hex={val.hex()}")
            elif t == 0x83:
                v = struct.unpack("!I", val)[0]
                print(f"    [0x83] confRev: {v}  (4 octets BE)  hex={val.hex()}")
            elif t == 0x85:
                print(f"    [0x85] smpSynch: {val[0]}  (1 octet)  hex={val.hex()}")
            elif t == 0x87:
                len_hex = f"0x{L:02x}" if L < 128 else f"0x81 0x{L:02x}"
                print(f"    [0x87] seqData: {L} octets  (tag 0x87 len {len_hex})  hex={val[:24].hex()}...")
                if L == 64:
                    print("           Ref 64 octets; rt_sender 6I3U=72 -> ASDU +8 -> 103 (0x67) vs 95 (0x5f).")

        print()

    print("--- Résumé 30 5f 80 vs 30 67 80 ---")
    print("  Réf:     30 5f 80  → ASDU length 95 (0x5f), seqData 64 octets.")
    print("  rt_sender: 30 67 80  → ASDU length 103 (0x67), seqData 72 octets (6I3U).")
    print("  Écart 8 octets = 72 - 64 (seqData).")
    print()
    print(f"Total packet: {len(REF)} bytes")
    if seq_end < len(REF):
        print(f"Octets après seqASDU: {REF[seq_end:].hex()!r}")


if __name__ == "__main__":
    main()
