#!/usr/bin/env python3
"""Decode an LSG message body into its typed bd fields.

    tools/bddump.py --log                       # last message in the newest session log
    tools/bddump.py --log --svc 4 --op 5        # ...the last Stats op 5
    tools/bddump.py --log --all --svc 21        # every Matchmaking message
    tools/bddump.py --hex "c1dd098c 04 47c1..." # a plaintext pasted from a log
"""
import argparse, pathlib, re, sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import bdproto as bd
import serverconfig

ROOT = pathlib.Path(__file__).resolve().parent.parent

TYPE_NAMES = {
    bd.BD_NOTYPE: "notype", bd.BD_BOOL: "bool", bd.BD_SINT8: "i8",
    bd.BD_UINT8: "u8", bd.BD_WCHAR16: "wchar", bd.BD_SINT16: "i16",
    bd.BD_UINT16: "u16", bd.BD_SINT32: "i32", bd.BD_UINT32: "u32",
    bd.BD_SINT64: "i64", bd.BD_UINT64: "u64", bd.BD_RANGED_SINT32: "ranged_i32",
    bd.BD_RANGED_UINT32: "ranged_u32", bd.BD_F32: "f32", bd.BD_F64: "f64",
    bd.BD_RANGED_F32: "ranged_f32", bd.BD_STR: "str", bd.BD_USTR: "ustr",
    bd.BD_MBSTR: "mbstr", bd.BD_BLOB: "blob",
}
FIXED = {bd.BD_BOOL: 1, bd.BD_SINT8: 8, bd.BD_UINT8: 8, bd.BD_WCHAR16: 16,
         bd.BD_SINT16: 16, bd.BD_UINT16: 16, bd.BD_SINT32: 32, bd.BD_UINT32: 32,
         bd.BD_F32: 32, bd.BD_SINT64: 64, bd.BD_UINT64: 64, bd.BD_F64: 64}
SIGNED = {bd.BD_SINT8, bd.BD_SINT16, bd.BD_SINT32, bd.BD_SINT64}
UNDECODABLE = {bd.BD_RANGED_SINT32, bd.BD_RANGED_UINT32, bd.BD_RANGED_F32}


def bits_left(r: bd.BdReader) -> int:
    return (len(r.buf) - r.pos) * 8 + (8 - r.bit_offset if r.bit_offset < 8 else 0)


def read_field(r: bd.BdReader):
    """(type tag, python value) for the next field; raises at the end of the buffer."""
    import struct
    t = r._read_data_type()
    if t in FIXED:
        n = FIXED[t]
        if t == bd.BD_BOOL:
            return t, bool(r.read_bits(1)[0] & 1)
        raw = r.read_bits(n)[: n // 8]
        if t == bd.BD_F32:
            return t, struct.unpack("<f", raw)[0]
        if t == bd.BD_F64:
            return t, struct.unpack("<d", raw)[0]
        return t, int.from_bytes(raw, "little", signed=t in SIGNED)
    if t in (bd.BD_STR, bd.BD_MBSTR):
        out = bytearray()
        while True:
            c = r.read_bits(8)[0]
            if c == 0:
                break
            out.append(c)
            if len(out) > 512:
                break
        return t, bytes(out).decode("latin1")
    if t == bd.BD_USTR:
        out = []
        while True:
            c = int.from_bytes(r.read_bits(16)[:2], "little")
            if c == 0:
                break
            out.append(chr(c))
            if len(out) > 512:
                break
        return t, "".join(out)
    if t == bd.BD_BLOB:
        lt = r._read_data_type()
        if lt != bd.BD_UINT32:
            raise ValueError(f"blob length has type {lt}, expected u32")
        n = int.from_bytes(r.read_bits(32)[:4], "little")
        if n > bits_left(r) // 8:
            raise ValueError(f"blob length {n} exceeds the buffer")
        return t, bytes(r.read_bits(n * 8)[:n])
    if t in UNDECODABLE:
        raise ValueError(f"{TYPE_NAMES[t]} needs the sender's min/max -- cannot walk blind")
    raise ValueError(f"unknown data type {t}")


def walk(body: bytes, indent="  "):
    """Print every typed field of a body (the bitstream after the service byte)."""
    r = bd.BdReader(body)
    r.bitmode = True
    tc = r.read_type_checked_bit()
    print(f"{indent}type_checked={tc}")
    if not tc:
        print(f"{indent}(untyped stream -- nothing to walk without the parameter list)")
        return
    i = 0
    while bits_left(r) >= 5:
        before = bits_left(r)
        try:
            t, v = read_field(r)
        except Exception as e:
            print(f"{indent}[{i}] stopped: {e} ({before} bits left)")
            return
        if isinstance(v, bytes):
            shown = v.hex(" ")
            if len(shown) > 96:
                shown = shown[:96] + f"... ({len(v)}B)"
            shown = f"({len(v)}B) {shown}"
        elif isinstance(v, int) and not isinstance(v, bool) and v > 9:
            shown = f"{v} (0x{v:x})"
        else:
            shown = repr(v)
        print(f"{indent}[{i}] {TYPE_NAMES.get(t, t):>10s} = {shown}")
        i += 1
    rest = bits_left(r)
    if rest:
        print(f"{indent}({rest} bits of padding left)")


def decode_message(plain: bytes, raw: bool):
    if raw:
        walk(plain)
        return
    hmac = int.from_bytes(plain[:4], "little")
    svc = plain[4]
    print(f"  hmac=0x{hmac:08x} service={svc}")
    walk(plain[5:])


HEXLINE = re.compile(r"^\s{2,}[0-9a-f]{4}\s\s((?:[0-9a-f]{2} ){1,16})")


def messages_from_log(path: pathlib.Path):
    """[(service, op, plaintext)] for every decrypted client message in a log."""
    out, cur, hdr = [], None, None
    for line in path.read_text(errors="replace").splitlines():
        m = re.search(r"LSG msg: .*service=(\d+).*op=(\d+)", line)
        if m:
            hdr = (int(m.group(1)), int(m.group(2)))
            continue
        if "decrypted plaintext:" in line:
            cur = bytearray()
            continue
        if cur is not None:
            hm = HEXLINE.match(line)
            if hm:
                cur += bytes.fromhex(hm.group(1).replace(" ", ""))
                continue
            if hdr:
                out.append((hdr[0], hdr[1], bytes(cur)))
            cur, hdr = None, None
    if cur is not None and hdr:
        out.append((hdr[0], hdr[1], bytes(cur)))
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--hex", help="plaintext as hex (spaces ok)")
    ap.add_argument("--log", nargs="?", const="", help="session log (default: newest)")
    ap.add_argument("--svc", type=int, help="only this service id")
    ap.add_argument("--op", type=int, help="only this op id")
    ap.add_argument("--all", action="store_true", help="every match, not just the last")
    ap.add_argument("--raw", action="store_true",
                    help="input is a bare body (no [u32 hmac][u8 service] header)")
    args = ap.parse_args()

    if args.hex:
        decode_message(bytes.fromhex(re.sub(r"[^0-9a-fA-F]", "", args.hex)), args.raw)
        return 0
    if args.log is None:
        ap.error("give --hex or --log")
    path = (pathlib.Path(args.log) if args.log else
            max(serverconfig.DATA_DIR.glob("session-*.log"),
                key=lambda p: p.stat().st_mtime))
    msgs = messages_from_log(path)
    if args.svc is not None:
        msgs = [m for m in msgs if m[0] == args.svc]
    if args.op is not None:
        msgs = [m for m in msgs if m[1] == args.op]
    if not msgs:
        print(f"no matching encrypted messages in {path}")
        return 1
    print(f"# {path.name}: {len(msgs)} message(s)")
    for svc, op, plain in (msgs if args.all else msgs[-1:]):
        print(f"service={svc} op={op}  ({len(plain)}B plaintext)")
        decode_message(plain, args.raw)
    return 0


if __name__ == "__main__":
    sys.exit(main())
