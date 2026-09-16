#!/usr/bin/env python3
"""A tiny DNS server that points a console at this machine: the rig runs one
per network namespace (tools/netns.sh), a deployment runs it for real PSPs.

    wow2-nsdns --bind <ip> --answer <ip>
"""
from __future__ import annotations

import argparse
import socket
import struct
import sys
from pathlib import Path

DEFAULT_NAMES = ("worms.stun.us.demonware.net",
                 "worms.stun.eu.demonware.net",
                 "worms-180.auth.mmp3.demonware.net",
                 "worms-180.lsg.mmp3.demonware.net")


def parse_question(msg: bytes) -> tuple[str, int, int] | None:
    """(name, qtype, offset-after-question) from a DNS query, or None."""
    if len(msg) < 12:
        return None
    qdcount = struct.unpack(">H", msg[4:6])[0]
    if qdcount < 1:
        return None
    labels, off = [], 12
    while off < len(msg):
        n = msg[off]
        if n == 0:
            off += 1
            break
        if n & 0xC0:
            return None
        off += 1
        labels.append(msg[off:off + n].decode("ascii", "replace"))
        off += n
    if off + 4 > len(msg):
        return None
    qtype = struct.unpack(">H", msg[off:off + 2])[0]
    return ".".join(labels), qtype, off + 4


def build_reply(msg: bytes, qend: int, answer_ip: str | None) -> bytes:
    """Echo the question; append one A record, or return NXDOMAIN."""
    tid = msg[0:2]
    flags = 0x8180 if answer_ip else 0x8183    # QR+RD+RA, +NXDOMAIN
    ancount = 1 if answer_ip else 0
    header = tid + struct.pack(">HHHHH", flags, 1, ancount, 0, 0)
    body = msg[12:qend]
    if not answer_ip:
        return header + body
    rr = (b"\xc0\x0c"
          + struct.pack(">HHIH", 1, 1, 60, 4)
          + socket.inet_aton(answer_ip))
    return header + body + rr


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--bind", default="127.0.0.53", help="address to listen on")
    ap.add_argument("--answer", required=True, help="A record to hand out")
    ap.add_argument("--names-file",
                    help="hosts-style file of names to answer, re-read per "
                         "query so the table can be edited without a restart. "
                         "Defaults to nsdns-names beside this module, which is "
                         "what an installed copy ships.")
    args = ap.parse_args()
    if not args.names_file:
        beside = Path(__file__).resolve().parent / "nsdns-names"
        if beside.is_file():
            args.names_file = str(beside)

    def wanted() -> set:
        if args.names_file:
            try:
                out = set()
                for line in open(args.names_file):
                    line = line.split("#", 1)[0].strip()
                    if line:
                        out.update(w.lower() for w in line.split()[1:] or line.split())
                if out:
                    return out
            except OSError:
                pass
        return {n.lower() for n in DEFAULT_NAMES}

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind((args.bind, 53))
    except OSError as e:
        print(f"nsdns: cannot bind {args.bind}:53 ({e})", file=sys.stderr)
        return 1
    print(f"nsdns: {args.bind}:53 -> {args.answer} for "
          f"{', '.join(sorted(wanted()))}"
          + (f" (from {args.names_file})" if args.names_file else ""), flush=True)

    while True:
        try:
            msg, peer = s.recvfrom(2048)
        except OSError:
            continue
        q = parse_question(msg)
        if not q:
            continue
        name, qtype, qend = q
        hit = qtype == 1 and name.lower() in wanted()
        try:
            s.sendto(build_reply(msg, qend, args.answer if hit else None), peer)
        except OSError:
            pass
        print(f"nsdns: {name} ({'A' if qtype == 1 else qtype}) -> "
              f"{args.answer if hit else 'NXDOMAIN'}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
