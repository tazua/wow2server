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
import time
from pathlib import Path

DEFAULT_NAMES = ("worms.stun.us.demonware.net",
                 "worms.stun.eu.demonware.net",
                 "worms-180.auth.mmp3.demonware.net",
                 "worms-180.lsg.mmp3.demonware.net")
REPLIES_PER_ADDRESS = 60
REPLIES_TOTAL = 3000
_minute: list = [0.0, 0, {}, 0]


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


def build_reply(msg: bytes, qend: int, served: bool, answer_ip: str | None) -> bytes:
    """Echo the question. A name we serve is answered authoritatively, with one
    A record or, for another type, none; any other name is NXDOMAIN. RD is the
    query's; RA stays set, because to a console this IS its resolver (§80y)."""
    rd = (msg[2] & 0x01) << 8
    flags = (0x8480 | rd) if served else (0x8083 | rd)
    ancount = 1 if served and answer_ip else 0
    header = msg[0:2] + struct.pack(">HHHHH", flags, 1, ancount, 0, 0)
    body = msg[12:qend]
    if not ancount:
        return header + body
    rr = (b"\xc0\x0c"
          + struct.pack(">HHIH", 1, 1, 60, 4)
          + socket.inet_aton(answer_ip))
    return header + body + rr


def is_query(msg: bytes) -> bool:
    """A standard query: not a response (QR) and opcode QUERY."""
    return len(msg) >= 12 and not msg[2] & 0x80 and not (msg[2] >> 3) & 0x0F


def reply_due(ip: str, now: float | None = None) -> bool:
    """A reply goes to whatever source a datagram claims, so they have a budget:
    REPLIES_PER_ADDRESS a minute an address and REPLIES_TOTAL in all (§80y)."""
    now = time.time() if now is None else now
    m = _minute
    if now - m[0] >= 60.0:
        if m[3]:
            print(f"nsdns: {m[3]} queries over the reply budget last minute went "
                  f"unanswered", flush=True)
        m[0], m[1], m[2], m[3] = now, 0, {}, 0
    if m[1] >= REPLIES_TOTAL or m[2].get(ip, 0) >= REPLIES_PER_ADDRESS:
        m[3] += 1
        return False
    m[1] += 1
    m[2][ip] = m[2].get(ip, 0) + 1
    return True


def respond(msg: bytes, peer_ip: str, wanted, answer_ip: str,
            now: float | None = None) -> tuple[bytes, str] | None:
    """(reply, what it says) for one datagram, or None for no reply at all.
    `wanted` is the set of names served, or what returns it."""
    if not is_query(msg) or not reply_due(peer_ip, now):
        return None
    q = parse_question(msg)
    if not q:
        return None
    name, qtype, qend = q
    served = name.lower() in (wanted() if callable(wanted) else wanted)
    hit = served and qtype == 1
    reply = build_reply(msg, qend, served, answer_ip if hit else None)
    return reply, (f"{name} ({'A' if qtype == 1 else qtype}) -> "
                   + (answer_ip if hit else "no record" if served else "NXDOMAIN"))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--bind", default="127.0.0.53", help="address to listen on")
    ap.add_argument("--port", type=int, default=53, help="UDP port (53; another for a test)")
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
        s.bind((args.bind, args.port))
    except OSError as e:
        print(f"nsdns: cannot bind {args.bind}:{args.port} ({e})", file=sys.stderr)
        return 1
    print(f"nsdns: {args.bind}:{args.port} -> {args.answer} for "
          f"{', '.join(sorted(wanted()))}"
          + (f" (from {args.names_file})" if args.names_file else ""), flush=True)

    while True:
        try:
            msg, peer = s.recvfrom(2048)
        except OSError:
            continue
        out = respond(msg, peer[0], wanted, args.answer)
        if out is None:
            continue
        try:
            s.sendto(out[0], peer)
        except OSError:
            pass
        print(f"nsdns: {out[1]}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
