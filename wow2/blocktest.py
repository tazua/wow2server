#!/usr/bin/env python3
"""F19 -- does a BLOCK actually stop an invite? Six checks, no emulator.

    .venv/bin/python tools/blocktest.py            # the suite
    .venv/bin/python tools/blocktest.py --revert   # WOW2_NO_BLOCK_GUARD=1
    .venv/bin/python tools/blocktest.py --keep     # leave the scratch dir
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import bdproto as bd                                        # noqa: E402
from lsgauth import (Peer, bufsize_announce, lsg_connect, login,  # noqa: E402
                     ticket_key, tiger192)

PORT = 3875
TITLE_ID = 0x0
ACCOUNTS = ["alice1", "bob222", "carol3"]
PASSWORD = "246813"
CLAN_ID = 0xC1A0C1A0C1A0C1A0
CLAN_NAME = "blockclan"


# --------------------------------------------------------------- request bodies
def _rpc(service: int, op: int) -> bd.BdWriter:
    """The writer for a parameterised RPC: service byte, tc bit, op, and the
    [u8 0] lead-in every RPC carries. `Console.send()` encrypts it.
    """
    w = bd.BdWriter()
    w.bitmode = True
    w.type_checked = False
    w.u8(service)
    w.write_bits(b"\x01", 1)
    w.type_checked = True
    w.u8(op)
    w.u8(0)
    return w


def req_block(target: int, flag: int) -> bytes:
    """Friends op 6 -- [u8 0][u64 entity][u8 flag]. 1 blocks, 0 unblocks."""
    w = _rpc(9, 6)
    w.u64(target)
    w.u8(flag)
    return w.getvalue()


def req_buddy_invite(target: int) -> bytes:
    """Friends op 1 -- [u8 0][u64 target]."""
    w = _rpc(9, 1)
    w.u64(target)
    return w.getvalue()


def req_match_invite(target: int, session_id: bytes) -> bytes:
    """Friends op 8 -- [u8 0][u64 target][blob 8B session id]."""
    w = _rpc(9, 8)
    w.u64(target)
    w.blob(session_id)
    return w.getvalue()


def req_clan_invite(team_id: int, target: int) -> bytes:
    """Teams op 6 -- [u8 0][u64 teamId][u64 target]. Team FIRST."""
    w = _rpc(3, 6)
    w.u64(team_id)
    w.u64(target)
    return w.getvalue()


def encrypt_rpc(key: bytes, seed: int, payload: bytes) -> bytes:
    """Frame `payload` the way a console sends a service RPC (§60): [u8 1][u32 seed]
    then 3DES-CBC under the session key, padded with the seed's low byte."""
    from authserver import session_cbc_encrypt, tiger_iv
    plain = struct.pack("<I", 0) + payload
    plain += bytes([seed & 0xFF]) * ((-len(plain)) % 8)
    body = b"\x01" + struct.pack("<I", seed) + session_cbc_encrypt(plain, key, tiger_iv(seed))
    return struct.pack("<I", len(body)) + body


# ------------------------------------------------------------------- the peers
class Console:
    """A signed-in LSG connection that can send service RPCs."""

    def __init__(self, host: str, port: int, account: str):
        self.account = account
        self.entity = int.from_bytes(tiger192(account.encode())[:8], "little")
        ticket, proof = login(host, port, account)
        self.key = ticket_key(ticket, PASSWORD)
        if self.key is None:
            raise SystemExit(f"{account}: the password does not open the ticket")
        self.seed = 0x1000 + (self.entity & 0xFFFF)
        self.p = Peer(host, port)
        self.p.send(bufsize_announce())
        self.p.send(lsg_connect(proof))
        if not self.p.frames(timeout=3.0):
            raise SystemExit(f"{account}: the server refused the LSG connect")

    def send(self, payload: bytes) -> None:
        self.seed += 1
        self.p.send(encrypt_rpc(self.key, self.seed, payload))
        self.p.frames(timeout=1.0)

    def close(self) -> None:
        self.p.close()


# ------------------------------------------------------------------ the server
def start_server(tmp: Path, revert: bool) -> subprocess.Popen:
    env = dict(os.environ,
               WOW2_PORT=str(PORT),
               WOW2_DATA_DIR=str(tmp),
               WOW2_HEXDUMPS="0",
               WOW2_LOG_LEVEL="info",
               WOW2_SHARED_PASSWORD_FALLBACK="false",
               WOW2_NO_NAT_TYPE="1")
    if revert:
        env["WOW2_NO_BLOCK_GUARD"] = "1"
    proc = subprocess.Popen([sys.executable, str(HERE / "authserver.py")],
                            env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, bufsize=1)
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", PORT), timeout=0.3).close()
            return proc
        except OSError:
            pass
        if proc.poll() is not None:
            print(proc.stdout.read())
            raise SystemExit("server died on startup")
        time.sleep(0.1)
    raise SystemExit("server never listened")


def seed(tmp: Path) -> None:
    """Three accounts with real credentials, and a clan alice1 already owns."""
    tmp.mkdir(parents=True, exist_ok=True)
    accounts, names = {}, {}
    for i, a in enumerate(ACCOUNTS):
        ent = int.from_bytes(tiger192(a.encode())[:8], "little")
        accounts[a] = {"pwhash": tiger192(PASSWORD.encode()).hex(),
                       "user_id": 200 + i,
                       "handle": tiger192(a.encode())[:8].hex(),
                       "first_seen": "2026-09-13T00:00:00",
                       "last_seen": "2026-09-13T00:00:00"}
        names[f"{ent:016x}"] = a
    (tmp / "accounts.json").write_text(json.dumps(accounts, indent=2))
    (tmp / "friends-db.json").write_text(json.dumps(
        {"names": names, "friends": [], "invites": [], "blocked": [],
         "messages": []}, indent=2))
    owner = int.from_bytes(tiger192(ACCOUNTS[0].encode())[:8], "little")
    (tmp / "teams-db.json").write_text(json.dumps(
        {"teams": {f"{CLAN_ID:016x}": {"name": CLAN_NAME,
                                       "owner": f"{owner:016x}",
                                       "members": [f"{owner:016x}"],
                                       "admins": [], "proposals": []}}},
        indent=2))


def friends(tmp: Path) -> dict:
    """The social store as the JSON file had it -- exported from the scratch
    server's own SQLite store (§66 step 4), same keys, same shapes."
    """
    import store
    conn = store.connect(tmp / store.DB_NAME)
    try:
        return store.export_friends(conn)
    finally:
        conn.close()


def teams(tmp: Path) -> dict:
    """The clan store as the JSON file had it, exported from the scratch
    server's own SQLite store (§66 step 5)."
    """
    import store
    conn = store.connect(tmp / store.DB_NAME)
    try:
        return store.export_teams(conn)
    finally:
        conn.close()


def mail_for(tmp: Path, entity: int) -> list:
    return [m for m in friends(tmp).get("messages", [])
            if m.get("to") == f"{entity:016x}"]


# ------------------------------------------------------------------- the suite
class Checks:
    def __init__(self):
        self.failed = 0
        self.total = 0

    def __call__(self, ok: bool, what: str, detail: str = "") -> None:
        print(f"{'PASS' if ok else 'FAIL'}  {what}"
              + (f"\n        {detail}" if detail and not ok else ""))
        self.total += 1
        if not ok:
            self.failed += 1


def run(tmp: Path, revert: bool) -> int:
    check = Checks()
    alice = Console("127.0.0.1", PORT, ACCOUNTS[0])
    bob = Console("127.0.0.1", PORT, ACCOUNTS[1])
    carol = Console("127.0.0.1", PORT, ACCOUNTS[2])

    print("\n-- bob blocks alice, carol blocks nobody")
    bob.send(req_block(alice.entity, 1))
    blocked = friends(tmp)["blocked"]
    check(len(blocked) == 1 and blocked[0]["who"] == f"{alice.entity:016x}",
          "the block is recorded (setup)", json.dumps(blocked))

    print("\n-- the three invites, alice -> bob (blocked) and alice -> carol (control)")
    alice.send(req_buddy_invite(bob.entity))
    alice.send(req_buddy_invite(carol.entity))
    alice.send(req_match_invite(bob.entity, (0x5701).to_bytes(8, "little")))
    alice.send(req_match_invite(carol.entity, (0x5701).to_bytes(8, "little")))
    alice.send(req_clan_invite(CLAN_ID, bob.entity))
    alice.send(req_clan_invite(CLAN_ID, carol.entity))
    time.sleep(0.4)

    bob_mail = mail_for(tmp, bob.entity)
    carol_mail = mail_for(tmp, carol.entity)
    types_b = sorted(m.get("type") for m in bob_mail)
    types_c = sorted(m.get("type") for m in carol_mail)

    check(1 not in types_b, "a BUDDY invite to someone who blocked you is dropped",
          f"bob's mailbox: {types_b}")
    check(5 not in types_b, "a MATCH invite to someone who blocked you is dropped",
          f"bob's mailbox: {types_b}")
    check(13 not in types_b, "a CLAN invite to someone who blocked you is dropped",
          f"bob's mailbox: {types_b}")

    props = teams(tmp)["teams"][f"{CLAN_ID:016x}"].get("proposals", [])
    to_bob = [p for p in props if p.get("to") == f"{bob.entity:016x}"]
    check(not to_bob, "...and leaves no clan PROPOSAL behind either",
          f"proposals: {json.dumps(props)}")

    invites = [i for i in friends(tmp)["invites"]
               if i.get("to") == f"{bob.entity:016x}"]
    check(not invites, "...and no buddy proposal behind either",
          f"invites: {json.dumps(invites)}")

    check(types_c == [1, 5, 13],
          "CONTROL: all three reach a gamer who blocked nobody",
          f"carol's mailbox: {types_c} (want [1, 5, 13])")

    for c in (alice, bob, carol):
        c.close()
    print(f"\n{'REVERTED (WOW2_NO_BLOCK_GUARD=1) -- ' if revert else ''}"
          f"{check.total - check.failed}/{check.total} checks passed")
    return check.failed


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--revert", action="store_true",
                    help="run against WOW2_NO_BLOCK_GUARD=1; the first three "
                         "checks must FAIL and the control must still pass")
    ap.add_argument("--keep", action="store_true",
                    help="leave the scratch data dir and print its path")
    a = ap.parse_args()

    tmp = Path(tempfile.mkdtemp(prefix="wow2-blocktest-"))
    seed(tmp)
    proc = start_server(tmp, a.revert)
    try:
        failed = run(tmp, a.revert)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        if a.keep:
            print(f"scratch dir kept: {tmp}")
        else:
            shutil.rmtree(tmp, ignore_errors=True)
    if a.revert:
        return 0 if failed else 1
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
