#!/usr/bin/env python3
"""How many players? N synthetic consoles sign in at the same instant and each
runs the game's own sign-in burst, a match start and two heavier calls,
against a store pre-filled for L lifetime players. Its own server on 3877.

    .venv/bin/python tools/loadtest.py --consoles 32 --lifetime 200
    .venv/bin/python tools/loadtest.py --consoles 128 --lifetime 200   # concurrency
    .venv/bin/python tools/loadtest.py --consoles 32 --lifetime 10000  # store size
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))
import bdproto as bd                                   # noqa
from lsgauth import tiger192                           # noqa
import blocktest, ownertest                            # noqa
from ownertest import Console, req_stats_read, req_storage_upload  # noqa
from blocktest import _rpc, PASSWORD                   # noqa

PORT = 3877


class FastConsole(Console):
    """ownertest's peer returns after a 0.3 s silence; this returns on the reply."""

    def call(self, payload, timeout=8.0):
        self.seed += 1
        self.p.send(blocktest.encrypt_rpc(self.key, self.seed, payload))
        deadline = time.time() + timeout
        pending = []
        while time.time() < deadline:
            got = self.p.frames(timeout=min(1.0, max(0.05, deadline - time.time())))
            pending += got
            err, r = ownertest.task_reply(pending, self.key)
            if r is not None:
                return err, r
            if getattr(self.p, "closed", False):
                return None, None
        return None, None


def req_noargs(service, op):
    return _rpc(service, op).getvalue()


def req_stats_upload(board, score):
    w = _rpc(4, 1)
    w.u8(0)
    w.i32(board)
    w.u64(0)
    w.i64(score)
    w.i32(0)
    w.i64(0)
    w.i64(0)
    return w.getvalue()


def req_storage_list(op):
    w = _rpc(10, op)
    if op == 7:
        w.u64(0)
    w.u32(0)
    w.u16(50)
    return w.getvalue()


def req_stats_page(board):
    w = _rpc(4, 5)
    w.i32(board)
    w.u64(0)
    w.u64(0)
    w.i64(50)
    return w.getvalue()


def seed(tmp, consoles, lifetime):
    names = [f"load{i:05d}" for i in range(max(consoles, lifetime))]
    accounts, fnames, stats = {}, {}, {}
    for i, a in enumerate(names):
        ent = int.from_bytes(tiger192(a.encode())[:8], "little")
        accounts[a] = {"pwhash": tiger192(PASSWORD.encode()).hex(), "user_id": 1000 + i,
                       "handle": tiger192(a.encode())[:8].hex(),
                       "first_seen": "2026-09-16T00:00:00", "last_seen": "2026-09-16T00:00:00"}
        fnames[f"{ent:016x}"] = a
        for board in (1, 2, 3, 5, 9, 12, 15):
            row = [1000 + (i * 7919) % 900, 0, a]
            if board == 1:
                row.append([[9, 0], [10, 123456789], [10, 0]])
            stats[f"{board}:{ent:016x}"] = row
    (tmp / "accounts.json").write_text(json.dumps(accounts))
    (tmp / "friends-db.json").write_text(json.dumps(
        {"names": fnames, "friends": [], "invites": [], "blocked": [], "messages": []}))
    (tmp / "stats-db.json").write_text(json.dumps(stats))
    return names[:consoles], (tmp / "stats-db.json").stat().st_size


def start_server(tmp):
    env = dict(os.environ, WOW2_PORT=str(PORT), WOW2_DATA_DIR=str(tmp), WOW2_HEXDUMPS="0",
               WOW2_LOG_LEVEL="info", WOW2_SHARED_PASSWORD_FALLBACK="false",
               WOW2_NO_NAT_TYPE="1", WOW2_NAT_RELAY="0", WOW2_MAX_CONNS_PER_IP="100000",
               WOW2_MAX_MSGS_PER_SEC="100000")
    proc = subprocess.Popen([sys.executable, str(TOOLS / "authserver.py")], env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", PORT), timeout=0.3).close(); return proc
        except OSError:
            time.sleep(0.1)
    raise SystemExit("server never listened")


def signin_burst(c):
    """What a console does between 'Signing in...' and the Infrastructure menu."""
    calls = [req_storage_list(7), req_storage_list(8), req_noargs(9, 5), req_noargs(9, 7),
             req_noargs(9, 19), req_noargs(3, 20), req_noargs(6, 1), req_noargs(8, 3)]
    calls += [req_stats_read(b, [c.entity]) for b in (1, 2, 3, 4, 5)]
    for p in calls:
        err, r = c.call(p, timeout=8.0)
        if r is None:
            return False
    return True


def match_start(c):
    for b in (1, 2, 3, 4, 5):
        err, r = c.call(req_stats_upload(b, 900), timeout=8.0)
        if r is None:
            return False
    return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--consoles", type=int, default=16)
    ap.add_argument("--lifetime", type=int, default=100)
    a = ap.parse_args()
    tmp = Path(tempfile.mkdtemp(prefix="wow2-load-"))
    names, stats_bytes = seed(tmp, a.consoles, a.lifetime)
    proc = start_server(tmp)
    results = {}
    lock = threading.Lock()

    def one(name):
        t0 = time.time()
        try:
            c = FastConsole("127.0.0.1", PORT, name)
            t1 = time.time()
            ok = signin_burst(c)
            t2 = time.time()
            ok2 = match_start(c)
            t3 = time.time()
            err, r = c.call(req_stats_page(5), timeout=8.0)
            err2, r2 = c.call(req_storage_upload("xyzzy.ufd", b"F" * 2048), timeout=8.0)
            t4 = time.time()
            with lock:
                results[name] = dict(login=t1 - t0, signin=t2 - t1, match=t3 - t2,
                                     extra=t4 - t3, ok=ok and ok2 and r is not None and r2 is not None)
            c.close()
        except Exception as e:
            with lock:
                results[name] = dict(error=repr(e), ok=False)

    threads = [threading.Thread(target=one, args=(n,)) for n in names]
    T0 = time.time()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    wall = time.time() - T0
    proc.terminate(); proc.wait(timeout=5)
    ok = [r for r in results.values() if r.get("ok")]
    bad = [r for r in results.values() if not r.get("ok")]
    rpcs = len(ok) * (13 + 5 + 2) + len(names) * 2
    timed_out = len(names) - len(ok) - len([r for r in bad if "error" in r])
    print(f"consoles={a.consoles} lifetime={a.lifetime} stats-db={stats_bytes/1024:.0f} KB  "
          f"wall={wall:.1f}s  ok={len(ok)} timed_out={timed_out} "
          f"errors={len([r for r in bad if 'error' in r])}  ~{rpcs/wall:.0f} RPC/s")
    for k in ("login", "signin", "match", "extra"):
        v = [r[k] for r in ok]
        if v:
            print(f"  {k:7s} median {statistics.median(v)*1000:6.0f} ms   p95 "
                  f"{sorted(v)[int(len(v)*0.95)-1 if len(v) > 1 else 0]*1000:6.0f} ms   "
                  f"max {max(v)*1000:6.0f} ms")
    for r in bad[:3]:
        print("  failed:", r)
    shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
