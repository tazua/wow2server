#!/usr/bin/env python3
"""`wow2-account` -- the operator's way in and out of the credential store.

    wow2-account list
    wow2-account set player1b                 # prompts, nothing in shell history
    wow2-account handle player1b              # match a log line to a name
    wow2-account remove player1b
"""
from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import authserver as srv
import store


def cmd_list(_args) -> int:
    rows = store.db().execute("SELECT * FROM accounts ORDER BY name").fetchall()
    if not rows:
        print(f"no accounts in {store.path()}")
        print("  (a console writes one when it CREATES an account; one that "
              "already had\n   an account signs straight in and never sends "
              "its name, so add it here)")
        return 0
    print(f"{store.path()}  --  {len(rows)} account(s)\n")
    print(f"  {'name':<20} {'handle':<18} {'cred':<5} {'id':<4} last seen")
    for row in rows:
        print(f"  {row['name']:<20} {row['handle'] or '?':<18} "
              f"{'yes' if row['pwhash'] else 'NO':<5} "
              f"{row['user_id'] or 0:<4} {row['last_seen'] or '-'}")
    return 0


def cmd_handle(args) -> int:
    for name in args.name:
        print(f"{srv.account_handle(name).hex()}  {name}")
    return 0


def cmd_set(args) -> int:
    if args.hash:
        digest = bytes.fromhex(args.hash)
        if len(digest) != 24:
            print("!! --hash wants the full 24-byte Tiger192 digest")
            return 1
    else:
        pw = args.password or getpass.getpass(f"password for {args.name}: ")
        if not pw:
            print("!! empty password")
            return 1
        digest = srv.tiger192(pw.encode())
    srv.set_account_password(args.name, digest)
    print(f"stored credential for {args.name!r} "
          f"(handle {srv.account_handle(args.name).hex()})")
    print("the console must now sign in with that password; the shared-password "
          "fallback no longer applies to it")
    return 0


def cmd_remove(args) -> int:
    with store.tx() as conn:
        cur = conn.execute("DELETE FROM accounts WHERE handle = ?",
                           (srv.account_handle(args.name).hex(),))
    if cur.rowcount == 0:
        print(f"no such account: {args.name}")
        return 1
    print(f"removed {args.name!r}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        prog="wow2-account", description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="every account, and whether it has a credential")

    p = sub.add_parser("set", help="store an account's credential")
    p.add_argument("name")
    p.add_argument("--password", help="NOT recommended: this lands in shell "
                                      "history and in ps output")
    p.add_argument("--hash", help="a 24-byte Tiger192 digest, hex, if you have "
                                  "it and not the password")

    p = sub.add_parser("handle", help="Tiger192(name)[:8] -- what the logs print")
    p.add_argument("name", nargs="+")

    p = sub.add_parser("remove", help="forget an account's credential")
    p.add_argument("name")

    args = ap.parse_args()
    try:
        return {"list": cmd_list, "set": cmd_set,
                "handle": cmd_handle, "remove": cmd_remove}[args.cmd](args)
    except store.StoreError as e:
        print(f"!! {e}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
