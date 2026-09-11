#!/usr/bin/env python3
"""`wow2-account` -- the operator's way in and out of the credential store.

WHY THIS HAD TO EXIST. A console only ever tells the server its name ONCE, in
the create-account message. Every later message identifies the account by its
**handle**, `Tiger192(name)[:8]`, which is a one-way hash -- so a server that
missed the create, or lost its store, can never learn that name again from the
console. It cannot even help: `Change password` names itself by handle too, so
it answers 704 BD_AUTH_BAD_ACCOUNT, and the escape hatch the README used to
recommend is exactly the thing that cannot work.

Measured the hard way: a deployment's store was deleted, a real PSP signed in
fine on the shared-password fallback, and then could not write its credential by
any route available to it. The name was recoverable only because a human
remembered it.

So the operator supplies the name, and the console proves the password by
signing in. That is all this does.

    wow2-account list
    wow2-account set player1b                 # prompts, nothing in shell history
    wow2-account handle player1b              # match a log line to a name
    wow2-account remove player1b

THE STORE HOLDS DIGESTS AND NEVER PASSWORDS. The client sends
`Tiger192(password)`, which *is* the key the login reply is built with, so the
digest is the credential -- which also means `list` does not print it. Anyone
holding it can impersonate the server to that account.
"""
from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import authserver as srv


def cmd_list(_args) -> int:
    db = srv._jload(srv.ACCOUNTS_DB, {})
    if not db:
        print(f"no accounts in {srv.ACCOUNTS_DB}")
        print("  (a console writes one when it CREATES an account; one that "
              "already had\n   an account signs straight in and never sends "
              "its name, so add it here)")
        return 0
    print(f"{srv.ACCOUNTS_DB}  --  {len(db)} account(s)\n")
    print(f"  {'name':<20} {'handle':<18} {'cred':<5} {'id':<4} last seen")
    for name, row in sorted(db.items()):
        print(f"  {name:<20} {row.get('handle', '?'):<18} "
              f"{'yes' if row.get('pwhash') else 'NO':<5} "
              f"{row.get('user_id', 0):<4} {row.get('last_seen', '-')}")
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
    db = srv._jload(srv.ACCOUNTS_DB, {})
    if args.name not in db:
        print(f"no such account: {args.name}")
        return 1
    del db[args.name]
    srv._jsave(srv.ACCOUNTS_DB, db)
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
    return {"list": cmd_list, "set": cmd_set,
            "handle": cmd_handle, "remove": cmd_remove}[args.cmd](args)


if __name__ == "__main__":
    raise SystemExit(main())
