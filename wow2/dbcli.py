#!/usr/bin/env python3
"""`wow2-db` -- the operator's way in and out of the SQLite store (§66).

    wow2-db check                 integrity, row counts, which stores were imported when
    wow2-db import DIR            the JSON stores in DIR -> the database (fresh tables only;
                                  renamed aside when DIR is the database's own directory)
    wow2-db export DIR            the database -> the seven JSON files, for an editor or a diff
    wow2-db backup PATH           a consistent copy, safe while the server runs
    wow2-db roundtrip DIR         import DIR into a scratch database, export, compare field by field
"""
from __future__ import annotations

import argparse
import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import store                                                    # noqa: E402


def _open(args) -> tuple[sqlite3.Connection, Path]:
    db_path = Path(args.db) if args.db else store.path()
    return store.connect(db_path), db_path.parent


def cmd_check(args) -> int:
    conn, data_dir = _open(args)
    bad, notes = store.check(conn, data_dir)
    print(f"{store.path() if not args.db else args.db}")
    for n in notes:
        print(f"  {n}")
    if bad:
        print(f"\n{len(bad)} finding(s):")
        for b in bad:
            print(f"  !! {b}")
        return 1
    print("\nok")
    return 0


def cmd_import(args) -> int:
    conn, data_dir = _open(args)
    src = Path(args.dir)
    own = src.resolve() == data_dir.resolve()
    try:
        done = store.import_dir(conn, src, data_dir, log=lambda m: print(m), rename=own)
    except store.StoreError as e:
        print(f"!! {e}")
        return 1
    if not done:
        print(f"nothing to import: none of {', '.join(store.STORES.values())} in {args.dir}")
        return 1
    for s, counts in done.items():
        print(f"  {store.STORES[s]:16s} -> " + ", ".join(f"{t} {n}" for t, n in counts.items()))
    print("imported; " + ("each file is renamed <name>.imported-<date> beside the database"
                          if own else "the files in the source directory were left as they are"))
    return 0


def cmd_export(args) -> int:
    conn, _ = _open(args)
    written = store.export_dir(conn, Path(args.dir))
    for s, p in written.items():
        print(f"  {s:9s} {p}")
    return 0


def cmd_backup(args) -> int:
    conn, _ = _open(args)
    dest = Path(args.path)
    if dest.exists() and not args.force:
        print(f"!! {dest} exists; --force to overwrite it")
        return 1
    dest.parent.mkdir(parents=True, exist_ok=True)
    copy = sqlite3.connect(str(dest))
    with copy:
        conn.backup(copy)
    copy.close()
    print(f"backed up to {dest} ({dest.stat().st_size} bytes)")
    return 0


def cmd_roundtrip(args) -> int:
    work = Path(tempfile.mkdtemp(prefix="wow2-roundtrip-"))
    try:
        fails, report = store.roundtrip(Path(args.dir), work, log=lambda m: print(m))
    except store.StoreError as e:
        print(f"!! {e}")
        return 1
    finally:
        if args.keep:
            print(f"(scratch kept at {work})")
        else:
            shutil.rmtree(work, ignore_errors=True)
    print(f"round trip of {args.dir}:")
    for line in report:
        print(line)
    print("\n" + ("FAIL: " + ", ".join(fails) if fails else "ALL PASS"))
    return 1 if fails else 0


def main() -> int:
    ap = argparse.ArgumentParser(
        prog="wow2-db", description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db", help=f"the database (default: {store.DB_NAME} in the data dir)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("check", help="integrity, counts, import history")
    p = sub.add_parser("import", help="JSON stores in DIR -> the database")
    p.add_argument("dir")
    p = sub.add_parser("export", help="the database -> JSON files in DIR")
    p.add_argument("dir")
    p = sub.add_parser("backup", help="a consistent copy of the database")
    p.add_argument("path")
    p.add_argument("--force", action="store_true")
    p = sub.add_parser("roundtrip", help="import DIR, export, compare (a self-test)")
    p.add_argument("dir")
    p.add_argument("--keep", action="store_true", help="keep the scratch directory")
    args = ap.parse_args()
    return {"check": cmd_check, "import": cmd_import, "export": cmd_export,
            "backup": cmd_backup, "roundtrip": cmd_roundtrip}[args.cmd](args)


if __name__ == "__main__":
    raise SystemExit(main())
