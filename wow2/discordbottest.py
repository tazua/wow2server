#!/usr/bin/env python3
"""Does the password bot hand out what it should and refuse what it must? No
Discord, no emulator: the desk is driven on a scratch store and the commands
through a fake context (§73).

    discordbottest.py            # every check
    discordbottest.py --keep     # leave the scratch directory behind
"""
from __future__ import annotations

import argparse
import asyncio
import os
import random
import shutil
import sqlite3
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

SCRATCH = Path(tempfile.mkdtemp(prefix="wow2-discordbottest-"))
os.environ["WOW2_DATA_DIR"] = str(SCRATCH)      # before serverconfig is imported
os.environ["WOW2_DISCORD_BOT_GUILD"] = "0"

import authserver as srv                                        # noqa: E402
import discordbot as bot                                        # noqa: E402
import store                                                    # noqa: E402

RESULTS: list[tuple[bool, str]] = []


def check(cond: bool, what: str) -> bool:
    RESULTS.append((bool(cond), what))
    print(f"  {'ok  ' if cond else 'FAIL'} {what}")
    return bool(cond)


def pwhash(name: str) -> str | None:
    row = store.db().execute("SELECT pwhash FROM accounts WHERE handle = ?",
                             (store.account_handle(name),)).fetchone()
    return row["pwhash"] if row else None


def bound_to(name: str) -> str | None:
    row = store.db().execute("SELECT user_id FROM discord_claims WHERE handle = ?",
                             (store.account_handle(name),)).fetchone()
    return row["user_id"] if row else None


def digest(password: str) -> str:
    return srv.tiger192(password.encode()).hex()


class Clock:
    def __init__(self) -> None:
        self.t = time.time()

    def __call__(self) -> float:
        return self.t


class FakeCtx(bot.Ctx):
    """A context that records what the handlers send, with DMs open or shut."""

    def __init__(self, user_id: str, admin: bool = False, dms_open: bool = True) -> None:
        self.user_id = user_id
        self.user_name = f"user{user_id}"
        self.is_admin = admin
        self.server = "Wormhole"
        self.help_mention = "<#555>"
        self.dms_open = dms_open
        self.replies: list[tuple[str, list]] = []
        self.dms: list[tuple[str, str, list]] = []

    async def reply(self, text, files=()):
        self.replies.append((text, list(files)))

    async def dm(self, user_id, text, files=()):
        if not self.dms_open:
            return False
        self.dms.append((user_id, text, list(files)))
        return True


def run(keep: bool) -> int:
    A, B, C, P, Q = "1001", "1002", "1003", "1004", "1005"
    clock = Clock()
    desk = bot.Desk(claims_per_day=3, rng=random.Random(7), clock=clock)

    print("the text")
    txt = bot.kit_text("BoggyB", "k7mfp2qx", "Wormhole", "<#555>")
    check("`k7mfp2qx`" in txt and "**BoggyB**" in txt and "**Wormhole**" in txt
          and "<#555>" in txt and "Change password" in txt and "Infrastructure mode" in txt,
          "the kit names the profile, the server, the help channel, the password and both routes")
    tmpl, why = bot.check_text("{name}: {password} {nope}")
    check(tmpl == bot.DEFAULT_TEXT and why and "nope" in why,
          "a template with a field that does not exist is named and the default used")
    tmpl, why = bot.check_text("Recruit, your password for {name} is {password}. {help}")
    check(why is None and bot.kit_text("x", "y", "z", "h", tmpl) == "Recruit, your password for x is y. h",
          "a template that fills in is used as given")
    check(bot.check_text("")[0] == bot.DEFAULT_TEXT, "an empty template means the default")
    longest = bot.kit_text("a" * 12, "k7mfp2qx", "W" * 100, "<#1234567890123456789>")
    check(len(longest) < 2000, f"the kit fits a Discord message with the longest name ({len(longest)} chars)")

    print("names and passwords")
    check(all(bot.name_error(n) is None for n in ("BoggyB", "lukas1", "a1b2c3d4e5f6", "fivec",
                                                  "x", "a" * 16, "dot.name", "two words")),
          "1 to 16 printable characters pass, a five-letter name included (the game's stated "
          "6-12 rule is not one it keeps)")
    check(all(bot.name_error(n) for n in ("", "a" * 17, " lead", "trail ", "h\u00e9llo", "tab\tname")),
          "empty, 17, an edge space, a non-ASCII letter and a tab are refused")
    pws = {bot.new_password() for _ in range(50)}
    check(len(pws) == 50 and all(len(p) == 8 for p in pws)
          and all(set(p) <= set(bot.PASSWORD_ALPHABET) for p in pws)
          and not any(c in "il1o0" for p in pws for c in p),
          "50 passwords: all different, 8 characters, no i/l/1/o/0 to misread on a screen")

    print("the desk")
    r = desk.claim("BoggyB", A)
    p1 = r.password
    check(r.outcome is bot.Outcome.CLAIMED and r.name == "BoggyB" and p1
          and pwhash("BoggyB") == digest(p1),
          "a name nobody holds: claimed, and the stored digest is Tiger192 of the password sent")
    check(srv.stored_credential("boggyb") == srv.tiger192(p1.encode()),
          "...which is the digest the login reply's ticket is encrypted under (any letter case)")
    check(bound_to("BoggyB") == A, "...and the name is bound to the Discord user who asked")
    uid = store.db().execute("SELECT user_id FROM accounts WHERE name = 'BoggyB'").fetchone()[0]
    check(uid and uid >= 100, f"...with a user id allocated like a console's create ({uid})")

    r = desk.claim("boggyb", B)
    check(r.outcome is bot.Outcome.TAKEN and "somebody else" in r.detail
          and pwhash("BoggyB") == digest(p1) and bound_to("BoggyB") == A,
          "somebody else asking for the same name (any case) is refused; nothing changes")

    r = desk.claim("BOGGYB", A)
    p2 = r.password
    check(r.outcome is bot.Outcome.RESET and p2 and p2 != p1 and r.name == "BoggyB"
          and pwhash("BoggyB") == digest(p2),
          "the same user again: a fresh password, the stored name keeps its first case")

    srv.set_account_password("lukas1", srv.tiger192(b"123456"))
    r = desk.claim("lukas1", A)
    check(r.outcome is bot.Outcome.TAKEN and "console" in r.detail
          and pwhash("lukas1") == digest("123456") and bound_to("lukas1") is None,
          "a name registered from a console is nobody's to claim")

    r = desk.reset("lukas1", C)
    p3 = r.password
    check(r.outcome is bot.Outcome.RESET and pwhash("lukas1") == digest(p3) and bound_to("lukas1") == C,
          "staff reset it for a player: new digest, bound to that player")
    r = desk.claim("lukas1", C)
    check(r.outcome is bot.Outcome.RESET and pwhash("lukas1") == digest(r.password),
          "...who may now reset it alone")
    check(desk.claim("lukas1", A).outcome is bot.Outcome.TAKEN, "...and nobody else may")

    r = desk.claim("fivec", P)
    check(r.outcome is bot.Outcome.CLAIMED and pwhash("fivec") == digest(r.password),
          "a five-letter name is claimed like any other")
    check(desk.claim("", P).outcome is bot.Outcome.INVALID
          and desk.claim("a" * 17, P).outcome is bot.Outcome.INVALID,
          "the empty name and a 17-character one are not")

    with store.tx() as conn:
        conn.execute("INSERT INTO accounts (name, handle) VALUES (?, ?)",
                     ("noticed1", store.account_handle("noticed1")))
    r = desk.claim("noticed1", B)
    check(r.outcome is bot.Outcome.CLAIMED and pwhash("noticed1") == digest(r.password),
          "a name an older server only noticed in passing (no digest) is free to claim")

    vet = store.account_handle("veteran1")
    ent = f"{int.from_bytes(bytes.fromhex(vet), 'little'):016x}"
    with store.tx() as conn:
        conn.execute("INSERT INTO profiles (entity, kind, name, at, fields) "
                     "VALUES (?, 'public', 'veteran1', ?, '[]')", (ent, store.now_iso()))
        conn.execute("INSERT INTO stats (board, entity, score, name) "
                     "VALUES (5, ?, 777, 'veteran1')", (ent,))
    r = desk.claim("veteran1", Q)
    check(r.outcome is getattr(bot.Outcome, "HISTORY", None) and pwhash("veteran1") is None
          and bound_to("veteran1") is None,
          "a name with no password but a profile and a rating here is not handed out (§80q)")
    d = desk.lookup("veteran1")
    check(d.get("history") == ["a profile", "scores"] and not d["registered"],
          "...and lookup shows staff what it has here")
    r = desk.reset("veteran1", C)
    check(r.outcome in (bot.Outcome.CLAIMED, bot.Outcome.RESET)
          and pwhash("veteran1") == digest(r.password) and bound_to("veteran1") == C,
          "CONTROL: staff may still give it to a player they have checked")

    print("the daily limit")
    # A has two successes today (the claim and the reset); B one (noticed1) and one refusal
    r = desk.claim("newname01", A)
    check(r.outcome is bot.Outcome.CLAIMED, "A's third password of the day is issued")
    r = desk.claim("newname02", A)
    check(r.outcome is bot.Outcome.TOO_MANY and pwhash("newname02") is None,
          "A's fourth is refused and nothing is written")
    again = bot.Desk(claims_per_day=3, rng=random.Random(9), clock=clock)
    check(again.claim("newname09", A).outcome is bot.Outcome.TOO_MANY
          and pwhash("newname09") is None,
          "...and so is it by a restarted bot: the count is in the store, not the process (§80q)")
    check(desk.claim("newname02", B).outcome is bot.Outcome.CLAIMED
          and desk.claim("newname03", B).outcome is bot.Outcome.CLAIMED
          and desk.claim("newname04", B).outcome is bot.Outcome.TOO_MANY,
          "a refusal did not count against B: two more, then B is at the limit too")
    clock.t += bot.DAY + 1
    check(desk.claim("newname05", A).outcome is bot.Outcome.CLAIMED, "a day later A may again")
    free = bot.Desk(claims_per_day=0, rng=random.Random(1), clock=clock)
    check(all(free.claim(f"unlimited{i}", C).outcome is bot.Outcome.CLAIMED for i in range(5)),
          "bot_claims_per_day = 0 is no limit")

    d = desk.lookup("BOGGYB")
    check(d["registered"] and d["name"] == "BoggyB" and d["claimed_by"] == A
          and d["handle"] == store.account_handle("boggyb"),
          "lookup: registered, the stored name, who set it, the handle the log prints")
    d = desk.lookup("nobody99")
    check(not d["registered"] and d["claimed_by"] is None, "lookup of a name never seen")

    print("recover: a password the game will not take any more")
    srv.set_account_password("changed1", srv.tiger192(b"oldpass1"))
    srv.set_account_password("changed1", srv.tiger192(b"abcdefghijklmn"))    # the in-game change to 14
    r = desk.recover("changed1", P, "nope1234")
    check(r.outcome is bot.Outcome.WRONG and pwhash("changed1") == digest("abcdefghijklmn")
          and bound_to("changed1") is None, "a wrong password: refused, nothing changes")
    r = desk.recover("changed1", P, "oldpass1")
    check(r.outcome is bot.Outcome.WRONG and pwhash("changed1") == digest("abcdefghijklmn"),
          "the password BEFORE the change proves nothing: a change is a change")
    r = desk.recover("CHANGED1", P, "abcdefghijklmn")
    check(r.outcome is bot.Outcome.RESET and r.password and pwhash("changed1") == digest(r.password)
          and bound_to("changed1") == P and len(r.password) == 8,
          "the 14-character password the game refuses proves the account: a fresh 8-character "
          "one, the name bound to the player")
    check(desk.recover("nobody99", P, "whatever").outcome is bot.Outcome.UNREGISTERED,
          "a name with no password on file is pointed at /claim, and the try is free")
    fresh = bot.Desk(claims_per_day=0, rng=random.Random(3), clock=clock)
    outs = [fresh.recover("changed1", B, f"guess{i}").outcome for i in range(6)]
    check(outs[:5] == [bot.Outcome.WRONG] * 5 and outs[5] is bot.Outcome.TOO_MANY,
          "five wrong tries an hour, the sixth is not even checked")
    clock.t += 3601
    check(fresh.recover("changed1", B, "guess7").outcome is bot.Outcome.WRONG, "an hour later, again")

    print("a decision and its write are one transaction (§80ae)")
    db_file = store.db().execute("PRAGMA database_list").fetchone()[2]

    def server_writes(name: str, password: str) -> bool:
        """A credential written from another connection, as the server's create or
        an in-game change; False when the write lock is held (the server waits)."""
        c = sqlite3.connect(db_file, timeout=0, isolation_level=None)
        c.row_factory = sqlite3.Row
        try:
            c.execute("BEGIN IMMEDIATE")
            srv._write_credential(c, name, srv.tiger192(password.encode()), "10.0.0.9")
            c.execute("COMMIT")
            return True
        except sqlite3.OperationalError:
            return False
        finally:
            c.close()

    real_new_password = bot.new_password
    landed: list[bool] = []

    def meanwhile(name: str, password: str):
        """The desk has decided and is about to write: the server writes first."""
        def new_password(rng=None):
            landed.append(server_writes(name, password))
            return real_new_password(rng)
        return new_password

    R = "1006"
    race = bot.Desk(claims_per_day=3, rng=random.Random(11), clock=clock)
    check(server_writes("racer0", "console0") and pwhash("racer0") == digest("console0"),
          "CONTROL: with no command being decided, the other connection's write goes in at once")
    bot.new_password = meanwhile("racer1", "console1")
    try:
        r = race.claim("racer1", R)
    finally:
        bot.new_password = real_new_password
    check(landed == [False] and r.outcome is bot.Outcome.CLAIMED
          and pwhash("racer1") == digest(r.password),
          "a console's create cannot land between /claim's check that a name is free and its "
          "write, to be overwritten: the server waits for the claim's lock, then answers 707")
    landed.clear()
    srv.set_account_password("racer2", srv.tiger192(b"first222"))
    bot.new_password = meanwhile("racer2", "second22")
    try:
        r = race.recover("racer2", R, "first222")
    finally:
        bot.new_password = real_new_password
    check(landed == [False] and r.outcome is bot.Outcome.RESET
          and pwhash("racer2") == digest(r.password),
          "nor can the owner's in-game change land between /recover's check of the password "
          "on file and its write: it waits, and is then checked against the new password")

    def broken(_user_id):
        raise sqlite3.OperationalError("disk I/O error")
    race._count = broken
    try:
        race.claim("racer3", R)
        raised = False
    except sqlite3.OperationalError:
        raised = True
    del race._count
    check(raised and pwhash("racer3") is None and bound_to("racer3") is None
          and not store.db().in_transaction,
          "a store that fails while counting a password writes none of it: no password that "
          "nobody was sent, no claim")

    print("the commands")
    files = bot.guide_files()
    ctx = FakeCtx(P)
    text = asyncio.run(bot.do_claim(desk, ctx, "Recruit01"))
    check(len(ctx.dms) == 1 and ctx.dms[0][0] == P and "`" in ctx.dms[0][1]
          and pwhash("Recruit01") == digest(ctx.dms[0][1].split("`")[1])
          and ctx.dms[0][2] == files and "DM" in text and not ctx.replies[0][1],
          "/claim: the kit and the pictures go by DM, the password in it is the stored one, "
          "the reply carries neither")
    ctx = FakeCtx(P, dms_open=False)
    text = asyncio.run(bot.do_claim(desk, ctx, "Recruit01"))
    check(not ctx.dms and "could not DM" in text and "`" in text
          and pwhash("Recruit01") == digest(text.split("`")[1]) and ctx.replies[0][1] == files,
          "/claim with DMs shut: the kit comes back in the private reply instead, pictures and all")
    desk_pw_recruit = text.split("`")[1]
    ctx = FakeCtx(B)
    text = asyncio.run(bot.do_claim(desk, ctx, "Recruit01"))
    check(not ctx.dms and "already has a password" in text and "<#555>" in text
          and "/recover Recruit01" in text,
          "/claim on somebody else's name: refused, pointed at /recover and the help channel, no DM")
    ctx = FakeCtx(B)
    text = asyncio.run(bot.do_claim(desk, ctx, "a" * 17))
    check("not a profile name" in text and "1 to 16" in text, "/claim on a bad name says the rule")
    with store.tx() as conn:
        conn.execute("INSERT INTO profiles (entity, kind, name, at, fields) "
                     "VALUES (?, 'public', 'veteran2', ?, '[]')",
                     (f"{int.from_bytes(bytes.fromhex(store.account_handle('veteran2')), 'little'):016x}",
                      store.now_iso()))
    ctx = FakeCtx(B)
    text = asyncio.run(bot.do_claim(desk, ctx, "veteran2"))
    check(not ctx.dms and "played on" in text and "<#555>" in text and pwhash("veteran2") is None,
          "/claim on a name that has played here: no DM, sent to staff in the help channel")

    ctx = FakeCtx(Q)
    text = asyncio.run(bot.do_recover(desk, ctx, "changed1", "wrong"))
    check("not the password on file" in text and "<#555>" in text and not ctx.dms,
          "/recover with a wrong password: refused, pointed at the help channel")
    ctx = FakeCtx(Q)
    text = asyncio.run(bot.do_recover(desk, ctx, "nobody99", "x"))
    check("/claim nobody99" in text, "/recover on a name with no password says /claim")
    ctx = FakeCtx(Q)
    text = asyncio.run(bot.do_recover(desk, ctx, "Recruit01", "z"))
    check("not the password" in text and pwhash("Recruit01") == digest(desk_pw_recruit),
          "/recover on somebody's name with a guess changes nothing")
    ctx = FakeCtx(Q)
    text = asyncio.run(bot.do_recover(desk, ctx, "Recruit01", desk_pw_recruit))
    check(len(ctx.dms) == 1 and "`" in ctx.dms[0][1]
          and pwhash("Recruit01") == digest(ctx.dms[0][1].split("`")[1]) and "DM" in text
          and bound_to("Recruit01") == Q,
          "/recover with the password on file: the kit by DM with a fresh password, the name "
          "now bound to whoever proved it")
    ctx = FakeCtx(B)
    text = asyncio.run(bot.do_reset(desk, ctx, "Recruit01", C, "userC"))
    check(text == "Staff only." and bound_to("Recruit01") == Q, "/reset by a member: refused, untouched")
    ctx = FakeCtx(A, admin=True)
    text = asyncio.run(bot.do_reset(desk, ctx, "Recruit01", C, "userC"))
    check(len(ctx.dms) == 1 and ctx.dms[0][0] == C and f"<@{C}>" in text
          and pwhash("Recruit01") == digest(ctx.dms[0][1].split("`")[1]) and bound_to("Recruit01") == C,
          "/reset by staff: the player named gets the kit by DM, the name is theirs now")
    ctx = FakeCtx(A, admin=True, dms_open=False)
    text = asyncio.run(bot.do_reset(desk, ctx, "Recruit01", C, "userC"))
    check(f"could not DM <@{C}>" in text and "`" in text,
          "/reset when the player's DMs are shut: staff get the kit to pass on")
    ctx = FakeCtx(A, admin=True)
    text = asyncio.run(bot.do_reset(desk, ctx, "", C, "userC"))
    check("cannot be a profile name" in text and not ctx.dms, "/reset on a bad name")

    ctx = FakeCtx(B)
    check(asyncio.run(bot.do_account(desk, ctx, "Recruit01")) == "Staff only.", "/account by a member")
    ctx = FakeCtx(A, admin=True)
    text = asyncio.run(bot.do_account(desk, ctx, "recruit01"))
    check("**Recruit01**: registered" in text and f"<@{C}>" in text
          and store.account_handle("recruit01") in text, "/account: registered, by whom, the handle")
    text = asyncio.run(bot.do_account(desk, ctx, "nobody99"))
    check("no password on file" in text, "/account on a name never seen")
    text = asyncio.run(bot.do_account(desk, ctx, "veteran2"))
    check("no password on file" in text and "on the server: a profile" in text,
          "/account on a name with history says what it has")

    print("the pictures")
    names = [p.name for p in files]
    check(len(files) == 4 and all(p.read_bytes()[:8] == b"\x89PNG\r\n\x1a\n" for p in files),
          f"four PNGs ship beside the module: {', '.join(names)}")
    check(names == sorted(names) and [n[0] for n in names] == ["1", "2", "3", "4"],
          "...numbered in the order the kit names them")

    print("what the bot holds (§80h)")
    check("permissions=0&" in bot.invite_url(123),
          "the password bot's invite asks for no permissions")
    extra = getattr(bot, "excess_permissions", lambda _v: [])
    check(extra(8) == ["Administrator"] and extra(0x20 | 0x10000000)
          == ["Manage Server", "Manage Roles"] and extra(0x400 | 0x800) == [],
          "a token with Administrator or Manage Server/Roles is named at the start; "
          "View Channels and Send Messages are not")

    print("who is staff (§80f)")
    resolve = getattr(bot, "staff_role_ids", None)
    staff = getattr(bot, "is_staff", None)
    if resolve is None or staff is None:
        check(False, "staff is decided by role id, not by a role's name")
    else:
        roles = [(11, "Admin"), (12, "Moderator"), (13, "member")]
        ids, problems = resolve(["Admin", "Moderator"], roles)
        check(ids == {11, 12} and not problems,
              "names in bot_admin_roles resolve to the one role carrying each")
        check(not staff(False, [13, 14], ids),
              "a member holding a role made AFTER the start under the name Moderator "
              "(id 14) is not staff")
        ids, problems = resolve(["Admin", "Moderator"], roles + [(14, "Moderator")])
        check(ids == {11} and any("2 roles are called 'Moderator'" in p for p in problems),
              "...and if a second Moderator role already exists at the start, the name "
              "grants nothing and the log says to give the id")
        ids, problems = resolve(["12", "99"], roles)
        check(ids == {12} and any("no role with id 99" in p for p in problems),
              "a role id is taken as itself; an id the server has not got is named")
        check(staff(True, [], set()) and staff(False, [12], {12}),
              "Manage Server is always staff, and so is a pinned role")

    passed = sum(1 for ok, _ in RESULTS if ok)
    print(f"\n{passed} of {len(RESULTS)} passed")
    for ok, what in RESULTS:
        if not ok:
            print(f"  FAILED: {what}")
    store.close()
    if keep:
        print(f"scratch kept: {SCRATCH}")
    else:
        shutil.rmtree(SCRATCH, ignore_errors=True)
    return 0 if passed == len(RESULTS) else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--keep", action="store_true")
    args = ap.parse_args()
    return run(args.keep)


if __name__ == "__main__":
    raise SystemExit(main())
