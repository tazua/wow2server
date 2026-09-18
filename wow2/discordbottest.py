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
import sys
import tempfile
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
        self.t = 1_000_000.0

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
    A, B, C, P = "1001", "1002", "1003", "1004"
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
    check(bot.name_error("BoggyB") is None and bot.name_error("lukas1") is None
          and bot.name_error("a1b2c3d4e5f6") is None, "6 to 12 letters and digits pass")
    check(all(bot.name_error(n) for n in ("abcde", "a" * 13, "has space", "dot.name", "", "fivec")),
          "too short, too long, a space, punctuation and the empty name are refused")
    check(bot.name_error("fivec", strict=False) is None and bot.name_error("a b", strict=False),
          "staff may name a shorter profile (an edited savedata), still letters and digits only")
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

    r = desk.reset("fivec", P)
    check(r.outcome is bot.Outcome.CLAIMED and pwhash("fivec") == digest(r.password),
          "staff may set a password for a name shorter than the game allows (an edited savedata)")
    check(desk.claim("fivec", P).outcome is bot.Outcome.INVALID
          and desk.claim("has space", P).outcome is bot.Outcome.INVALID,
          "a player may not: the game's own rule, 6 to 12 letters and digits")

    with store.tx() as conn:
        conn.execute("INSERT INTO accounts (name, handle) VALUES (?, ?)",
                     ("noticed1", store.account_handle("noticed1")))
    r = desk.claim("noticed1", B)
    check(r.outcome is bot.Outcome.CLAIMED and pwhash("noticed1") == digest(r.password),
          "a name an older server only noticed in passing (no digest) is free to claim")

    print("the daily limit")
    # A has two successes today (the claim and the reset); B one (noticed1) and one refusal
    r = desk.claim("newname01", A)
    check(r.outcome is bot.Outcome.CLAIMED, "A's third password of the day is issued")
    r = desk.claim("newname02", A)
    check(r.outcome is bot.Outcome.TOO_MANY and pwhash("newname02") is None,
          "A's fourth is refused and nothing is written")
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
    ctx = FakeCtx(B)
    text = asyncio.run(bot.do_claim(desk, ctx, "Recruit01"))
    check(not ctx.dms and "already has a password" in text and "<#555>" in text,
          "/claim on somebody else's name: refused, pointed at the help channel, no DM")
    ctx = FakeCtx(B)
    text = asyncio.run(bot.do_claim(desk, ctx, "x"))
    check("not a profile name" in text and "6 to 12" in text, "/claim on a bad name says the rule")

    ctx = FakeCtx(B)
    text = asyncio.run(bot.do_reset(desk, ctx, "Recruit01", C, "userC"))
    check(text == "Staff only." and bound_to("Recruit01") == P, "/reset by a member: refused, untouched")
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
    text = asyncio.run(bot.do_reset(desk, ctx, "no way", C, "userC"))
    check("cannot be a profile name" in text and not ctx.dms, "/reset on a bad name")

    ctx = FakeCtx(B)
    check(asyncio.run(bot.do_account(desk, ctx, "Recruit01")) == "Staff only.", "/account by a member")
    ctx = FakeCtx(A, admin=True)
    text = asyncio.run(bot.do_account(desk, ctx, "recruit01"))
    check("**Recruit01**: registered" in text and f"<@{C}>" in text
          and store.account_handle("recruit01") in text, "/account: registered, by whom, the handle")
    text = asyncio.run(bot.do_account(desk, ctx, "nobody99"))
    check("no password on file" in text, "/account on a name never seen")

    print("the pictures")
    names = [p.name for p in files]
    check(len(files) == 4 and all(p.read_bytes()[:8] == b"\x89PNG\r\n\x1a\n" for p in files),
          f"four PNGs ship beside the module: {', '.join(names)}")
    check(names == sorted(names) and [n[0] for n in names] == ["1", "2", "3", "4"],
          "...numbered in the order the kit names them")

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
