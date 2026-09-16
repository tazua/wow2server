"""The pot: who staked what on a ranked match, and who gets paid.

PHASE 21 established the mechanic and PHASE 22 implements the missing half.

A ranked ("Play for points") lobby shows every player a stake worth 10% of their
board-5 rating and the sum of the stakes as `Pot`. The client pays its own stake:
`bdStats op 1` fires ~1 s after the `Sessions op 2` that starts the match and
writes `max(10, served - served//10)` -- the rating it read at sign-in, minus its
stake, floored so nobody is left under 10.

**PHASE 24 OVERTURNS THE REST OF THIS FILE'S PREMISE: the CLIENT pays the pot
out.** Phases 21-22 concluded "nothing ever pays the pot out" because no match on
this rig had ever *finished* -- every one was quit, and a quit skips the whole
end-of-match chain. Played to a real finish (2026-09-11 11:14), the winner
re-uploads boards 2,3,4,5, each raised by exactly the sum of both stakes on that
board, and the loser re-uploads none of them:

    board  served   staked(start)   paid(end)   pot        check
      2     4242     -424 -> 3818    4552       424+310    3818+734 = 4552
      3     3300     -330 -> 2970    3580       330+280    2970+610 = 3580
      4     2100     -210 -> 1890    2360       210+260    1890+470 = 2360
      5     4444     -444 -> 4000    4824       444+380    4000+824 = 4824

Exact on all four, and zero-sum across the two accounts (8244 before, 8244
after). So the mechanic never needed our half at all.

What that means for this file: `note_payout()` closes a pot the client has
already settled, and `award()` refuses to pay one twice. `wow2 award` is now only
for matches that did NOT finish cleanly -- and for those the original servers'
behaviour (both stakes burned) is the `forfeit` policy, not `refund`.

So the payout is ours. Two things constrain the design and both come from the
Team17 forum archive, where the developers and players described the live system:

  * "If you complete a match as the victor, you gain points toward your rank. If
    you complete a match as the loser, you lose points" -- so the pot went
    somewhere, and it went to the winner.
  * "If your opponent leaves the match at any point (whether you are winning or
    losing), your rank and completion percentage both go down, and there is
    nothing you can do about it" -- the single loudest complaint about the PSP
    version. That is EXACTLY this mechanic with the payout skipped: both stakes
    are already paid when the match starts, so an abandoned match burns both.

Which means winner-takes-the-pot reproduces the original, and it is also a good
ladder on its own terms: with ratings W and L the winner ends on W + 0.1*L and
the loser on 0.9*L, so beating someone far above you pays enormously and beating
someone far below you pays nearly nothing. It is zero-sum, which is what the word
"pot" on the lobby screen says it is.

THE SERVER CAN SEE WHO WON, after all -- twice over, in a FINISHED match:

  * the rating-board write that goes UP is the winner's payout (above), and
  * only the non-loser uploads board 8 ("Hard cases"): `Init_Hc_Stat` is gated on
    the result global being >= 0. The loser uploads no board 8 at all.

Neither signal exists in a match that was quit. There, nothing carries a result
-- the two `Sessions op 2` firings decode as occupancy only, quitting sends
`Sessions op 3` and nothing else -- so `wow2 award NAME` and the `unresolved`
policy still apply to abandoned matches only.

    capture/pot.json      the ledger: open pots, settled pots, the policy
    capture/stats-db.json where a payout actually lands (board 5)

A payout is visible to the client at its NEXT FULL SIGN-IN: re-entering
Infrastructure reconnects without re-reading boards 1..5, so restart the server
and run tools/login.py to see a new rating on screen.
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import statsdb

POT_DB = statsdb.CAP / "pot.json"

# What a brand-new account is worth on board 5. NOTHING in the game decides this
# -- the client reads its rating from us and the only constant it carries is the
# floor of 10, so a fresh account served nothing writes back max(10, 0) = 10 and
# can never wager.
#
# It USED TO BE 1000 and it used to be WRITTEN, by `ensure_start()` at the first
# sign-in. Two things were wrong with that and only the second is about the
# number (T12, §57):
#
#   * a written row puts every account that has ever signed in onto the RANKED
#     LEADERBOARD, whether or not it has played a ranked match. Measured on the
#     rig: eight rows on board 5 against six on board 1 (games started), with
#     player7 and player8 sitting at exactly 1000 having started nothing.
#   * 1000 is not where the two formulas agree. See statsdb.STARTING_RATING.
#
# So the value is SERVED on a miss now and the row appears when the player first
# stakes, which is the moment they join the board. This name is kept because the
# pot status line prints it.
RATING_START = statsdb.STARTING_RATING

DEFAULT_POLICY = {
    "payout": "winner-takes-all",   # or "placing"
    "unresolved": "refund",         # or "forfeit" (faithful to the original)
    "placing": [0.6, 0.25, 0.15],
}


def load() -> dict:
    try:
        d = json.loads(POT_DB.read_text())
    except (OSError, ValueError):
        d = {}
    d.setdefault("policy", dict(DEFAULT_POLICY))
    for k, v in DEFAULT_POLICY.items():
        d["policy"].setdefault(k, v)
    d.setdefault("open", {})
    d.setdefault("pending", {})
    d.setdefault("settled", [])
    return d


def save(d: dict) -> bool:
    """Atomic, like `statsdb.save` and `authserver._jsave`: a crash between
    truncate and write used to leave a short file that `load()` read as no pots
    at all, i.e. every open wager forgotten."""
    try:
        POT_DB.parent.mkdir(parents=True, exist_ok=True)
        tmp = POT_DB.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(d, indent=1))
        os.replace(tmp, POT_DB)
        return True
    except OSError:
        return False


def _pot_of(rec: dict) -> int:
    return sum(int(s.get("stake", 0)) for s in rec.get("stakes", {}).values())


# How long a pot is held after its session is deleted, before the `unresolved`
# policy is applied.
#
# PHASE 26 -- THE RACE THIS FIXES. In a finished three-player ranked match the
# order on the wire was:
#
#   15:29:21.534  session delete  (the HOST sent Sessions op 3 -- and the host
#                                  had LOST, so it left as soon as it was out)
#   15:29:21.535  pot 924 REFUNDED by the `unresolved` policy
#   15:29:22.422  the WINNER's board-5 payout: 900 -> 1824
#
# The refund and the client's own payout both landed, so 924 rating was created
# out of nothing and the match stopped being zero-sum. note_payout() could not
# help: it looks for an OPEN pot and the pot had been closed 0.9 s earlier.
#
# Phase 24 measured this on a 1v1 where the winner happened to be the host, so
# the delete came after the payout and the ordering never showed. It is not
# safe to assume: the host is whoever created the lobby, and a host can lose.
#
# So a session delete no longer settles -- it moves the pot to `pending` with a
# deadline, and the policy is applied only once the deadline passes with no
# payout. sweep() is called from every entry point rather than from a timer, so
# there is no thread and no clock to get wrong; the cost is that a pending pot
# settles on the next pot operation rather than exactly on time, which only
# delays the bookkeeping, never the player's rating.
SETTLE_GRACE_S = 20.0


def _now() -> float:
    return time.time()


def sweep(d: dict | None = None) -> list[str]:
    """Apply the `unresolved` policy to any pending pot whose grace has expired.

    Returns the messages produced. Call it from anywhere that touches the bank;
    it is cheap and idempotent."""
    own = d is None
    d = load() if own else d
    msgs, now = [], _now()
    for key, rec in list(d.get("pending", {}).items()):
        if now < float(rec.get("deadline", 0)):
            continue
        pot = _pot_of(rec)
        how = d["policy"].get("unresolved", "refund")
        if pot and how == "refund":
            for eh, st in rec["stakes"].items():
                _pay(eh, st.get("name", ""), int(st.get("stake", 0)))
            msgs.append(f"pot {pot} REFUNDED (session 0x{key} ended with no winner "
                        f"declared and no client payout within {SETTLE_GRACE_S:.0f}s; "
                        f"policy 'refund')")
        elif pot:
            msgs.append(f"pot {pot} FORFEIT (session 0x{key} ended with no winner "
                        f"declared; policy 'forfeit' -- what the real servers did)")
        rec = d["pending"].pop(key)
        rec.update({"pot": pot, "settled": how, "closed": rec.get("ended", "")})
        if pot:
            d["settled"].append(rec)
    if msgs and own:
        save(d)
    return msgs


# ------------------------------------------------------------------ recording

def open_pot(sid: int, host: str, when: str) -> dict:
    """A ranked session was created. Open a pot for it (idempotent)."""
    d = load()
    k = f"{sid:x}"
    rec = d["open"].setdefault(k, {})
    rec.setdefault("session", k)
    rec.setdefault("opened", when)
    rec.setdefault("host", host)
    rec.setdefault("stakes", {})
    save(d)
    return rec


def note_stake(sid: int, entity: int, name: str, before: int, after: int,
               when: str = "") -> tuple[int, int]:
    """Record one player's stake (`served - written`). Returns (stake, pot)."""
    stake = max(0, int(before) - int(after))
    d = load()
    k = f"{sid:x}"
    rec = d["open"].setdefault(k, {"session": k, "opened": when, "host": "",
                                   "stakes": {}})
    rec["stakes"][f"{entity:016x}"] = {"name": name, "before": int(before),
                                       "after": int(after), "stake": stake,
                                       "at": when}
    save(d)
    return stake, _pot_of(rec)


def note_payout(sid: int, entity: int, name: str, before: int, after: int,
                when: str = "") -> str:
    """The CLIENT paid the pot out. Close the pot; do not pay it again.

    Phase 24: a finished match ends with the winner re-uploading boards 2..5,
    each raised by the whole pot for that board (`start_write + sum(stakes)`),
    measured exact on all four. So a rating-board write that goes UP is not a
    stake -- it is the payout, and the player who sent it WON. Anything the
    server did on top of that (an award, or the `refund` policy on session
    delete) would be a second payment out of nothing.
    """
    d = load()
    sweep(d)
    k = f"{sid:x}"
    # A pending pot is one whose session has already been deleted but whose
    # grace has not expired -- exactly the case this race produces, because the
    # losing host leaves before the winner's board-5 write arrives.
    pending = k in d.get("pending", {})
    rec = d["open"].get(k) or d.get("pending", {}).get(k)
    gain = int(after) - int(before)
    if not rec:
        return (f"{name} gained {gain} on board {RATING_BOARD_NAME} with no open "
                f"pot for session 0x{k} -- not banked, nothing to close")
    pot = _pot_of(rec)
    rec = (d["pending"] if pending else d["open"]).pop(k)
    rec.pop("deadline", None)
    rec.update({"pot": pot, "settled": "client", "closed": when,
                "winner": {"entity": f"{entity:016x}", "name": name,
                           "before": int(before), "after": int(after),
                           "gain": gain}})
    d["settled"].append(rec)
    save(d)
    msg = (f"pot {pot} PAID BY THE CLIENT to {name} ({before} -> {after}, "
           f"+{gain}); session 0x{k} closed, `wow2 award` not needed")
    if gain != pot:
        msg += (f"  [!! the client paid {gain} but we banked {pot} -- a stake "
                f"was missed or an extra player is in the session]")
    return msg


RATING_BOARD_NAME = "5"


def newest_open(d: dict | None = None) -> tuple[str, dict] | tuple[None, None]:
    """The pot with stakes in it, most recently opened first.

    PENDING pots count: a pot whose session has been deleted but whose grace has
    not expired is still payable, and `wow2 award` must be able to reach it --
    that window is exactly when a person is most likely to be typing the
    command."""
    d = d or load()
    staked = [(k, v) for k, v in list(d["open"].items()) + list(d.get("pending", {}).items())
              if _pot_of(v) > 0]
    if not staked:
        return None, None
    staked.sort(key=lambda kv: kv[1].get("opened", ""), reverse=True)
    return staked[0]


# -------------------------------------------------------------------- payout

def _pay(entity_hex: str, name: str, amount: int) -> tuple[int, int]:
    entity = int(entity_hex, 16)
    before, _rank, stored = statsdb.get(statsdb.RATING_BOARD, entity, name)
    after = max(statsdb.RATING_FLOOR, before + int(amount))
    statsdb.put(statsdb.RATING_BOARD, entity, after, stored or name)
    return before, after


def _shares(rec: dict, order: list[str], policy: dict) -> dict:
    """entity_hex -> payout, for a finishing order given as names or ids."""
    stakes = rec.get("stakes", {})
    pot = _pot_of(rec)
    placed = []
    for who in order:
        hit = None
        for eh, s in stakes.items():
            if eh == who.lower() or (s.get("name", "").lower() == who.lower()):
                hit = eh
                break
        if hit is None:
            raise KeyError(who)
        if hit not in placed:
            placed.append(hit)
    if not placed:
        return {}
    if len(placed) == 1 or policy.get("payout") != "placing":
        out = {placed[0]: pot}
        for eh in placed[1:]:
            out[eh] = 0
        return out
    weights = list(policy.get("placing") or DEFAULT_POLICY["placing"])
    weights = (weights + [0.0] * len(placed))[:len(placed)]
    total = sum(weights) or 1.0
    out, spent = {}, 0
    for i, eh in enumerate(placed[1:], start=1):
        cut = int(round(pot * weights[i] / total))
        out[eh] = cut
        spent += cut
    out[placed[0]] = pot - spent          # first place absorbs the rounding
    return out


def award(order: list[str], sid: str | None = None) -> str:
    """Pay an open pot out to a finishing order (winner first). Returns a report."""
    d = load()
    sweep(d)
    if sid:
        key = sid.lower().removeprefix("0x")
        rec = d["open"].get(key) or d.get("pending", {}).get(key)
    else:
        key, rec = newest_open(d)
    if not rec:
        for done in reversed(d["settled"]):
            if done.get("settled") == "client" and (not sid or
                    done.get("session") == (sid or "").lower().removeprefix("0x")):
                w = done.get("winner", {})
                return (f"session 0x{done.get('session')} was already settled BY "
                        f"THE CLIENT: {w.get('name', '?')} took the pot of "
                        f"{done.get('pot', 0)} ({w.get('before')} -> "
                        f"{w.get('after')}). Awarding again would pay it twice.")
        return "no open pot with stakes in it -- nothing to award"
    pot = _pot_of(rec)
    try:
        shares = _shares(rec, order, d["policy"])
    except KeyError as e:
        who = ", ".join(f"{s.get('name')} ({eh[:8]}...)"
                        for eh, s in rec.get("stakes", {}).items())
        return f"{e.args[0]!r} did not stake in session {key} -- staked: {who or 'nobody'}"
    lines = [f"pot {pot} from session {key} ({len(rec['stakes'])} player(s))"]
    paid = []
    for eh, amount in sorted(shares.items(), key=lambda kv: -kv[1]):
        s = rec["stakes"][eh]
        before, after = _pay(eh, s.get("name", ""), amount)
        lines.append(f"  {s.get('name', eh[:8]):<16} staked {s.get('stake', 0):>6}"
                     f"   +{amount:<6} rating {before} -> {after}")
        paid.append({"entity": eh, "name": s.get("name", ""), "won": amount,
                     "before": before, "after": after})
    rec = d["open"].pop(key, None) or d["pending"].pop(key)
    rec.pop("deadline", None)
    rec.update({"pot": pot, "settled": "award", "order": order, "paid": paid})
    d["settled"].append(rec)
    save(d)
    return "\n".join(lines)


def settle_unresolved(sid: int, when: str = "", policy: str | None = None) -> str | None:
    """The session went away. HOLD the pot; do not settle it yet.

    See SETTLE_GRACE_S: the client's own payout arrives about a second AFTER the
    session delete when the host is the loser, and settling here paid the pot
    twice. `policy` forces an immediate settlement (used by `wow2 award`)."""
    d = load()
    msgs = sweep(d)
    key = f"{sid:x}"
    rec = d["open"].get(key)
    if not rec:
        save(d)
        return "; ".join(msgs) or None
    pot = _pot_of(rec)
    if pot and policy is None:
        rec = d["open"].pop(key)
        rec["ended"] = when
        rec["deadline"] = _now() + SETTLE_GRACE_S
        d["pending"][key] = rec
        save(d)
        held = (f"pot {pot} HELD for {SETTLE_GRACE_S:.0f}s (session 0x{key} deleted; "
                f"waiting to see whether the winner's client pays it out). "
                f"`wow2 award NAME` settles it now.")
        return "; ".join(msgs + [held])
    how = policy or d["policy"].get("unresolved", "refund")
    if pot and how == "refund":
        for eh, st in rec["stakes"].items():
            _pay(eh, st.get("name", ""), int(st.get("stake", 0)))
        msg = (f"pot {pot} REFUNDED (session 0x{key}; policy 'refund')")
    elif pot:
        msg = (f"pot {pot} FORFEIT (session 0x{key}; policy 'forfeit')")
    else:
        msg = None
    rec = d["open"].pop(key)
    rec.update({"pot": pot, "settled": how, "closed": when})
    if pot:
        d["settled"].append(rec)
    save(d)
    return "; ".join(msgs + ([msg] if msg else [])) or None


# --------------------------------------------------------------------- report

def describe() -> str:
    d = load()
    swept = sweep(d)
    if swept:
        save(d)
    out = [f"policy: payout={d['policy']['payout']}  "
           f"unresolved={d['policy']['unresolved']}  "
           f"placing={d['policy']['placing']}  start rating={RATING_START}"]
    if swept:
        out.extend("swept: " + m for m in swept)
    if not d["open"] and not d.get("pending"):
        out.append("no open pot")
    for k, rec in sorted(list(d["open"].items()) + list(d.get("pending", {}).items()),
                         key=lambda kv: kv[1].get("opened", "")):
        pot = _pot_of(rec)
        held = rec.get("deadline")
        tag = "OPEN" if held is None else f"HELD({max(0, held - _now()):.0f}s left)"
        out.append(f"{tag} session 0x{k}  host={rec.get('host', '?')!r}  "
                   f"opened {rec.get('opened', '?')}  pot {pot}")
        for eh, s in rec["stakes"].items():
            out.append(f"    {s.get('name', eh[:8]):<16} {s.get('before')} -> "
                       f"{s.get('after')}   staked {s.get('stake')}")
        if pot:
            out.append(f"    -> wow2 award <winner>          (pays {pot})")
    for rec in d["settled"][-5:]:
        who = ", ".join(f"{p['name']}+{p['won']}" for p in rec.get("paid", [])
                        if p.get("won"))
        out.append(f"settled 0x{rec.get('session', '?')} pot {rec.get('pot', 0)} "
                   f"{rec.get('settled', '?')}{('  ' + who) if who else ''}")
    return "\n".join(out)


if __name__ == "__main__":
    args = sys.argv[1:]
    if args and args[0] == "award":
        print(award(args[1:]))
    else:
        print(describe())
