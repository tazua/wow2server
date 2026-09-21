"""The pot: who staked what on a ranked match, and who gets paid.

The client pays its stake at match start and the winner pays the pot out at
the end (netrecon §21, §24, §26); this records both, holds a pot through the
session-delete/payout race, and settles what the client never did (`wow2
award`). The ledger is the `pots` table, the ratings the `stats` table (§66).
The same wager is placed on the Weekly, Monthly and Yearly boards from what
each served (§74), so a stake is recorded per board and a refund or an award
pays every board its own pot back (§77).
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import statsdb
import store

RATING_START = statsdb.STARTING_RATING

DEFAULT_POLICY = {
    "payout": "winner-takes-all",
    "unresolved": "refund",
    "placing": [0.6, 0.25, 0.15],
}
# The boards a ranked start stakes besides the rating: the game's Weekly,
# Monthly and Yearly (§74), each from what it served.
SIDE_BOARDS = {2: "Weekly", 3: "Monthly", 4: "Yearly"}


# ------------------------------------------------------------------ the rows

def policy() -> dict:
    d = {}
    raw = store.meta_get(store.db(), "pot_policy")
    if raw:
        try:
            d = json.loads(raw)
        except ValueError:
            d = {}
    out = dict(DEFAULT_POLICY)
    out.update({k: v for k, v in d.items() if k in DEFAULT_POLICY})
    return out


def _live() -> list[tuple[str, str, dict]]:
    """(state, session, doc) for every open or pending pot, oldest first."""
    return [(r["state"], r["session"], json.loads(r["doc"])) for r in store.db().execute(
        "SELECT state, session, doc FROM pots WHERE state != 'settled' ORDER BY seq")]


def _find_live(key: str) -> tuple[str | None, dict | None]:
    r = store.db().execute("SELECT state, doc FROM pots WHERE session = ? AND "
                           "state != 'settled'", (key,)).fetchone()
    return (r["state"], json.loads(r["doc"])) if r else (None, None)


def _write_live(key: str, state: str, doc: dict) -> None:
    conn = store.db()
    cur = conn.execute("UPDATE pots SET state = ?, doc = ? WHERE session = ? AND "
                       "state != 'settled'", (state, json.dumps(doc), key))
    if cur.rowcount == 0:
        conn.execute("INSERT INTO pots (session, state, doc) VALUES (?, ?, ?)",
                     (key, state, json.dumps(doc)))


def _settle(key: str, doc: dict, keep_empty: bool = False) -> None:
    """The live row becomes a settled one; a pot with nothing in it just goes,
    unless the caller wants the record (a client payout with nothing banked
    is an anomaly worth keeping).
    """
    conn = store.db()
    conn.execute("DELETE FROM pots WHERE session = ? AND state != 'settled'", (key,))
    if doc.get("pot") or keep_empty:
        conn.execute("INSERT INTO pots (session, state, doc) VALUES (?, 'settled', ?)",
                     (key, json.dumps(doc)))


def _settled(limit: int | None = None, session: str | None = None) -> list[dict]:
    """Settled pots, newest first."""
    sql, args = "SELECT doc FROM pots WHERE state = 'settled'", []
    if session is not None:
        sql += " AND session = ?"
        args.append(session)
    sql += " ORDER BY seq DESC"
    if limit:
        sql += " LIMIT ?"
        args.append(limit)
    return [json.loads(r["doc"]) for r in store.db().execute(sql, args)]


def _when(when: str | None) -> str:
    """A timestamp WITH the date."""
    return when or store.now_iso()


def _pot_of(rec: dict) -> int:
    return sum(int(s.get("stake", 0)) for s in rec.get("stakes", {}).values())


def _side_pots(rec: dict) -> dict[str, int]:
    """board -> what was staked on it by everyone, for the boards that saw a stake."""
    out: dict[str, int] = {}
    for s in rec.get("stakes", {}).values():
        for b, st in s.get("boards", {}).items():
            out[b] = out.get(b, 0) + int(st.get("stake", 0))
    return {b: pot for b, pot in out.items() if pot}


def _refund(eh: str, st: dict) -> None:
    """One player's stakes back: the rating, and every side board still in the
    period the stake was placed in (a board that has started over owes nothing)."""
    _pay(eh, st.get("name", ""), int(st.get("stake", 0)))
    for b, side in st.get("boards", {}).items():
        _pay_board(int(b), eh, st.get("name", ""), int(side.get("stake", 0)))


SETTLE_GRACE_S = 20.0    # the winner's payout lands ~1 s AFTER a losing host's session delete


def _now() -> float:
    return time.time()


def sweep() -> list[str]:
    """Apply the `unresolved` policy to any pending pot whose grace has expired."""
    msgs, now = [], _now()
    with store.tx():
        how = policy().get("unresolved", "refund")
        for state, key, rec in _live():
            if state != "pending" or now < float(rec.get("deadline", 0)):
                continue
            pot = _pot_of(rec)
            if pot and how == "refund":
                for eh, st in rec["stakes"].items():
                    _refund(eh, st)
                msgs.append(f"pot {pot} REFUNDED (session 0x{key} ended with no winner "
                            f"declared and no client payout within {SETTLE_GRACE_S:.0f}s; "
                            f"policy 'refund'){_side_note(rec)}")
            elif pot:
                msgs.append(f"pot {pot} FORFEIT (session 0x{key} ended with no winner "
                            f"declared; policy 'forfeit' -- what the real servers did)")
            rec.update({"pot": pot, "settled": how, "closed": rec.get("ended", "")})
            _settle(key, rec)
    return msgs


# ------------------------------------------------------------------ recording

def open_pot(sid: int, host: str, when: str | None = None) -> dict:
    """A ranked session was created. Open a pot for it (idempotent)."""
    k = f"{sid:x}"
    with store.tx():
        state, rec = _find_live(k)
        if rec is None:
            rec = {"session": k, "opened": _when(when), "host": host, "stakes": {}}
            _write_live(k, "open", rec)
        return rec


def note_stake(sid: int, entity: int, name: str, before: int, after: int,
               when: str | None = None) -> tuple[int, int]:
    """Record one player's stake (`served - written`). Returns (stake, pot)."""
    stake = max(0, int(before) - int(after))
    k = f"{sid:x}"
    with store.tx():
        state, rec = _find_live(k)
        if rec is None:
            state, rec = "open", {"session": k, "opened": _when(when), "host": "",
                                  "stakes": {}}
        rec.setdefault("stakes", {}).setdefault(f"{entity:016x}", {}).update({
            "name": name, "before": int(before), "after": int(after), "stake": stake,
            "at": _when(when)})
        _write_live(k, state, rec)
        return stake, _pot_of(rec)


def note_side_stake(sid: int, board_id: int, entity: int, name: str, before: int,
                    after: int, when: str | None = None) -> int:
    """Record the same player's stake on a side board (Weekly, Monthly, Yearly),
    which the client places a second or two BEFORE the rating's. Only while the
    pot is open: after the session is gone an upload here is the client's own
    payout, not a stake. Returns the stake, 0 if nothing was recorded."""
    stake = int(before) - int(after)
    if board_id not in SIDE_BOARDS or stake <= 0:
        return 0
    k = f"{sid:x}"
    with store.tx():
        state, rec = _find_live(k)
        if state != "open":
            return 0
        entry = rec.setdefault("stakes", {}).setdefault(
            f"{entity:016x}", {"name": name, "before": 0, "after": 0, "stake": 0,
                               "at": _when(when)})
        entry.setdefault("boards", {})[str(board_id)] = {
            "before": int(before), "after": int(after), "stake": stake}
        _write_live(k, state, rec)
    return stake


def _side_note(rec: dict) -> str:
    """"; Weekly 76, Monthly 76 back too" for a report line."""
    pots = _side_pots(rec)
    if not pots:
        return ""
    return "; " + ", ".join(f"{SIDE_BOARDS.get(int(b), b)} {pot}" for b, pot in sorted(pots.items())) \
        + " on the side boards too"


def note_payout(sid: int, entity: int, name: str, before: int, after: int,
                when: str | None = None) -> str:
    """The CLIENT paid the pot out. Close the pot; do not pay it again."""
    k = f"{sid:x}"
    gain = int(after) - int(before)
    with store.tx():
        sweep()
        state, rec = _find_live(k)
        if not rec:
            return (f"{name} gained {gain} on board {RATING_BOARD_NAME} with no open "
                    f"pot for session 0x{k} -- not banked, nothing to close")
        pot = _pot_of(rec)
        rec.pop("deadline", None)
        rec.update({"pot": pot, "settled": "client", "closed": _when(when),
                    "winner": {"entity": f"{entity:016x}", "name": name,
                               "before": int(before), "after": int(after),
                               "gain": gain}})
        _settle(k, rec, keep_empty=True)
    msg = (f"pot {pot} PAID BY THE CLIENT to {name} ({before} -> {after}, "
           f"+{gain}); session 0x{k} closed, `wow2 award` not needed")
    if gain != pot:
        msg += (f"  [!! the client paid {gain} but we banked {pot} -- a stake "
                f"was missed or an extra player is in the session]")
    return msg


RATING_BOARD_NAME = "5"


def newest_open() -> tuple[str, dict] | tuple[None, None]:
    """The pot with stakes in it, most recently opened first."""
    staked = [(k, v) for _state, k, v in _live() if _pot_of(v) > 0]
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


def _pay_board(board_id: int, entity_hex: str, name: str, amount: int) -> tuple[int, int] | None:
    """The same on a side board -- unless its period has turned since the stake,
    when the player is served the starting rating again and is owed nothing."""
    entity = int(entity_hex, 16)
    if statsdb.raw(board_id, entity) is None:
        return None
    before, _rank, stored = statsdb.get(board_id, entity, name)
    after = max(statsdb.RATING_FLOOR, before + int(amount))
    statsdb.put(board_id, entity, after, stored or name)
    return before, after


def _placed(rec: dict, order: list[str]) -> list[str]:
    """The finishing order as entity ids, from names or ids; KeyError for a stranger."""
    stakes = rec.get("stakes", {})
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
    return placed


def _shares(rec: dict, order: list[str], policy: dict, pot: int | None = None) -> dict:
    """entity_hex -> payout of `pot` (the rating's unless given), for a finishing
    order given as names or ids."""
    pot = _pot_of(rec) if pot is None else pot
    placed = _placed(rec, order)
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
    out[placed[0]] = pot - spent
    return out


def award(order: list[str], sid: str | None = None) -> str:
    """Pay an open pot out to a finishing order (winner first). Returns a report."""
    with store.tx():
        sweep()
        if sid:
            key = sid.lower().removeprefix("0x")
            _state, rec = _find_live(key)
        else:
            key, rec = newest_open()
        if not rec:
            for done in _settled(session=key if sid else None):
                if done.get("settled") == "client":
                    w = done.get("winner", {})
                    return (f"session 0x{done.get('session')} was already settled BY "
                            f"THE CLIENT: {w.get('name', '?')} took the pot of "
                            f"{done.get('pot', 0)} ({w.get('before')} -> "
                            f"{w.get('after')}). Awarding again would pay it twice.")
            return "no open pot with stakes in it -- nothing to award"
        pot = _pot_of(rec)
        try:
            shares = _shares(rec, order, policy())
        except KeyError as e:
            who = ", ".join(f"{s.get('name')} ({eh[:8]}...)"
                            for eh, s in rec.get("stakes", {}).items())
            return f"{e.args[0]!r} did not stake in session {key} -- staked: {who or 'nobody'}"
        side = {b: _shares(rec, order, policy(), side_pot)
                for b, side_pot in _side_pots(rec).items()}
        lines = [f"pot {pot} from session {key} ({len(rec['stakes'])} player(s))"]
        paid = []
        for eh, amount in sorted(shares.items(), key=lambda kv: -kv[1]):
            s = rec["stakes"][eh]
            before, after = _pay(eh, s.get("name", ""), amount)
            boards, notes = {}, []
            for b, split in sorted(side.items()):
                got = _pay_board(int(b), eh, s.get("name", ""), split.get(eh, 0))
                if got is not None:
                    boards[b] = {"won": split.get(eh, 0), "before": got[0], "after": got[1]}
                    notes.append(f"{SIDE_BOARDS.get(int(b), b)} +{split.get(eh, 0)}")
            lines.append(f"  {s.get('name', eh[:8]):<16} staked {s.get('stake', 0):>6}"
                         f"   +{amount:<6} rating {before} -> {after}"
                         + (f"   ({', '.join(notes)})" if notes else ""))
            paid.append({"entity": eh, "name": s.get("name", ""), "won": amount,
                         "before": before, "after": after, "boards": boards})
        rec.pop("deadline", None)
        rec.update({"pot": pot, "settled": "award", "order": order, "paid": paid,
                    "closed": store.now_iso()})
        _settle(key, rec)
    return "\n".join(lines)


def settle_unresolved(sid: int, when: str | None = None,
                      policy_override: str | None = None) -> str | None:
    """The session went away. HOLD the pot; do not settle it yet."""
    key = f"{sid:x}"
    with store.tx():
        msgs = sweep()
        state, rec = _find_live(key)
        if not rec or state != "open":
            return "; ".join(msgs) or None
        pot = _pot_of(rec)
        if pot and policy_override is None:
            rec["ended"] = _when(when)
            rec["deadline"] = _now() + SETTLE_GRACE_S
            _write_live(key, "pending", rec)
            held = (f"pot {pot} HELD for {SETTLE_GRACE_S:.0f}s (session 0x{key} deleted; "
                    f"waiting to see whether the winner's client pays it out). "
                    f"`wow2 award NAME` settles it now.")
            return "; ".join(msgs + [held])
        how = policy_override or policy().get("unresolved", "refund")
        if pot and how == "refund":
            for eh, st in rec["stakes"].items():
                _refund(eh, st)
            msg = (f"pot {pot} REFUNDED (session 0x{key}; policy 'refund'){_side_note(rec)}")
        elif pot:
            msg = (f"pot {pot} FORFEIT (session 0x{key}; policy 'forfeit')")
        else:
            msg = None
        rec.update({"pot": pot, "settled": how, "closed": _when(when)})
        _settle(key, rec)
    return "; ".join(msgs + ([msg] if msg else [])) or None


# --------------------------------------------------------------------- report

def describe() -> str:
    swept = sweep()
    pol = policy()
    out = [f"policy: payout={pol['payout']}  unresolved={pol['unresolved']}  "
           f"placing={pol['placing']}  start rating={RATING_START}"]
    out.extend("swept: " + m for m in swept)
    live = sorted(_live(), key=lambda t: t[2].get("opened", ""))
    if not live:
        out.append("no open pot")
    for state, k, rec in live:
        pot = _pot_of(rec)
        held = rec.get("deadline")
        tag = "OPEN" if state == "open" else f"HELD({max(0, float(held or 0) - _now()):.0f}s left)"
        out.append(f"{tag} session 0x{k}  host={rec.get('host', '?')!r}  "
                   f"opened {rec.get('opened', '?')}  pot {pot}")
        for eh, s in rec.get("stakes", {}).items():
            sides = ", ".join(f"{SIDE_BOARDS.get(int(b), b)} {st.get('stake')}"
                              for b, st in sorted(s.get("boards", {}).items()))
            out.append(f"    {s.get('name', eh[:8]):<16} {s.get('before')} -> "
                       f"{s.get('after')}   staked {s.get('stake')}"
                       + (f"   ({sides})" if sides else ""))
        if pot:
            out.append(f"    -> wow2 award <winner>          (pays {pot}{_side_note(rec)})")
    for rec in reversed(_settled(limit=5)):
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
