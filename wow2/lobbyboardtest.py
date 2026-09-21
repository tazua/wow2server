#!/usr/bin/env python3
"""Does the Discord lobby board post what the session table says, coalesce a
burst into one edit, survive Discord being down, and never block the caller?
And does the leaderboards message show the store's top rows, in the period
that is current, repainted after a score and when the period turns? No
Discord, no emulator: a fake webhook endpoint in this process records every
request and answers what the checks tell it to (netrecon §69, §76).

    lobbyboardtest.py            # every check
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import lobbyboard                                               # noqa: E402
import statsdb                                                  # noqa: E402
import store                                                    # noqa: E402

RESULTS: list[tuple[bool, str]] = []
LOGGED: list[str] = []

BOARD_HOOK, LFG_HOOK, BAD_HOOK, DEAD_HOOK = "100100100", "200200200", "300300300", "400400400"
LEAD_HOOK, OTHER_LEAD = "700700700", "800800800"


def check(cond: bool, what: str) -> bool:
    RESULTS.append((bool(cond), what))
    print(f"  {'ok  ' if cond else 'FAIL'} {what}")
    return bool(cond)


def capture_log(msg: str) -> None:
    LOGGED.append(msg)


class FakeDiscord:
    """A webhook endpoint that remembers what it was sent and answers to order."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict]] = []
        self.next_id = 1000
        self.gone: set[str] = set()
        self.answer: list[int] = []
        self.refuse: set[str] = set()
        self.dead: set[str] = set()
        self.delay = 0.0
        self.lock = threading.Lock()
        fake = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _serve(self, method: str):
                n = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(n) or b"{}")
                path = self.path
                with fake.lock:
                    fake.calls.append((method, path, body))
                    forced = fake.answer.pop(0) if fake.answer else None
                if fake.delay:
                    time.sleep(fake.delay)
                hook = path.split("/api/webhooks/")[1].split("/")[0]
                if hook in fake.refuse:
                    return self._reply(401, {"message": "401: Unauthorized", "code": 0})
                if hook in fake.dead:
                    return self._reply(404, {"message": "Unknown Webhook", "code": 10015})
                if method == "GET":
                    return self._reply(200, {"id": hook, "name": "Drill Sergeant"})
                if forced == 429:
                    return self._reply(429, {"message": "You are being rate limited.",
                                             "retry_after": 0.2, "global": False})
                if forced:
                    return self._reply(forced, {"message": f"forced {forced}"})
                if method == "PATCH":
                    mid = path.rsplit("/messages/", 1)[1]
                    if mid in fake.gone:
                        return self._reply(404, {"message": "Unknown Message", "code": 10008})
                    return self._reply(200, {"id": mid})
                with fake.lock:
                    fake.next_id += 1
                    mid = str(fake.next_id)
                return self._reply(200, {"id": mid})

            def _reply(self, status: int, payload: dict):
                raw = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_POST(self):
                self._serve("POST")

            def do_PATCH(self):
                self._serve("PATCH")

            def do_GET(self):
                self._serve("GET")

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def url(self, hook: str) -> str:
        return f"http://127.0.0.1:{self.port}/api/webhooks/{hook}/tok-{hook}"

    def of(self, method: str, hook: str | None = None) -> list[tuple[str, str, dict]]:
        return [c for c in self.calls if c[0] == method
                and (hook is None or f"/api/webhooks/{hook}/" in c[1])]

    def reset(self) -> None:
        with self.lock:
            self.calls.clear()

    def close(self) -> None:
        self.srv.shutdown()
        self.srv.server_close()


def board(fake: FakeDiscord, db: Path | None, lobby=BOARD_HOOK, announce=LFG_HOOK,
          mention="<@&424242>") -> lobbyboard.LobbyBoard:
    b = lobbyboard.LobbyBoard()
    b.debounce = 0.15
    b.cooldown = 0.6
    b.retry_delay = 0.3
    bad = b.configure(fake.url(lobby) if lobby else "",
                      fake.url(announce) if announce else "", mention, "Open lobbies")
    assert not bad, bad
    b.start(db)
    return b


def leaders(fake: FakeDiscord, db: Path | None, hook=LEAD_HOOK, rows=10,
            start=400) -> lobbyboard.LeaderBoard:
    b = lobbyboard.LeaderBoard()
    b.debounce = 0.15
    b.retry_delay = 0.3
    bad = b.configure(fake.url(hook), "Leader boards", rows, None, start)
    assert not bad, bad
    b.start(db)
    return b


def seed(db: Path, rows: list[tuple[int, str, int, str | None]]) -> None:
    """(board, name, score, period) rows straight into a scratch store."""
    conn = store.connect(db)
    try:
        with store.tx(conn):
            for board, name, score, period in rows:
                conn.execute("INSERT OR REPLACE INTO stats (board, entity, score, name, period) "
                             "VALUES (?, ?, ?, ?, ?)",
                             (board, store.account_handle(name), score, name, period))
    finally:
        conn.close()


def field(call, name: str) -> dict | None:
    return next((f for f in embed_of(call).get("fields", []) if f["name"].startswith(name)), None)


def utc(*ymdhm) -> float:
    import datetime
    return datetime.datetime(*ymdhm, tzinfo=datetime.timezone.utc).timestamp()


def rec(sid: int, name: str, players=1, max_players=4, points=0, created=None) -> dict:
    return {"id": sid, "name": name, "players": players, "max_players": max_players,
            "points": points, "created": created or int(time.time()) - 60}


def embed_of(call) -> dict:
    return call[2]["embeds"][0]


def render_open(b, name, ranked, n, mx) -> str:
    return lobbyboard.render_announcement(b.mention, name, ranked, n, mx, b.text)


def run(keep: bool) -> int:
    lobbyboard.set_logger(capture_log)
    root = Path(tempfile.mkdtemp(prefix="wow2-lobbyboardtest-"))
    fake = FakeDiscord()
    db = root / "wow2.sqlite3"
    try:
        print("-- configuration")
        b = lobbyboard.LobbyBoard()
        bad = b.configure("https://discord.com/api/webhooks/not-a-number/tok", "", "", "")
        check(len(bad) == 1 and "lobby_webhook" in bad[0] and not b.url,
              "a malformed webhook URL is reported and that side is left off")
        b = lobbyboard.LobbyBoard()
        check(b.configure("https://discord.com/api/webhooks/123/AbC_-xyz", "", "", "") == []
              and b.url.endswith("/123/AbC_-xyz"),
              "a real-looking webhook URL is accepted")
        b = lobbyboard.LobbyBoard()
        check(b.start(None) is False and not b.enabled, "nothing configured: start() is a no-op")
        b.refresh({1: rec(1, "nobody")})
        b.opened(rec(1, "nobody"))
        check(fake.calls == [], "...and refresh()/opened() send nothing")

        print("-- the board")
        b = board(fake, db)
        check(b.flush(3), "start() posts the empty board")
        posts = fake.of("POST", BOARD_HOOK)
        check(len(posts) == 1 and posts[0][1].endswith("?wait=true")
              and "No open lobbies" in embed_of(posts[0])["description"]
              and embed_of(posts[0])["color"] == lobbyboard.COLOR_EMPTY,
              "...one POST with ?wait=true, saying there is nothing open, in grey")
        conn = store.connect(db)
        saved = store.meta_get(conn, f"discord.board.{BOARD_HOOK}")
        conn.close()
        check(saved == str(fake.next_id), f"...and its message id {saved} is in the meta table")
        board_id = saved

        fake.reset()
        sessions = {0x5701: rec(0x5701, "player1", points=1, created=1_700_000_000)}
        t0 = time.monotonic()
        b.refresh(sessions)
        took = time.monotonic() - t0
        check(took < 0.02, f"refresh() returns at once ({took * 1000:.1f} ms)")
        b.flush(3)
        edits = fake.of("PATCH", BOARD_HOOK)
        d = embed_of(edits[0])["description"] if edits else ""
        check(len(edits) == 1 and edits[0][1].endswith(f"/messages/{board_id}")
              and fake.of("POST", BOARD_HOOK) == [],
              "a session: the board message is EDITED, nothing new is posted")
        check("**player1**" in d and "1/4" in d and "ranked" in d
              and "opened <t:1700000000:R>" in d and "Updated <t:" in d
              and embed_of(edits[0])["color"] == lobbyboard.COLOR_OPEN,
              "...naming the host, 1/4, ranked, when it opened, in green")
        check(len(edits[0][2]["embeds"][0]["description"]) < 4096
              and edits[0][2]["allowed_mentions"] == {"parse": []},
              "...and the board never pings anyone")

        fake.reset()
        for n in range(2, 12):
            sessions[0x5701]["players"] = min(n, 4)
            b.refresh(sessions)
        b.flush(3)
        edits = fake.of("PATCH", BOARD_HOOK)
        check(len(edits) == 1 and "4/4 full" in embed_of(edits[0])["description"]
              and "\U0001F534" in embed_of(edits[0])["description"],
              f"ten updates in a burst: ONE edit, showing the last state (4/4 full, red dot)")

        fake.reset()
        sessions[0x5702] = rec(0x5702, "player2", players=2)
        sessions[0x5703] = rec(0x5703, "player3", players=1)
        b.refresh(sessions)
        b.flush(3)
        d = embed_of(fake.of("PATCH", BOARD_HOOK)[0])["description"]
        order = [d.index("**player3**"), d.index("**player2**"), d.index("**player1**")]
        check(order == sorted(order), "open lobbies first, newest first, the full one last")

        fake.reset()
        many = {i: rec(i, f"host{i}") for i in range(1, 31)}
        b.refresh(many)
        b.flush(3)
        d = embed_of(fake.of("PATCH", BOARD_HOOK)[0])["description"]
        check(d.count("\U0001F7E2") == lobbyboard.MAX_ROWS and "and 5 more" in d,
              f"thirty lobbies: {lobbyboard.MAX_ROWS} rows and 'and 5 more'")

        print("-- announcements")
        fake.reset()
        b.opened(sessions[0x5701])
        b.flush(3)
        posts = fake.of("POST", LFG_HOOK)
        c = posts[0][2]["content"] if posts else ""
        check(len(posts) == 1 and c.startswith("<@&424242> ") and "**player1**" in c
              and "ranked lobby (4/4)" in c
              and posts[0][2]["allowed_mentions"]["parse"] == ["roles", "users", "everyone"],
              "a new lobby is announced with the mention first and pings allowed")
        note_id = str(fake.next_id)
        fake.reset()
        b.closed(0x5701)
        b.flush(3)
        again = dict(sessions[0x5701], id=0x5799, players=1)
        b.opened(again)
        b.flush(3)
        edits = fake.of("PATCH", LFG_HOOK)
        check(fake.of("POST", LFG_HOOK) == [] and len(edits) == 2
              and edits[0][1].endswith(f"/messages/{note_id}") and "closed" in edits[0][2]["content"]
              and edits[1][1].endswith(f"/messages/{note_id}")
              and edits[1][2]["content"] == render_open(b, "player1", True, 1, 4)
              and edits[1][2]["allowed_mentions"] == {"parse": []},
              "the same host again inside the cooldown: no second ping, the struck-through "
              "announcement is edited back to open, and the edit pings nobody")
        fake.reset()
        b.closed(0x5799)
        b.flush(3)
        edits = fake.of("PATCH", LFG_HOOK)
        check(len(edits) == 1 and edits[0][1].endswith(f"/messages/{note_id}")
              and "closed" in edits[0][2]["content"],
              "...and closing the second lobby strikes that same message through again")
        b.opened(sessions[0x5701])
        b.flush(3)
        check(len(fake.of("POST", LFG_HOOK)) == 0, "still inside the cooldown: still no new ping")
        b.opened(sessions[0x5702])
        b.flush(3)
        check(len(fake.of("POST", LFG_HOOK)) == 1
              and "friendly lobby (2/4)" in fake.of("POST", LFG_HOOK)[0][2]["content"],
              "a different host is announced (friendly, 2/4)")
        fake.reset()
        b.closed(0x5701)
        b.flush(3)
        edits = fake.of("PATCH", LFG_HOOK)
        c = edits[0][2]["content"] if edits else ""
        check(len(edits) == 1 and edits[0][1].endswith(f"/messages/{note_id}")
              and c.startswith("~~") and "closed <t:" in c and "<@&" not in c
              and edits[0][2]["allowed_mentions"] == {"parse": []},
              "closing it strikes the announcement through, with the mention gone")
        fake.reset()
        b.closed(0x9999)
        b.flush(3)
        check(fake.calls == [], "closing a session that was never announced sends nothing")
        time.sleep(0.7)
        fake.reset()
        b.opened(sessions[0x5701])
        b.flush(3)
        check(len(fake.of("POST", LFG_HOOK)) == 1, "after the cooldown the same host is announced again")
        b7 = lobbyboard.LobbyBoard()
        b7.debounce = 0.1
        b7.configure("", fake.url(LFG_HOOK), "", "", None, 0)
        b7.start(None)
        fake.reset()
        for i in range(3):
            b7.opened(dict(sessions[0x5701], id=0x6000 + i))
        b7.flush(3)
        check(b7.cooldown == 0 and len(fake.of("POST", LFG_HOOK)) == 3,
              "announce_cooldown = 0 pings every time")
        b7.stop(2)

        print("-- the message survives a restart")
        b.stop(timeout=3)
        edits = fake.of("PATCH", BOARD_HOOK)
        e = embed_of(edits[-1]) if edits else {}
        check(edits and "Server offline since <t:" in e.get("description", "")
              and e.get("color") == lobbyboard.COLOR_OFFLINE and not b.enabled,
              "stop() edits the board to 'Server offline', in red")
        b._thread.join(2)
        check(not b._thread.is_alive(), "...and the worker thread has exited")
        fake.reset()
        b2 = board(fake, db)
        b2.flush(3)
        check(fake.of("POST", BOARD_HOOK) == [] and len(fake.of("PATCH", BOARD_HOOK)) == 1
              and fake.of("PATCH", BOARD_HOOK)[0][1].endswith(f"/messages/{board_id}"),
              "a new server on the same store edits the SAME message, posts nothing new")

        print("-- Discord misbehaving")
        fake.reset()
        fake.gone.add(board_id)
        b2.refresh(sessions)
        b2.flush(3)
        conn = store.connect(db)
        saved2 = store.meta_get(conn, f"discord.board.{BOARD_HOOK}")
        conn.close()
        check(len(fake.of("PATCH", BOARD_HOOK)) == 1 and len(fake.of("POST", BOARD_HOOK)) == 1
              and saved2 == str(fake.next_id) and saved2 != board_id,
              "a deleted board message (404 on edit) is re-posted and the new id saved")
        fake.reset()
        fake.answer = [429]
        b2.refresh({})
        b2.flush(3)
        check(len(fake.of("PATCH", BOARD_HOOK)) == 2 and b2.posted > 0,
              "a 429 is retried after retry_after and the edit lands")
        fake.reset()
        fake.answer = [500]
        b2.refresh(sessions)
        check(b2.flush(3) and len(fake.of("PATCH", BOARD_HOOK)) == 1, "a 500 is not retried at once")
        time.sleep(0.9)
        check(len(fake.of("PATCH", BOARD_HOOK)) == 2
              and any("answered 500" in m for m in LOGGED),
              f"...but again after retry_delay, and it was logged")
        fake.reset()
        LOGGED.clear()
        fake.delay = 0.4
        t0 = time.monotonic()
        b2.refresh({})
        for i in range(5):
            b2.opened(rec(7000 + i, f"slow{i}"))
        took = time.monotonic() - t0
        check(took < 0.02, f"with Discord answering slowly the callers still return at once "
                           f"({took * 1000:.1f} ms for six calls)")
        b2.flush(12)
        fake.delay = 0.0
        b2.stop(timeout=3)

        fake.reset()
        LOGGED.clear()
        b3 = lobbyboard.LobbyBoard()
        b3.debounce = 0.1
        b3.configure(f"http://127.0.0.1:1/api/webhooks/5/dead", "", "", "")
        b3.start(None)
        t0 = time.monotonic()
        b3.refresh(sessions)
        took = time.monotonic() - t0
        b3.flush(5)
        check(took < 0.02 and b3.enabled and len([m for m in LOGGED if "failed" in m]) == 1,
              "an unreachable endpoint: one '!!' line, nothing raised, board still on")
        b3.refresh({})
        b3.flush(5)
        check(len([m for m in LOGGED if "failed" in m]) == 1,
              "...and the next failure inside a minute is not logged again")
        b3.stop(timeout=2)

        fake.reset()
        LOGGED.clear()
        fake.refuse.add(BAD_HOOK)
        b4 = board(fake, None, lobby=BAD_HOOK, announce=None)
        b4.flush(3)
        b4.refresh(sessions)
        b4.flush(3)
        check(not b4.enabled and len(fake.calls) == 1
              and any("refused us (401)" in m for m in LOGGED),
              "a webhook that answers 401 turns the board off after one call and one line")

        fake.reset()
        LOGGED.clear()
        fake.dead.add(DEAD_HOOK)
        b4 = board(fake, None, lobby=DEAD_HOOK, announce=None)
        b4.flush(3)
        b4.refresh(sessions)
        b4.flush(3)
        check(not b4.enabled and len(fake.calls) == 1
              and any("does not exist any more (404 on POST)" in m for m in LOGGED),
              "a board webhook deleted on Discord's side (404 on POST) turns the board "
              "off after one call, with a line that says so")
        fake.reset()
        LOGGED.clear()
        b4 = board(fake, None, lobby=BOARD_HOOK, announce=DEAD_HOOK)
        b4.flush(3)
        check(not b4.enabled and fake.of("GET", DEAD_HOOK) and not fake.of("POST")
              and any("does not exist any more (404 on GET)" in m for m in LOGGED),
              "...and a deleted PINGS webhook is found by a GET at start, before any lobby")
        b4.stop(timeout=2)

        print("-- the poster's voice")
        sarge = {"announce_text": "{mention} Listen up! {name} opened a {mode} lobby, {count}. Move it!",
                 "closed_text": "At ease. {name}'s {mode} lobby closed {when}.",
                 "empty_text": "Nothing on the board. Host one, recruit.",
                 "offline_text": "Server down since {when}. Stand by."}
        b5 = lobbyboard.LobbyBoard()
        bad = b5.configure(fake.url(BOARD_HOOK), fake.url(LFG_HOOK), "<@&7>", "Sitrep", sarge)
        check(bad == [] and b5.text == {**lobbyboard.DEFAULT_TEXT, **sarge},
              "four templates from the config replace the defaults")
        a = lobbyboard.render_announcement("<@&7>", "player1", True, 1, 4, b5.text)
        c = lobbyboard.render_closed("player1", False, 1_700_000_000, 2, 4, b5.text)
        e = lobbyboard.render_board("Sitrep", (), "up", 1_700_000_000, b5.text)["description"]
        o = lobbyboard.render_board("Sitrep", (), "offline", 1_700_000_000, b5.text)["description"]
        check(a == "<@&7> Listen up! player1 opened a ranked lobby, 1/4. Move it!"
              and c == "At ease. player1's friendly lobby closed <t:1700000000:R>."
              and e.startswith("Nothing on the board. Host one, recruit.")
              and o == "Server down since <t:1700000000:R>. Stand by.",
              "...and every field fills in: mention, name, mode, count, when")
        check(lobbyboard.render_announcement("", "player1", False, 1, 4, b5.text)
              == "Listen up! player1 opened a friendly lobby, 1/4. Move it!",
              "an empty mention leaves no leading space")
        b6 = lobbyboard.LobbyBoard()
        bad = b6.configure(fake.url(BOARD_HOOK), "", "", "", {"announce_text": "{name} did {thing}",
                                                            "closed_text": "", "offline_text": "{when"})
        check(len(bad) == 2 and all("using the default" in m for m in bad)
              and "{thing}" not in b6.text["announce_text"] and "{mention}" in bad[0]
              and b6.text["closed_text"] == lobbyboard.DEFAULT_TEXT["closed_text"]
              and b6.text["offline_text"] == lobbyboard.DEFAULT_TEXT["offline_text"],
              "a template with an unknown field or a broken brace is named, with the fields "
              "it may use, and the default stands; an empty one is the default too")

        print("-- the server's half")
        import authserver
        s = {"id": 0x5710, "name": "player9", "players": 1, "max_players": 4, "points": 0,
             "created": int(time.time())}
        snap = lobbyboard.snapshot({0x5710: s})
        check(snap == (("player9", 1, 4, False, s["created"], False),),
              "snapshot() takes exactly the fields the create handler fills in")
        check(getattr(authserver.lobbyboard, "BOARD") is lobbyboard.BOARD
              and "lobbyboard.BOARD.refresh(SESSIONS)" in
              Path(authserver.__file__).read_text(),
              "authserver imports the board and refreshes it from the session handlers")
        src = Path(authserver.__file__).read_text()
        check(src.count("lobbyboard.BOARD.refresh(SESSIONS)") == 4
              and src.count("lobbyboard.BOARD.closed(") == 3
              and src.count("lobbyboard.BOARD.opened(") == 1,
              "...create, update, delete and host-gone all refresh; create announces; "
              "delete, host-gone and a replaced session close")
        put = src[src.index("def stats_put("):src.index("def read_typed_tail(")]
        check(put.count("lobbyboard.BOARD.scored(board_id)") == 1
              and put.index("stats STORED") < put.index("lobbyboard.BOARD.scored(board_id)")
              and "serverconfig.DISCORD_LEADERBOARD_WEBHOOK" in src,
              "...and a stored score tells the leaderboards, after the write, with the "
              "webhook from the config")

        print("-- the same board on another community's server ([[discord.also]])")
        OTHER_BOARD, OTHER_LFG = "500500500", "600600600"
        fake.reset()
        fan = lobbyboard.Fanout()
        bad = fan.configure(fake.url(BOARD_HOOK), fake.url(LFG_HOOK), "<@&424242>", "Open lobbies",
                            {"announce_text": "{mention} home: {name} {count}"}, 0.6,
                            [{"name": "Worms Central", "lobby_webhook": fake.url(OTHER_BOARD),
                              "announce_webhook": fake.url(OTHER_LFG), "mention": "<@&777>",
                              "announce_text": "{mention} theirs: {name} {count}"},
                             {"name": "broken", "lobby_webhook": "https://discord.com/api/webhooks/x/y",
                              "colour": "red"},
                             "not a table"])
        check(len(fan.boards) == 3 and fan.boards[1].label == "discord.also[0] (Worms Central)"
              and fan.boards[1].mention == "<@&777>" and fan.boards[1].title == "Open lobbies"
              and fan.boards[1].cooldown == 0.6
              and fan.boards[1].text["announce_text"] == "{mention} theirs: {name} {count}"
              and fan.boards[1].text["closed_text"] == lobbyboard.DEFAULT_TEXT["closed_text"],
              "a second server gets its own board with its own mention and lines, inheriting "
              "the title, the cooldown and the texts it does not set")
        check(len(bad) == 4 and any("(broken): discord.lobby_webhook is not a webhook URL" in x for x in bad)
              and any("(broken): no such setting 'colour'" in x for x in bad)
              and any("(broken): none of lobby_webhook, announce_webhook and leaderboard_webhook" in x for x in bad)
              and any("also[2] is not a table" in x for x in bad),
              "a broken entry is named with every problem; the good ones are untouched")
        for b in fan.boards:
            b.debounce = 0.15
            b.retry_delay = 0.3
        fandb = root / "fan.sqlite3"
        check(fan.start(fandb) and fan.enabled, "start() runs every board that has a webhook")
        fan.refresh({}); fan.flush()
        check(len(fake.of("POST", BOARD_HOOK)) == 1 and len(fake.of("POST", OTHER_BOARD)) == 1
              and embed_of(fake.of("POST", OTHER_BOARD)[0])["title"] == "Open lobbies",
              "the empty board is posted to both servers")
        fan.opened(rec(0x5720, "host9", 1, 4, 1)); fan.refresh({0x5720: rec(0x5720, "host9", 1, 4, 1)}); fan.flush()
        pings_home = fake.of("POST", LFG_HOOK)
        pings_other = fake.of("POST", OTHER_LFG)
        check(len(pings_home) == 1 and pings_home[0][2]["content"] == "<@&424242> home: host9 1/4"
              and len(pings_other) == 1 and pings_other[0][2]["content"] == "<@&777> theirs: host9 1/4",
              "a lobby opening pings both servers, each with its own role and its own words")
        check(len(fake.of("PATCH", BOARD_HOOK)) == 1 and len(fake.of("PATCH", OTHER_BOARD)) == 1
              and "host9" in embed_of(fake.of("PATCH", OTHER_BOARD)[0])["description"],
              "...and both boards are edited to show it")
        fan.closed(0x5720); fan.refresh({}); fan.flush()
        check(len(fake.of("PATCH", LFG_HOOK)) == 1 and len(fake.of("PATCH", OTHER_LFG)) == 1,
              "the lobby closing strikes the announcement through on both")
        fake.reset()
        fan.stop()
        check(len(fake.of("PATCH", BOARD_HOOK)) == 1 and len(fake.of("PATCH", OTHER_BOARD)) == 1
              and fake.of("PATCH", OTHER_BOARD)[0][2]["embeds"][0]["color"] == lobbyboard.COLOR_OFFLINE,
              "a clean stop paints both boards offline")
        conn = store.connect(fandb)
        check(store.meta_get(conn, f"discord.board.{OTHER_BOARD}") is not None
              and store.meta_get(conn, f"discord.board.{BOARD_HOOK}") is not None,
              "each board's message id is kept under its own webhook id, so a restart edits both")
        conn.close()
        lone = lobbyboard.Fanout()
        check(lone.configure("", "", "", "", None, None, []) == [] and lone.start(fandb) is False
              and not lone.enabled, "nothing configured anywhere: off, as before")

        print("-- the leaderboards (§76)")
        check(lobbyboard.period_text("week", 1_789_000_000) == "week 37 of 2026"
              and lobbyboard.period_text("month", 1_789_000_000) == "September 2026"
              and lobbyboard.period_text("year", 1_789_000_000) == "2026",
              "a windowed board's heading names its period: week 37 of 2026, September 2026, 2026")
        check(lobbyboard.next_turn(utc(2026, 9, 23, 15, 30)) == utc(2026, 9, 28)
              and lobbyboard.next_turn(utc(2026, 9, 21)) == utc(2026, 9, 28)
              and lobbyboard.next_turn(utc(2026, 10, 31, 12)) == utc(2026, 11, 1)
              and lobbyboard.next_turn(utc(2026, 12, 30, 12)) == utc(2027, 1, 1),
              "next_turn() is the next Monday, unless a month or a year begins first; "
              "a Monday at 00:00 is already the new week")
        e = lobbyboard.render_leaderboards(
            "Leader boards", ((5, "Permanent", "", ((1, "wormy", 440), (1, "bo", 440),
                                                    (3, "snailhead", 360)), 12),
                              (2, "Weekly", "week 37 of 2026", (), 0)),
            "up", 1_789_000_000, None, 400)
        f5, f2 = e["fields"]
        check(e["color"] == lobbyboard.COLOR_LEADER and e["description"].startswith(
                  "Ranked rating, best first. Everyone starts at 400")
              and e["timestamp"] == "2026-09-10T00:26:40+00:00" and e["footer"]["text"] == "Updated",
              "the leaderboards embed: gold, the starting rating in the blurb, an 'Updated' stamp")
        check(f5["name"] == "Permanent" and f5["value"] ==
              "```\n 1. wormy      440\n 1. bo         440\n 3. snailhead  360\n```*…and 9 more*"
              and f2["name"] == "Weekly — week 37 of 2026" and f2["value"] == "*Nobody yet.*",
              "...a field per board: rank, name and score in aligned columns, ties sharing a rank, "
              "'and N more', an empty board saying so, the period in the heading")
        o = lobbyboard.render_leaderboards("Leader boards", (), "offline", 1_700_000_000)
        check(o["color"] == lobbyboard.COLOR_OFFLINE and "Server offline since <t:1700000000:R>"
              in o["description"] and "fields" not in o, "...and offline is the red offline line")
        big = tuple((r, f"name{r:02d}", 1000 - r) for r in range(1, 31))
        e = lobbyboard.render_leaderboards("L", ((5, "Permanent", "", big, 30),), "up", 0)
        check(e["fields"][0]["value"].count("\n") == lobbyboard.MAX_ROWS + 1
              and "and 5 more" in e["fields"][0]["value"] and len(e["fields"][0]["value"]) < 1024,
              f"thirty rows: {lobbyboard.MAX_ROWS} lines and 'and 5 more', inside Discord's field limit")

        lb = lobbyboard.LeaderBoard()
        bad = lb.configure("https://discord.com/api/webhooks/x/y", "", 0)
        check(len(bad) == 2 and "leaderboard_webhook is not a webhook URL" in bad[0]
              and "leaderboard_rows must be 1 to 25" in bad[1] and lb.rows == 10 and not lb.url
              and lb.title == "Leader boards",
              "a malformed webhook URL and a row count out of range are reported, the defaults stand")
        LOGGED.clear()
        lb = lobbyboard.LeaderBoard()
        lb.configure(fake.url(LEAD_HOOK))
        check(lb.start(None) is False and not lb.enabled and any("need the store" in m for m in LOGGED),
              "started without a store: off, with a line saying so")

        fake.reset()
        LOGGED.clear()
        ldb = root / "leaders.sqlite3"
        store.connect(ldb).close()
        lb = leaders(fake, ldb)
        check(lb.flush(3) and len(fake.of("POST", LEAD_HOOK)) == 1
              and [f["name"].split(" — ")[0] for f in embed_of(fake.of("POST", LEAD_HOOK)[0])["fields"]]
              == ["Permanent", "Weekly", "Monthly", "Yearly"]
              and all(f["value"] == "*Nobody yet.*" for f in embed_of(fake.of("POST", LEAD_HOOK)[0])["fields"])
              and any("leaderboard message" in m for m in LOGGED),
              "start() posts the leaderboards at once: Permanent, Weekly, Monthly, Yearly, all empty")
        lead_id = str(fake.next_id)
        conn = store.connect(ldb)
        saved = store.meta_get(conn, f"discord.leaderboard.{LEAD_HOOK}")
        conn.close()
        check(saved == lead_id, f"...and its message id {saved} is in the meta table under the "
                                f"webhook id, apart from the lobby board's")
        seed(ldb, [(5, f"player{i:02d}", 1000 - 10 * i, None) for i in range(1, 13)]
                  + [(5, "boggyb", 990, None)]
                  + [(2, "boggyb", 440, statsdb.period_key(2)), (2, "oldtimer", 999, "2020-W01"),
                     (3, "boggyb", 440, statsdb.period_key(3)), (4, "boggyb", 440, statsdb.period_key(4))])
        fake.reset()
        t0 = time.monotonic()
        lb.scored(5)
        took = time.monotonic() - t0
        lb.flush(3)
        edits = fake.of("PATCH", LEAD_HOOK)
        f5 = field(edits[0], "Permanent") if edits else {"value": ""}
        check(took < 0.02 and len(edits) == 1 and edits[0][1].endswith(f"/messages/{lead_id}")
              and not fake.of("POST", LEAD_HOOK),
              f"a score on board 5: scored() returns at once ({took * 1000:.1f} ms), the message is "
              f"EDITED, nothing new posted")
        tied = sorted(["player01", "boggyb"], key=store.account_handle)     # a tie is ordered by entity id
        check(f5["value"].startswith(f"```\n 1. {tied[0]:<8}  990\n 1. {tied[1]:<8}  990\n 3. player02  980\n")
              and f5["value"].count("\n") == 11 and f5["value"].endswith("```*…and 3 more*"),
              "...Permanent: ten rows of thirteen, best first, a tie sharing rank 1, 'and 3 more'")
        f2 = field(edits[0], "Weekly")
        check(f2 and f2["name"] == "Weekly — " + lobbyboard.period_text("week", time.time())
              and f2["value"] == "```\n 1. boggyb  440\n```" and "oldtimer" not in f2["value"],
              "...Weekly: this week's row only, the row from 2020 ignored, the week in the heading")
        fake.reset()
        lb.scored(1)
        lb.scored(9)
        lb.scored(29)
        lb.flush(3)
        check(fake.calls == [], "a score on a board the message does not show (1, 9, 29) repaints nothing")
        for b in (2, 3, 4, 5, 2, 3, 4, 5):
            lb.scored(b)
        lb.flush(3)
        check(len(fake.of("PATCH", LEAD_HOOK)) == 1,
              "a match start's burst on boards 2-5, twice over: ONE edit")

        fake.reset()
        lb.next_turn = lambda now: now + 0.2
        lb.scored(5)
        lb.flush(3)
        fake.reset()
        time.sleep(1.7)
        turned = fake.of("PATCH", LEAD_HOOK)
        check(len(turned) >= 1 and field(turned[0], "Weekly") is not None,
              f"the period turning (next_turn a second away) repaints the message with nothing scored "
              f"({len(turned)} edit(s))")
        lb.next_turn = lobbyboard.next_turn
        was = statsdb.PERIOD_BOARDS_ON
        statsdb.PERIOD_BOARDS_ON = False
        due_off = lb._due()
        statsdb.PERIOD_BOARDS_ON = was
        due_on = lb._due()
        check(due_off is None and due_on is not None and 1.0 <= due_on <= 8 * 86400,
              "with stats.period_boards off there is no timed wake; on, it is within the week")

        fake.reset()
        lb.stop(timeout=3)
        edits = fake.of("PATCH", LEAD_HOOK)
        check(edits and embed_of(edits[-1])["color"] == lobbyboard.COLOR_OFFLINE
              and "Server offline" in embed_of(edits[-1])["description"] and not lb.enabled,
              "stop() paints the leaderboards offline, in red")
        lb._thread.join(2)
        check(not lb._thread.is_alive() and lb._conn is None,
              "...the worker has exited and closed its own store connection")
        fake.reset()
        lb2 = leaders(fake, ldb)
        lb2.flush(3)
        check(not fake.of("POST", LEAD_HOOK) and len(fake.of("PATCH", LEAD_HOOK)) == 1
              and fake.of("PATCH", LEAD_HOOK)[0][1].endswith(f"/messages/{lead_id}")
              and field(fake.of("PATCH", LEAD_HOOK)[0], "Permanent")["value"].count("\n") == 11,
              "a new server on the same store edits the SAME message, with the rows it holds")
        lb2.stop(timeout=3)

        fake.reset()
        fan = lobbyboard.Fanout()
        bad = fan.configure(fake.url(BOARD_HOOK), "", "", "Open lobbies", None, None,
                            [{"name": "Worms Central", "leaderboard_webhook": fake.url(OTHER_LEAD),
                              "leaderboard_title": "Top worms",
                              "leaderboard_empty_text": "No one on this one yet."}],
                            fake.url(LEAD_HOOK), "Ranked", 5, 400)
        check(bad == [] and len(fan.leaders) == 2 and fan.leaders[0].url == fake.url(LEAD_HOOK)
              and fan.leaders[0].title == "Ranked" and fan.leaders[0].rows == 5
              and fan.leaders[1].label == "discord.also[0] (Worms Central)"
              and fan.leaders[1].title == "Top worms" and fan.leaders[1].rows == 5
              and fan.leaders[1].text["leaderboard_empty_text"] == "No one on this one yet."
              and len(fan.boards) == 2 and not fan.boards[1].url,
              "the fan-out: the operator's leaderboards, and a second server's from a table with "
              "only leaderboard_webhook (its own title and line, the row count inherited), no complaint")
        for b in fan.boards + fan.leaders:
            b.debounce = 0.15
        fan.start(ldb)
        fan.flush(3)
        fan.scored(5)
        fan.flush(3)
        home = fake.of("PATCH", LEAD_HOOK)
        other = fake.of("PATCH", OTHER_LEAD)
        check(len(fake.of("POST", LEAD_HOOK)) == 0 and len(fake.of("POST", OTHER_LEAD)) == 1
              and len(home) == 2 and len(other) == 1
              and embed_of(other[0])["title"] == "Top worms"
              and field(other[0], "Permanent")["value"].count("\n") == 6
              and field(other[0], "Monthly")["value"] == "```\n 1. boggyb  440\n```",
              "...a score edits both (the operator's message is the one from before, the second "
              "server's is new), the second under its own title with five rows")
        fake.reset()
        fan.stop()
        check(len(fake.of("PATCH", LEAD_HOOK)) == 1 and len(fake.of("PATCH", OTHER_LEAD)) == 1
              and len(fake.of("PATCH", BOARD_HOOK)) == 1,
              "a clean stop paints every board offline, the leaderboards with the lobby boards")
        fake.reset()
        LOGGED.clear()
        fake.dead.add(DEAD_HOOK)
        lb3 = leaders(fake, ldb, hook=DEAD_HOOK)
        lb3.flush(3)
        check(not lb3.enabled and any("does not exist any more (404 on POST)" in m
                                      and "Leaderboard off" in m for m in LOGGED),
              "a leaderboards webhook deleted on Discord's side turns that message off, "
              "with the line that says so")
        lb3.stop(timeout=2)
    finally:
        fake.close()
        if keep:
            print(f"(scratch kept at {root})")
        else:
            shutil.rmtree(root, ignore_errors=True)
    passed = sum(1 for ok, _ in RESULTS if ok)
    print(f"\n{passed} of {len(RESULTS)} passed")
    for ok, what in RESULTS:
        if not ok:
            print(f"  FAILED: {what}")
    return 0 if passed == len(RESULTS) else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--keep", action="store_true")
    return run(ap.parse_args().keep)


if __name__ == "__main__":
    raise SystemExit(main())
