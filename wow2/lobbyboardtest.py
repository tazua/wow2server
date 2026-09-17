#!/usr/bin/env python3
"""Does the Discord lobby board post what the session table says, coalesce a
burst into one edit, survive Discord being down, and never block the caller?
No Discord, no emulator: a fake webhook endpoint in this process records
every request and answers what the checks tell it to (netrecon §69).

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
import store                                                    # noqa: E402

RESULTS: list[tuple[bool, str]] = []
LOGGED: list[str] = []

BOARD_HOOK, LFG_HOOK, BAD_HOOK, DEAD_HOOK = "100100100", "200200200", "300300300", "400400400"


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


def rec(sid: int, name: str, players=1, max_players=4, points=0, created=None) -> dict:
    return {"id": sid, "name": name, "players": players, "max_players": max_players,
            "points": points, "created": created or int(time.time()) - 60}


def embed_of(call) -> dict:
    return call[2]["embeds"][0]


def run(keep: bool) -> int:
    lobbyboard.set_logger(capture_log)
    root = Path(tempfile.mkdtemp(prefix="wow2-lobbyboardtest-"))
    fake = FakeDiscord()
    db = root / "wow2.sqlite3"
    try:
        print("-- configuration")
        b = lobbyboard.LobbyBoard()
        bad = b.configure("https://discord.com/api/webhooks/not-a-number/tok", "", "", "")
        check(len(bad) == 1 and "lobby_webhook" in bad[0] and not b.lobby_url,
              "a malformed webhook URL is reported and that side is left off")
        b = lobbyboard.LobbyBoard()
        check(b.configure("https://discord.com/api/webhooks/123/AbC_-xyz", "", "", "") == []
              and b.lobby_url.endswith("/123/AbC_-xyz"),
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
        b.opened(sessions[0x5701])
        b.flush(3)
        check(len(fake.of("POST", LFG_HOOK)) == 1, "the same host again inside the cooldown: no second ping")
        b.opened(sessions[0x5702])
        b.flush(3)
        check(len(fake.of("POST", LFG_HOOK)) == 2
              and "friendly lobby (2/4)" in fake.of("POST", LFG_HOOK)[1][2]["content"],
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
