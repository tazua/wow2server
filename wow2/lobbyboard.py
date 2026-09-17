#!/usr/bin/env python3
"""The Discord lobby board: one message in a channel that always shows the
live session list, and an optional announcement when a lobby opens. Fed by
the server's session handlers, posted through Discord webhooks from a worker
thread that never blocks a handler (netrecon §69; tools/README.md
"lobbyboard.py"; the [discord] section of wow2-server.example.toml).
"""
from __future__ import annotations

import json
import re
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

_log = print


def set_logger(fn) -> None:
    """The server owns the session log; borrow it rather than opening another."""
    global _log
    _log = fn


WEBHOOK_RE = re.compile(r"^https?://[^/]+/api/webhooks/(\d+)/[^/?#]+/?$")

COLOR_OPEN = 0x57F287
COLOR_EMPTY = 0x99AAB5
COLOR_OFFLINE = 0xED4245

DEBOUNCE = 2.0
ANNOUNCE_COOLDOWN = 300.0
RETRY_DELAY = 30.0
HTTP_TIMEOUT = 10.0
RETRY_AFTER_MAX = 30.0
MAX_ROWS = 25
MAX_NOTES = 200
LOG_INTERVAL = 60.0

NO_PINGS = {"parse": []}
ALL_PINGS = {"parse": ["roles", "users", "everyone"]}

# What the board says, as templates; a deployment gives the poster a voice in
# [discord] (wow2-server.example.toml lists the fields each one may use).
DEFAULT_TEXT = {
    "announce_text": "{mention} \U0001F3AE **{name}** opened a {mode} lobby ({count}) "
                     "— sign in and join it from Find Game!",
    "closed_text": "~~\U0001F3AE **{name}** opened a {mode} lobby~~ — closed {when}",
    "empty_text": "*No open lobbies. Host one from the Infrastructure menu and it "
                  "appears here.*",
    "offline_text": "\U0001F534 *Server offline since {when}.*",
}
TEXT_FIELDS = {
    "announce_text": {"mention": "<@&1>", "name": "x", "mode": "ranked", "count": "1/4",
                      "players": 1, "max": 4},
    "closed_text": {"name": "x", "mode": "ranked", "count": "1/4", "when": "<t:0:R>"},
    "empty_text": {"when": "<t:0:R>"},
    "offline_text": {"when": "<t:0:R>"},
}


def check_text(text: dict) -> tuple[dict, list[str]]:
    """The templates a deployment set, each tried once; a broken one is replaced
    by the default and named."""
    out, bad = dict(DEFAULT_TEXT), []
    for key, tmpl in (text or {}).items():
        if key not in DEFAULT_TEXT:
            continue
        try:
            str(tmpl).format(**TEXT_FIELDS[key])
        except (KeyError, IndexError, ValueError) as e:
            bad.append(f"discord.{key} cannot be filled in ({e!r}; the fields are "
                       f"{', '.join('{' + f + '}' for f in TEXT_FIELDS[key])}) -- using the default")
            continue
        if str(tmpl).strip():
            out[key] = str(tmpl)
    return out, bad


def webhook_id(url: str) -> str:
    """The id of a well-formed webhook URL, else "" (what configure() checks)."""
    m = WEBHOOK_RE.match(url or "")
    return m.group(1) if m else ""


def _id_in(url: str) -> str:
    """The id out of any URL built on a webhook, for a log line."""
    m = re.search(r"/api/webhooks/(\d+)/", url or "")
    return m.group(1) if m else "?"


def snapshot(sessions: dict) -> tuple:
    """What the board needs from the live session table, cheap to take and safe
    to hand to another thread: open lobbies first, newest first, like the browser.
    """
    rows = []
    for rec in sessions.values():
        mx = int(rec.get("max_players") or 0)
        n = int(rec.get("players") or 0)
        rows.append((bool(mx) and n >= mx, -int(rec.get("id") or 0),
                     str(rec.get("name") or "?"), n, mx, bool(rec.get("points")),
                     int(rec.get("created") or 0)))
    rows.sort()
    return tuple((name, n, mx, ranked, created, full)
                 for full, _neg, name, n, mx, ranked, created in rows)


def render_board(title: str, rows: tuple, state: str, now: float,
                 text: dict | None = None) -> dict:
    """The embed for a snapshot. `state` is "up" or "offline"."""
    text = text or DEFAULT_TEXT
    when = f"<t:{int(now)}:R>"
    if state == "offline":
        return {"title": title, "color": COLOR_OFFLINE,
                "description": text["offline_text"].format(when=when)}
    lines = []
    for name, n, mx, ranked, created, full in rows[:MAX_ROWS]:
        dot = "\U0001F534" if full else "\U0001F7E2"
        count = f"{n}/{mx}" if mx else f"{n} player{'s' if n != 1 else ''}"
        line = (f"{dot} **{name}** — {count}{' full' if full else ''} — "
                f"{'ranked' if ranked else 'friendly'}")
        if created:
            line += f" — opened <t:{created}:R>"
        lines.append(line)
    if len(rows) > MAX_ROWS:
        lines.append(f"*…and {len(rows) - MAX_ROWS} more*")
    if not lines:
        lines.append(text["empty_text"].format(when=when))
    lines += ["", f"Updated {when}"]
    return {"title": title, "color": COLOR_OPEN if rows else COLOR_EMPTY,
            "description": "\n".join(lines)}


def count_text(n: int, mx: int) -> str:
    return f"{n}/{mx}" if mx else f"{n} player{'s' if n != 1 else ''}"


def render_announcement(mention: str, name: str, ranked: bool, n: int, mx: int,
                        text: dict | None = None) -> str:
    tmpl = (text or DEFAULT_TEXT)["announce_text"]
    return tmpl.format(mention=mention or "", name=name,
                       mode="ranked" if ranked else "friendly",
                       count=count_text(n, mx), players=n, max=mx).strip()


def render_closed(name: str, ranked: bool, now: float, n: int = 0, mx: int = 0,
                  text: dict | None = None) -> str:
    tmpl = (text or DEFAULT_TEXT)["closed_text"]
    return tmpl.format(name=name, mode="ranked" if ranked else "friendly",
                       count=count_text(n, mx), when=f"<t:{int(now)}:R>").strip()


class LobbyBoard:
    """The board and the announcements, behind one worker thread."""

    def __init__(self) -> None:
        self.enabled = False
        self.lobby_url = ""
        self.announce_url = ""
        self.mention = ""
        self.title = "Open lobbies"
        self.text = dict(DEFAULT_TEXT)
        self.debounce = DEBOUNCE
        self.cooldown = ANNOUNCE_COOLDOWN
        self.retry_delay = RETRY_DELAY
        self.db_path: Path | None = None
        self._cv = threading.Condition()
        self._latest: tuple | None = None
        self._events: list[tuple] = []
        self._pending = 0
        self._stopping = False
        self._state = "up"
        self._thread: threading.Thread | None = None
        self._board_id: str | None = None
        self._notes: dict[int, tuple[str, str, bool, int, int]] = {}
        self._last_open: dict[str, float] = {}
        self._last_sid: dict[str, int] = {}
        self._muted_until = 0.0
        self.posted = 0

    # ------------------------------------------------------------ the server side
    def configure(self, lobby_url: str = "", announce_url: str = "", mention: str = "",
                  title: str = "Open lobbies", text: dict | None = None,
                  cooldown: float | None = None) -> list[str]:
        """Take the settings; returns the problems (an empty list is good)."""
        self.text, bad = check_text(text)
        if cooldown is not None:
            self.cooldown = max(0.0, float(cooldown))
        for what, url in (("lobby_webhook", lobby_url), ("announce_webhook", announce_url)):
            if url and not webhook_id(url):
                bad.append(f"discord.{what} is not a webhook URL "
                           f"(https://discord.com/api/webhooks/<id>/<token>)")
        self.lobby_url = lobby_url if webhook_id(lobby_url) else ""
        self.announce_url = announce_url if webhook_id(announce_url) else ""
        self.mention = (mention or "").strip()
        self.title = title or "Open lobbies"
        return bad

    def start(self, db_path: Path | str | None = None) -> bool:
        """Start the worker if anything is configured. The board is posted at once."""
        if not self.lobby_url and not self.announce_url:
            return False
        self.db_path = Path(db_path) if db_path else None
        self.enabled = True
        self._stopping = False
        self._state = "up"
        self._thread = threading.Thread(target=self._run, name="lobbyboard", daemon=True)
        self._thread.start()
        self.refresh({})
        return True

    def refresh(self, sessions: dict) -> None:
        """The session table changed. Called from the loop thread; returns at once."""
        if not self.enabled or not self.lobby_url:
            return
        self._offer(snapshot(sessions))

    def opened(self, rec: dict) -> None:
        """A session was created: a fresh ping, or, inside the host's cooldown, the
        host's last announcement edited back to open (an edit pings nobody)."""
        if not self.enabled or not self.announce_url:
            return
        name = str(rec.get("name") or "?")
        sid = int(rec.get("id") or 0)
        ranked = bool(rec.get("points"))
        n, mx = int(rec.get("players") or 0), int(rec.get("max_players") or 0)
        text = render_announcement(self.mention, name, ranked, n, mx, self.text)
        now = time.time()
        if now - self._last_open.get(name, 0.0) < self.cooldown:
            prev = self._last_sid.get(name)
            if prev is not None:
                self._queue(("reopen", sid, name, ranked, text, n, mx, prev))
                self._last_sid[name] = sid
            return
        self._last_open[name] = now
        self._last_sid[name] = sid
        self._queue(("open", sid, name, ranked, text, n, mx, None))

    def closed(self, sid: int) -> None:
        """A session went away: strike its announcement through."""
        if not self.enabled or not self.announce_url:
            return
        self._queue(("close", int(sid), "", False, "", 0, 0, None))

    def stop(self, timeout: float = 5.0) -> None:
        """Mark the board offline and wait (bounded) for the worker to say so."""
        if not self.enabled:
            return
        with self._cv:
            self._state = "offline"
            self._stopping = True
        if self.lobby_url:
            self._offer(())
        with self._cv:
            self._cv.notify()
        self.flush(timeout)
        self.enabled = False

    def flush(self, timeout: float = 10.0) -> bool:
        """Wait until every queued post has been attempted. Returns False on timeout."""
        deadline = time.monotonic() + timeout
        with self._cv:
            while self._pending:
                left = deadline - time.monotonic()
                if left <= 0:
                    return False
                self._cv.wait(left)
        return True

    # ---------------------------------------------------------------- the worker
    def _offer(self, snap: tuple) -> None:
        with self._cv:
            if self._latest is None:
                self._pending += 1
            self._latest = snap
            self._cv.notify()

    def _queue(self, ev: tuple) -> None:
        with self._cv:
            self._events.append(ev)
            self._pending += 1
            self._cv.notify()

    def _run(self) -> None:
        self._load_ids()
        if self.announce_url:
            self._call("GET", self.announce_url, None)    # a deleted webhook answers 404 now, not at the first lobby
        failed: tuple | None = None
        retry_at = 0.0
        while True:
            with self._cv:
                while not self._events and self._latest is None:
                    if self._stopping:
                        return
                    if failed is not None and self.enabled:
                        left = retry_at - time.monotonic()
                        if left <= 0:
                            self._latest, failed = failed, None
                            self._pending += 1
                            break
                        self._cv.wait(left)
                    else:
                        failed = None
                        self._cv.wait()
                events, self._events = self._events, []
                snap = self._latest
            for ev in events:
                try:
                    self._do_event(ev)
                finally:
                    self._done()
            if snap is None:
                continue
            if not self._stopping:
                time.sleep(self.debounce)
            with self._cv:
                snap, self._latest = self._latest, None
            try:
                ok = self._post_board(snap)
            finally:
                self._done()
            if ok or self._stopping:
                failed = None
            else:
                failed, retry_at = snap, time.monotonic() + self.retry_delay

    def _done(self) -> None:
        with self._cv:
            self._pending = max(0, self._pending - 1)
            self._cv.notify_all()

    def _do_event(self, ev: tuple) -> None:
        kind, sid, name, ranked, text, n, mx, prev = ev
        if kind == "open":
            mid = self._send(self.announce_url,
                             {"content": text, "allowed_mentions": ALL_PINGS})
            if mid:
                self._notes[sid] = (mid, name, ranked, n, mx)
                while len(self._notes) > MAX_NOTES:
                    self._notes.pop(next(iter(self._notes)))
        elif kind == "reopen":
            note = self._notes.pop(prev, None) or self._notes.pop(sid, None)
            if note is None:
                return
            mid = note[0]
            if self._edit(self.announce_url, mid,
                          {"content": text, "allowed_mentions": NO_PINGS}) == 200:
                self._notes[sid] = (mid, name, ranked, n, mx)
        elif kind == "close":
            note = self._notes.get(sid)       # kept: a re-host inside the cooldown edits it back
            if note:
                mid, name, ranked, n, mx = note
                self._edit(self.announce_url, mid,
                           {"content": render_closed(name, ranked, time.time(), n, mx,
                                                     self.text),
                            "allowed_mentions": NO_PINGS})

    def _post_board(self, snap: tuple) -> bool:
        embed = render_board(self.title, snap, self._state, time.time(), self.text)
        body = {"content": "", "embeds": [embed], "allowed_mentions": NO_PINGS}
        if self._board_id:
            status = self._edit(self.lobby_url, self._board_id, body)
            if status != 404:
                return status == 200
            self._board_id = None
        mid = self._send(self.lobby_url, body)
        if not mid:
            return False
        self._board_id = mid
        self._save_id(mid)
        _log(f"discord: board message {mid} posted through webhook {_id_in(self.lobby_url)}")
        return True

    # ------------------------------------------------------------------- HTTP
    def _send(self, url: str, body: dict) -> str | None:
        """POST a new message; the message id, or None."""
        status, data = self._call("POST", url + "?wait=true", body)
        if status == 200 and isinstance(data, dict) and data.get("id"):
            self.posted += 1
            return str(data["id"])
        return None

    def _edit(self, url: str, mid: str, body: dict) -> int:
        status, _data = self._call("PATCH", f"{url}/messages/{mid}", body)
        if status == 200:
            self.posted += 1
        return status

    def _call(self, method: str, url: str, body: dict, retried: bool = False):
        if not self.enabled:
            return 0, None
        req = urllib.request.Request(url, method=method,
                                     data=None if body is None else json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json",
                                              "User-Agent": "wow2-server lobbyboard"})
        try:
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r:
                raw = r.read()
                return r.status, (json.loads(raw) if raw else None)
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                payload = json.loads(raw) if raw else None
            except ValueError:
                payload = None
            if e.code == 429 and not retried:
                wait = 1.0
                if isinstance(payload, dict):
                    try:
                        wait = float(payload.get("retry_after", wait))
                    except (TypeError, ValueError):
                        pass
                time.sleep(min(max(wait, 0.0), RETRY_AFTER_MAX))
                return self._call(method, url, body, retried=True)
            if e.code in (401, 403):
                _log(f"!! discord: webhook {_id_in(url)} refused us ({e.code}); "
                     f"the URL is wrong or the webhook was deleted -- board off "
                     f"until restart")
                self.enabled = False
            elif e.code == 404 and method != "PATCH":
                _log(f"!! discord: webhook {_id_in(url)} does not exist any more "
                     f"(404 on {method}); it was deleted on Discord's side -- make a "
                     f"new one, put its URL in [discord], restart. Board and pings "
                     f"off until then")
                self.enabled = False
            elif e.code != 404:
                self._complain(f"discord: {method} to webhook {_id_in(url)} "
                               f"answered {e.code}: {str(payload)[:120]}")
            return e.code, payload
        except (urllib.error.URLError, OSError, ValueError) as e:
            self._complain(f"discord: {method} to webhook {_id_in(url)} failed: {e}")
            return 0, None

    def _complain(self, msg: str) -> None:
        now = time.monotonic()
        if now >= self._muted_until:
            _log(f"!! {msg}")
            self._muted_until = now + LOG_INTERVAL

    # ------------------------------------------------------------ persistence
    def _key(self) -> str:
        return f"discord.board.{webhook_id(self.lobby_url)}"

    def _load_ids(self) -> None:
        if not self.db_path or not self.lobby_url:
            return
        try:
            import store
            conn = store.connect(self.db_path)
            try:
                self._board_id = store.meta_get(conn, self._key()) or None
            finally:
                conn.close()
        except Exception as e:                                       # noqa: BLE001
            _log(f"!! discord: could not read the board's message id ({e}); "
                 f"posting a fresh one")

    def _save_id(self, mid: str) -> None:
        if not self.db_path:
            return
        try:
            import store
            conn = store.connect(self.db_path)
            try:
                with store.tx(conn):
                    store.meta_set(conn, self._key(), mid)
            finally:
                conn.close()
        except Exception as e:                                       # noqa: BLE001
            _log(f"!! discord: could not save the board's message id ({e}); "
                 f"the next start will post a new one")


BOARD = LobbyBoard()
