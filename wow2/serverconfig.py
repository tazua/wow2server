#!/usr/bin/env python3
"""Deployment configuration for the WOW2 server: one file, safe defaults.
Precedence is environment > config file > built-in defaults, and every key is
documented in wow2-server.example.toml.

    WOW2_CONFIG=/etc/wow2-server.toml tools/wow2 server start
"""
from __future__ import annotations

import os
import tomllib
from pathlib import Path

ROOT = Path(os.environ.get("WOW2_ROOT", Path(__file__).resolve().parent.parent))

_RIG_TREE = (ROOT / "tools" / "authserver.py").is_file()
_PUBLIC_TREE = (not _RIG_TREE and (ROOT / "wow2" / "authserver.py").is_file()
                and (ROOT / "pyproject.toml").is_file())
_IN_SOURCE_TREE = _RIG_TREE or _PUBLIC_TREE
_DEFAULT_DATA = (ROOT / "capture" if _RIG_TREE
                 else ROOT / "wow2-data" if _PUBLIC_TREE
                 else Path.cwd() / "wow2-data")

SEARCH = [
    os.environ.get("WOW2_CONFIG"),
    "wow2-server.toml",
    str(ROOT / "wow2-server.toml"),
    "/etc/wow2-server.toml",
]

DEFAULTS: dict[str, dict] = {
    "server": {
        "bind": "0.0.0.0",
        "port": 3074,
    },
    "accounts": {
        "shared_password_fallback": False,
        "create_mode": "refuse_duplicates",
    },
    "logging": {
        "hexdumps": False,
        "level": "info",
    },
    "limits": {
        "max_msgs_per_sec": 100,
        "max_conns_per_ip": 16,
        "max_stream_bytes": 4 * 1024 * 1024,
        "max_creates_per_ip_per_hour": 20,
    },
    "nat": {
        "relay": False,
        "relay_port_base": 40000,
        "relay_ports": 32,
        "relay_idle_timeout": 600,
        "public_address": "",
        # ---- NAT TYPE DISCOVERY (the game's own three-test STUN probe) ----
        "nat_type": True,
        "nat_type_alt_port": 3078,
        "nat_type_alt_address": "",
    },
    "stats": {
        "starting_rating": 400,
        "period_boards": True,
    },
    "storage": {
        "data_dir": str(_DEFAULT_DATA),
    },
    "discord": {
        "lobby_webhook": "",
        "announce_webhook": "",
        "mention": "",
        "title": "Open lobbies",
        "announce_text": "",
        "closed_text": "",
        "empty_text": "",
        "offline_text": "",
        "announce_cooldown": 300,
        # ---- THE PASSWORD BOT (wow2-discordbot; DOCS.md "Discord") ----
        "bot_guild": 0,
        "bot_admin_roles": ["Admin", "Moderator"],
        "bot_help_channel": "connection-help",
        "bot_claims_per_day": 3,
        "bot_text": "",
    },
}


def _read_file() -> tuple[dict, str | None]:
    """Load the first config file that exists. A BROKEN one is fatal."""
    for cand in SEARCH:
        if not cand:
            continue
        p = Path(cand)
        try:
            found = p.is_file()
        except OSError:    # a cwd the service user cannot read (sudo -u from /root)
            found = False
        if found:
            try:
                with open(p, "rb") as f:
                    return tomllib.load(f), str(p)
            except (OSError, tomllib.TOMLDecodeError) as e:
                print(f"!! {p} could not be read: {e}", flush=True)
                print("   Refusing to start on the built-in defaults, because "
                      "they are not what you asked for.", flush=True)
                print("   (TOML has no bare words: strings need quotes, as in "
                      'level = "info".)', flush=True)
                raise SystemExit(2)
    return {}, None


_FILE, PATH = _read_file()


def _merged() -> dict[str, dict]:
    out = {k: dict(v) for k, v in DEFAULTS.items()}
    for section, values in _FILE.items():
        if isinstance(values, dict):
            out.setdefault(section, {}).update(values)
    return out


_CFG = _merged()


def unknown_keys() -> list[str]:
    """Keys in the config file that no setting reads, each with its nearest
    real name; a misspelt key is otherwise a setting silently left at default."""
    import difflib
    out = []
    for section, values in _FILE.items():
        if not isinstance(values, dict):
            out.append(f"{section} (not a section)")
            continue
        known = DEFAULTS.get(section)
        if known is None:
            out.append(f"[{section}] (not a section this server reads)")
            continue
        for key in values:
            if key not in known:
                near = difflib.get_close_matches(key, list(known), n=1, cutoff=0.6)
                out.append(f"{section}.{key}" + (f" (did you mean {near[0]}?)" if near else ""))
    return out

_ENV = {
    ("server", "bind"): ("WOW2_BIND", str),
    ("server", "port"): ("WOW2_PORT", int),
    ("accounts", "shared_password_fallback"): ("WOW2_SHARED_PASSWORD_FALLBACK",
                                               lambda v: v not in ("0", "false", "no")),
    ("accounts", "create_mode"): ("WOW2_CREATE_MODE", str),
    ("logging", "hexdumps"): ("WOW2_HEXDUMPS", lambda v: v not in ("0", "false", "no")),
    ("logging", "level"): ("WOW2_LOG_LEVEL", str),
    ("storage", "data_dir"): ("WOW2_DATA_DIR", str),
    ("stats", "starting_rating"): ("WOW2_STARTING_RATING", int),
    ("stats", "period_boards"): ("WOW2_PERIOD_BOARDS", lambda v: v not in ("0", "false", "no", "off")),
    ("limits", "max_msgs_per_sec"): ("WOW2_MAX_MSGS_PER_SEC", int),
    ("limits", "max_conns_per_ip"): ("WOW2_MAX_CONNS_PER_IP", int),
    ("limits", "max_stream_bytes"): ("WOW2_MAX_STREAM_BYTES", int),
    ("limits", "max_creates_per_ip_per_hour"): ("WOW2_MAX_CREATES_PER_IP_PER_HOUR", int),
    ("nat", "relay"): ("WOW2_NAT_RELAY", lambda v: v not in ("0", "false", "no", "off")),
    ("nat", "public_address"): ("WOW2_RELAY_PUBLIC_ADDRESS", str),
    ("nat", "relay_port_base"): ("WOW2_RELAY_PORT_BASE", int),
    ("nat", "relay_ports"): ("WOW2_RELAY_PORTS", int),
    ("nat", "nat_type"): ("WOW2_NO_NAT_TYPE",
                          lambda v: v in ("0", "false", "no", "off")),
    ("nat", "nat_type_alt_port"): ("WOW2_NAT_TYPE_ALT_PORT", int),
    ("nat", "nat_type_alt_address"): ("WOW2_NAT_TYPE_ALT_ADDRESS", str),
    ("discord", "lobby_webhook"): ("WOW2_DISCORD_LOBBY_WEBHOOK", str),
    ("discord", "announce_webhook"): ("WOW2_DISCORD_ANNOUNCE_WEBHOOK", str),
    ("discord", "mention"): ("WOW2_DISCORD_MENTION", str),
    ("discord", "bot_guild"): ("WOW2_DISCORD_BOT_GUILD", int),
    ("discord", "bot_claims_per_day"): ("WOW2_DISCORD_BOT_CLAIMS_PER_DAY", int),
}
for (_sec, _key), (_env, _cast) in _ENV.items():
    _raw = os.environ.get(_env)
    if _raw is not None:
        try:
            _CFG.setdefault(_sec, {})[_key] = _cast(_raw)
        except ValueError:
            print(f"!! {_env}={_raw!r} is not valid; ignoring", flush=True)


def get(section: str, key: str):
    return _CFG.get(section, {}).get(key, DEFAULTS.get(section, {}).get(key))


BIND = get("server", "bind")
PORT = int(get("server", "port"))
SHARED_PASSWORD_FALLBACK = bool(get("accounts", "shared_password_fallback"))
CREATE_MODE = get("accounts", "create_mode")
HEXDUMPS = bool(get("logging", "hexdumps"))
LOG_LEVEL = str(get("logging", "level")).lower()
DEBUG = LOG_LEVEL == "debug"
DATA_DIR = Path(get("storage", "data_dir"))
MAX_MSGS_PER_SEC = int(get("limits", "max_msgs_per_sec"))
MAX_CONNS_PER_IP = int(get("limits", "max_conns_per_ip"))
MAX_STREAM_BYTES = int(get("limits", "max_stream_bytes"))
MAX_CREATES_PER_IP_PER_HOUR = int(get("limits", "max_creates_per_ip_per_hour"))
NAT_RELAY = bool(get("nat", "relay"))
NAT_TYPE = bool(get("nat", "nat_type"))
NAT_TYPE_ALT_PORT = int(get("nat", "nat_type_alt_port"))
NAT_TYPE_ALT_ADDRESS = str(get("nat", "nat_type_alt_address"))
STARTING_RATING = int(get("stats", "starting_rating"))
PERIOD_BOARDS = bool(get("stats", "period_boards"))
DISCORD_LOBBY_WEBHOOK = str(get("discord", "lobby_webhook") or "")
DISCORD_ANNOUNCE_WEBHOOK = str(get("discord", "announce_webhook") or "")
DISCORD_MENTION = str(get("discord", "mention") or "")
DISCORD_TITLE = str(get("discord", "title") or "Open lobbies")
DISCORD_TEXT = {k: str(get("discord", k) or "")
                for k in ("announce_text", "closed_text", "empty_text", "offline_text")}
DISCORD_COOLDOWN = float(get("discord", "announce_cooldown"))
DISCORD_BOT_GUILD = int(get("discord", "bot_guild") or 0)
DISCORD_BOT_ADMIN_ROLES = [str(r) for r in (get("discord", "bot_admin_roles") or [])]
DISCORD_BOT_HELP_CHANNEL = str(get("discord", "bot_help_channel") or "connection-help").lstrip("#")
DISCORD_BOT_CLAIMS_PER_DAY = int(get("discord", "bot_claims_per_day"))
DISCORD_BOT_TEXT = str(get("discord", "bot_text") or "")


def _nat_type_line() -> str:
    if not NAT_TYPE:
        return "  nat: type discovery off (consoles report no NAT type)\n"
    alt = (f", test 2 from {NAT_TYPE_ALT_ADDRESS}" if NAT_TYPE_ALT_ADDRESS
           else ", test 2 unanswerable (no second address)")
    return f"  nat: type discovery ON, test 3 from UDP {NAT_TYPE_ALT_PORT}{alt}\n"


def _nat_line() -> str:
    if not NAT_RELAY:
        return "  nat: relay off (peer sessions go direct)\n"
    base = int(get("nat", "relay_port_base"))
    n = int(get("nat", "relay_ports"))
    return (f"  nat: relay ON, UDP {base}-{base + n - 1} "
            f"-- OPEN THESE IN THE FIREWALL\n")


def _discord_line() -> str:
    if not DISCORD_LOBBY_WEBHOOK and not DISCORD_ANNOUNCE_WEBHOOK:
        return "  discord: off\n"
    parts = []
    if DISCORD_LOBBY_WEBHOOK:
        parts.append(f"lobby board -> webhook {_webhook_id(DISCORD_LOBBY_WEBHOOK)}")
    if DISCORD_ANNOUNCE_WEBHOOK:
        parts.append(f"announcements -> webhook {_webhook_id(DISCORD_ANNOUNCE_WEBHOOK)}"
                     + (f" (mention {DISCORD_MENTION})" if DISCORD_MENTION else ""))
    return "  discord: " + ", ".join(parts) + "\n"


def _webhook_id(url: str) -> str:
    """The numeric id out of a webhook URL, never the token beside it."""
    parts = url.rstrip("/").split("/")
    return parts[-2] if len(parts) >= 2 and parts[-2].isdigit() else "(malformed URL)"


def describe() -> str:
    """One block for the server banner -- an operator should be able to see what
    is in force without guessing which env var won.
    """
    src = PATH or "built-in defaults (no config file)"
    return (f"config: {src}"
            f"{'' if _RIG_TREE else '  [source checkout]' if _PUBLIC_TREE else '  [installed, not a source tree]'}\n"
            f"  bind {BIND}:{PORT}   data {DATA_DIR}\n"
            f"  accounts: shared-password fallback "
            f"{'ON (development)' if SHARED_PASSWORD_FALLBACK else 'off'}, "
            f"create_mode={CREATE_MODE}\n"
            f"  logging: level {LOG_LEVEL}, "
            f"hexdumps {'on' if HEXDUMPS else 'off'}\n"
            + _nat_line()
            + _nat_type_line()
            + f"  stats: a player with no ranked row is served "
            f"{STARTING_RATING} (stakes {max(1, STARTING_RATING // 10)}); "
            + ("the Weekly, Monthly and Yearly boards restart from it each period\n"
               if PERIOD_BOARDS else "Weekly, Monthly and Yearly are all-time boards from 0\n")
            + f"  limits: {MAX_MSGS_PER_SEC} msg/s per conn, "
            f"{MAX_CONNS_PER_IP} conns per address, "
            f"{MAX_STREAM_BYTES // 1024} KB per conn, "
            + (f"{MAX_CREATES_PER_IP_PER_HOUR} new accounts per address per hour\n"
               if MAX_CREATES_PER_IP_PER_HOUR else "new accounts per address unlimited\n")
            + _discord_line().rstrip("\n")
            + "".join(f"\n  !! config: unknown key {k} -- ignored"
                      for k in unknown_keys()))


if __name__ == "__main__":
    print(describe())
