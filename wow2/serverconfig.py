#!/usr/bin/env python3
"""Deployment configuration for the WOW2 server -- one file, safe defaults.

WHY THIS IS SEPARATE FROM `rigconfig.py`. There are two kinds of knob here and
they were the same kind for a long time, which is why there are 43 `WOW2_*`
environment variables:

  * **Deployment settings** -- bind address, port, where data lives, whether an
    unknown account may sign in on a shared password, whether every packet gets
    hexdumped to disk. An operator has to set these and should not have to read
    `CLAUDE.md` to find them. They belong in a file.
  * **Research switches** -- `WOW2_NO_PUSH`, `WOW2_LSG_HOLD`, `WOW2_FRIEND_ROWS`
    and the rest. They exist to bisect a protocol failure by turning one specific
    behaviour off, they are used for minutes at a time, and putting them in a
    config file would invite someone to deploy with one set. They stay in the
    environment and stay undocumented outside `tools/README.md`.

`rigconfig.py` is a third thing again: values the SERVER and the INPUT DRIVER
must agree on (the account password, the emulator layout). It is about the rig,
not about a deployment, and it keeps its own life.

Precedence, highest first:   environment  >  config file  >  the defaults here.
The environment wins so that every existing `WOW2_*` invocation keeps working
exactly as before -- nothing in the rig had to change for this file to exist.

    WOW2_CONFIG=/etc/wow2-server.toml tools/wow2 server start

With no config file at all the defaults are the rig's historical behaviour, so
this module is invisible until someone wants it.
"""
from __future__ import annotations

import os
import tomllib
from pathlib import Path

ROOT = Path(os.environ.get("WOW2_ROOT", Path(__file__).resolve().parent.parent))

# In the source tree the rig writes to <repo>/capture and everything (git
# history, the tools, CLAUDE.md) assumes it. Once INSTALLED, that same expression
# points at site-packages, which is not a data directory -- a server must not
# write its databases there and on most systems could not anyway. So default to
# the repo only when this really is the repo, and otherwise to a directory the
# operator can see, in the working directory.
_IN_SOURCE_TREE = (ROOT / "tools" / "authserver.py").is_file()
_DEFAULT_DATA = ROOT / "capture" if _IN_SOURCE_TREE else Path.cwd() / "wow2-data"

#: Searched in order. The first that exists wins.
SEARCH = [
    os.environ.get("WOW2_CONFIG"),
    "wow2-server.toml",
    str(ROOT / "wow2-server.toml"),
    "/etc/wow2-server.toml",
]

DEFAULTS: dict[str, dict] = {
    "server": {
        # 0.0.0.0 is the historical behaviour and what the rig needs (the
        # namespaces reach it over the bridge). A deployment that only wants
        # loopback can say so here instead of editing the source.
        "bind": "0.0.0.0",
        "port": 3074,              # auth TCP, LSG TCP and bdDiscovery UDP all
    },
    "accounts": {
        # When an account has no stored credential, fall back to the shared
        # password from rigconfig. This is what lets the eight-console rig work
        # with no credential store at all -- and it is a DEVELOPMENT default.
        # A deployment wants it false, so that only accounts that actually
        # created themselves can sign in.
        "shared_password_fallback": True,
        # Answer create-account with success. "name_exists" makes the client log
        # in instead, which is the old returning-user experiment.
        "create_mode": "success",
    },
    "logging": {
        # Every message hexdumped to the session log. Invaluable for recon,
        # unacceptable for a deployment -- the PPSSPP console log hit 357 MB once
        # and the server log grows the same way.
        "hexdumps": True,
        # "debug" is the rig's historical behaviour: every read, every message
        # body, every reply. "info" keeps one line per RPC and drops the
        # per-packet noise -- which is ~90% of the volume and all of the reason
        # a session log grows without bound.
        "level": "debug",
    },
    "limits": {
        # Nothing here has ever faced a hostile peer. These are generous -- the
        # client's own steady state is a few messages a second and two
        # connections per console -- and they exist so that a peer that misbehaves
        # loses its own connection instead of the server's memory.
        "max_msgs_per_sec": 100,     # per connection, averaged over a second
        "max_conns_per_ip": 16,      # a console needs 2; change-password opens a 3rd
        "max_stream_bytes": 4 * 1024 * 1024,   # per connection, lifetime
    },
    "nat": {
        # Carry the peer session through the server instead of relying on a NAT
        # punch. OFF is the historical behaviour and the right default on a LAN,
        # where the direct path always wins and is free.
        #
        # Turn it ON for a deployment whose players are behind carrier NAT --
        # which, measured, defeats the introduction broker outright (Phase 35).
        # It costs ~7 datagrams/sec each way per pair, so a four-player match is
        # roughly 50 KB/s through the server.
        #
        # THE RELAY PORTS MUST BE OPEN IN THE FIREWALL, exactly like the main
        # one. The server logs the range at startup.
        "relay": False,
        "relay_port_base": 40000,
        "relay_ports": 32,           # one per console, so 16 two-player matches
        "relay_idle_timeout": 600,   # seconds before a mailbox may be reclaimed
        # What to tell a console the server's address is. Empty means "ask the
        # routing table", which is right on the rig (bridge or loopback) and on
        # a VPS with one address. Set it when the server sits behind its own NAT
        # or has several addresses and the kernel would pick the wrong one.
        "public_address": "",
    },
    "storage": {
        # Where the JSON stores and uploaded blobs live.
        "data_dir": str(_DEFAULT_DATA),
    },
}


def _read_file() -> tuple[dict, str | None]:
    """Load the first config file that exists. A BROKEN one is fatal.

    This used to print the parse error and carry on with the built-in defaults,
    on the reasoning that a typo should not take the server down. That is the
    wrong trade and it showed up the first time someone deployed: a missing pair
    of quotes around `level = info` meant the server came up with hexdumps on and
    `shared_password_fallback` back at its development default, while the
    operator had written `false` and believed it. Silently running with settings
    nobody chose is worse than not running, especially when one of them decides
    who may sign in.

    So: no file is fine and means "defaults". A file that exists and does not
    parse stops the process. Delete it or fix it.
    """
    for cand in SEARCH:
        if not cand:
            continue
        p = Path(cand)
        if p.is_file():
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

#: Environment overrides, applied last. Only DEPLOYMENT settings appear here --
#: research switches are read where they are used and are not config at all.
_ENV = {
    ("server", "bind"): ("WOW2_BIND", str),
    ("server", "port"): ("WOW2_PORT", int),
    ("accounts", "shared_password_fallback"): ("WOW2_SHARED_PASSWORD_FALLBACK",
                                               lambda v: v not in ("0", "false", "no")),
    ("accounts", "create_mode"): ("WOW2_CREATE_MODE", str),
    ("logging", "hexdumps"): ("WOW2_HEXDUMPS", lambda v: v not in ("0", "false", "no")),
    ("logging", "level"): ("WOW2_LOG_LEVEL", str),
    ("storage", "data_dir"): ("WOW2_DATA_DIR", str),
    ("limits", "max_msgs_per_sec"): ("WOW2_MAX_MSGS_PER_SEC", int),
    ("limits", "max_conns_per_ip"): ("WOW2_MAX_CONNS_PER_IP", int),
    ("limits", "max_stream_bytes"): ("WOW2_MAX_STREAM_BYTES", int),
    ("nat", "relay"): ("WOW2_NAT_RELAY", lambda v: v not in ("0", "false", "no", "off")),
    ("nat", "public_address"): ("WOW2_RELAY_PUBLIC_ADDRESS", str),
    ("nat", "relay_port_base"): ("WOW2_RELAY_PORT_BASE", int),
    ("nat", "relay_ports"): ("WOW2_RELAY_PORTS", int),
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
NAT_RELAY = bool(get("nat", "relay"))


def _nat_line() -> str:
    if not NAT_RELAY:
        return "  nat: relay off (peer sessions go direct)\n"
    base = int(get("nat", "relay_port_base"))
    n = int(get("nat", "relay_ports"))
    return (f"  nat: relay ON, UDP {base}-{base + n - 1} "
            f"-- OPEN THESE IN THE FIREWALL\n")


def describe() -> str:
    """One block for the server banner -- an operator should be able to see what
    is in force without guessing which env var won."""
    src = PATH or "built-in defaults (no config file)"
    return (f"config: {src}"
            f"{'' if _IN_SOURCE_TREE else '  [installed, not a source tree]'}\n"
            f"  bind {BIND}:{PORT}   data {DATA_DIR}\n"
            f"  accounts: shared-password fallback "
            f"{'ON (development)' if SHARED_PASSWORD_FALLBACK else 'off'}, "
            f"create_mode={CREATE_MODE}\n"
            f"  logging: level {LOG_LEVEL}, "
            f"hexdumps {'on' if HEXDUMPS else 'off'}\n"
            + _nat_line()
            + f"  limits: {MAX_MSGS_PER_SEC} msg/s per conn, "
            f"{MAX_CONNS_PER_IP} conns per address, "
            f"{MAX_STREAM_BYTES // 1024} KB per conn")


if __name__ == "__main__":
    print(describe())
