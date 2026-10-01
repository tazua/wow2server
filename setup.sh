#!/usr/bin/env bash
# wow2-server: the whole install in one command.
#
#   ./setup.sh                        a local install: .venv, wow2-server.toml,
#                                     wow2-data/ -- then `.venv/bin/wow2-server`
#   sudo ./setup.sh --system          a service: the `wow2` user (and `wow2bot`
#                                     for the password bot), a venv under
#                                     /opt/wow2-server, /etc/wow2-server.toml,
#                                     /var/lib/wow2-server, the systemd units,
#                                     enabled and started
#   sudo ./setup.sh --system --dns 203.0.113.10
#                                     ...plus the DNS responder a retail PSP
#                                     needs, answering with that address
#   ... --open-firewall               also open the ports in ufw/firewalld
#
# Safe to run twice: an existing config file is kept, an existing venv is
# updated in place. Without --system nothing outside this directory is touched
# except a missing python3/venv, which is installed with the system's package
# manager (and asks for sudo to do it).
#
# There is no other dependency. Tiger192, the hash the auth path is built on,
# is pure Python (wow2/tiger.py), so `pip install .` is the entire install.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SYSTEM=0
DNS_ADDR=""
OPEN_FW=0
PREFIX=/opt/wow2-server           # the venv, with --system
STATE=/var/lib/wow2-server        # the data directory, with --system
CONF=/etc/wow2-server.toml
SVC_USER=wow2
BOT_USER=wow2bot                  # the password bot, in SVC_USER's group

while [ $# -gt 0 ]; do
    case "$1" in
        --system) SYSTEM=1 ;;
        --dns) DNS_ADDR="${2:?--dns needs the address to answer with}"; shift ;;
        --dns=*) DNS_ADDR="${1#--dns=}" ;;
        --open-firewall) OPEN_FW=1 ;;
        -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
        *) echo "unknown option: $1 (try --help)" >&2; exit 2 ;;
    esac
    shift
done

say()  { printf '\n==> %s\n' "$*"; }
note() { printf '    %s\n' "$*"; }
die()  { printf '!! %s\n' "$*" >&2; exit 1; }

if [ "$SYSTEM" = 1 ] && [ "$(id -u)" != 0 ]; then
    die "--system installs a service; run it as root:  sudo $0 --system"
fi
[ -n "$DNS_ADDR" ] && [ "$SYSTEM" != 1 ] && die "--dns is part of --system"
# the service users read the venv whatever root's umask (027/077 when hardened); secrets are chmodded below
if [ "$SYSTEM" = 1 ]; then umask 022; fi

# --------------------------------------------------------------- python 3.11+
# tomllib arrived in 3.11 and the server reads its config with it.
SUDO=""
if [ "$(id -u)" != 0 ]; then SUDO="sudo"; fi

pkg_install() {
    # Install the named packages with whichever package manager this is.
    if command -v apt-get >/dev/null; then
        $SUDO apt-get update -qq
        $SUDO apt-get install -y -qq --no-install-recommends "$@"
    elif command -v dnf >/dev/null; then
        $SUDO dnf install -y -q "$@"
    elif command -v pacman >/dev/null; then
        $SUDO pacman -S --needed --noconfirm "$@"
    elif command -v apk >/dev/null; then
        $SUDO apk add -q "$@"
    elif command -v zypper >/dev/null; then
        $SUDO zypper -n install "$@"
    elif command -v brew >/dev/null; then
        brew install "$@"
    else
        return 1
    fi
}

python_ok() {
    # python3 present, 3.11 or newer, and able to make a venv with pip in it
    # (Debian and Ubuntu ship that half in a separate python3-venv package).
    command -v "$1" >/dev/null 2>&1 || return 1
    "$1" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' \
        2>/dev/null || return 1
    "$1" -c 'import ensurepip, venv' 2>/dev/null || return 1
}

say "python"
PY=""
for cand in python3 python3.13 python3.12 python3.11 python; do
    if python_ok "$cand"; then PY="$cand"; break; fi
done
if [ -z "$PY" ]; then
    note "python 3.11+ with venv support is missing; installing it"
    if command -v apt-get >/dev/null; then
        pkg_install python3 python3-venv python3-pip || true
    elif command -v dnf >/dev/null; then
        pkg_install python3 python3-pip || true
    elif command -v pacman >/dev/null; then
        pkg_install python python-pip || true
    elif command -v apk >/dev/null; then
        pkg_install python3 py3-pip || true
    elif command -v zypper >/dev/null; then
        pkg_install python3 python3-pip || true
    elif command -v brew >/dev/null; then
        pkg_install python@3.12 || true
    fi
    for cand in python3 python3.13 python3.12 python3.11 python; do
        if python_ok "$cand"; then PY="$cand"; break; fi
    done
    [ -n "$PY" ] || die "no usable python3 (need 3.11+ with the venv module); install one and re-run"
fi
note "$("$PY" -c 'import sys; print(sys.executable, sys.version.split()[0])')"

# ------------------------------------------------------------------ the venv
if [ "$SYSTEM" = 1 ]; then
    VENV="$PREFIX"; SHOW="$PREFIX"
else
    VENV="$HERE/.venv"; SHOW=".venv"
fi
say "installing wow2-server into $SHOW"
if [ ! -x "$VENV/bin/python" ]; then
    "$PY" -m venv "$VENV"
fi
"$VENV/bin/python" -m pip install --quiet --upgrade pip >/dev/null 2>&1 || true
# [bot] adds discord.py for the password bot; a platform it will not install on
# still gets the server.
if ! "$VENV/bin/python" -m pip install --quiet "$HERE[bot]" 2>/dev/null; then
    "$VENV/bin/python" -m pip install --quiet "$HERE"
    note "(discord.py did not install, so wow2-discordbot is not available; the server is)"
fi
# heals a venv an older setup.sh made under a hardened umask: pip leaves what it already has
if [ "$SYSTEM" = 1 ]; then chmod -R a+rX "$VENV"; fi
# -P: do not put the current directory on sys.path, so this imports the
# INSTALLED package and not the checkout it was installed from.
"$VENV/bin/python" -P - <<'PY'
import sys
try:
    import sqlite3
except ImportError:
    # Every distribution here ships it with python3 (Debian, Ubuntu, Fedora,
    # Arch and Alpine were checked), but a python built from source without
    # the SQLite headers would not, and the store is where every account lives.
    sys.exit("!! this python has no sqlite3 module; install the distribution's "
             "python3 (Debian/Ubuntu: libpython3-stdlib) and re-run")
import wow2.authserver as a
a.check_tiger()
print("    installed; tiger192 self-test ok, sqlite %s  (%s)"
      % (sqlite3.sqlite_version, a.__file__))
PY

# ------------------------------------------------------------------- config
write_config() {
    # $1 = destination, $2 = data directory to name in it.
    if [ -e "$1" ]; then
        note "$1 exists -- keeping it"
        return
    fi
    sed -e "s|^# data_dir = \"/var/lib/wow2-server\"|data_dir = \"$2\"|" \
        "$HERE/wow2-server.example.toml" > "$1"
    note "wrote $1"
    note "(the deployment defaults: shared-password fallback off, hexdumps off,"
    note "one log line per RPC; data in $2)"
}

if [ "$SYSTEM" = 1 ]; then
    say "the service users and their state directory"
    if ! id -u "$SVC_USER" >/dev/null 2>&1; then
        useradd --system --home "$STATE" --create-home --shell /usr/sbin/nologin \
            "$SVC_USER" 2>/dev/null \
        || useradd --system --home "$STATE" --create-home "$SVC_USER"
    fi
    # The bot's own user, so the server cannot read the bot's environment (the
    # token); the shared group is how both write the one database.
    if ! id -u "$BOT_USER" >/dev/null 2>&1; then
        useradd --system --gid "$SVC_USER" --no-create-home --home-dir /nonexistent \
            --shell /usr/sbin/nologin "$BOT_USER" 2>/dev/null \
        || useradd --system --gid "$SVC_USER" --no-create-home "$BOT_USER"
    fi
    mkdir -p "$STATE"
    chown "$SVC_USER:$SVC_USER" "$STATE"
    chmod 770 "$STATE"
    for f in "$STATE/wow2.sqlite3" "$STATE/wow2.sqlite3-wal" "$STATE/wow2.sqlite3-shm"; do
        if [ -e "$f" ]; then chown "$SVC_USER:$SVC_USER" "$f"; chmod 660 "$f"; fi
    done
    note "users $SVC_USER (the server) and $BOT_USER (the password bot), data in $STATE"

    say "configuration"
    write_config "$CONF" "$STATE"
    chmod 640 "$CONF"; chown "root:$SVC_USER" "$CONF"

    say "systemd"
    if [ -d /etc/systemd/system ] && command -v systemctl >/dev/null; then
        install -m 644 "$HERE/packaging/wow2-server.service" /etc/systemd/system/
        install -m 644 "$HERE/packaging/wow2-nsdns@.service" /etc/systemd/system/
        install -m 644 "$HERE/packaging/wow2-discordbot.service" /etc/systemd/system/
        if [ -d /run/systemd/system ]; then
            systemctl daemon-reload
            # restart, not `enable --now`: a re-run after a `git pull` is an
            # upgrade, and the unit that is already running is the OLD code.
            systemctl enable wow2-server
            systemctl restart wow2-server
            sleep 1
            if systemctl is-active --quiet wow2-server; then
                note "wow2-server is running"
            else
                journalctl -u wow2-server -n 20 --no-pager || true
                die "wow2-server did not start; the log is above"
            fi
            if [ -n "$DNS_ADDR" ]; then
                systemctl enable "wow2-nsdns@$DNS_ADDR"
                systemctl restart "wow2-nsdns@$DNS_ADDR"
                sleep 1
                if systemctl is-active --quiet "wow2-nsdns@$DNS_ADDR"; then
                    note "wow2-nsdns@$DNS_ADDR is running (UDP 53 on $DNS_ADDR)"
                else
                    journalctl -u "wow2-nsdns@$DNS_ADDR" -n 20 --no-pager || true
                    die "the DNS responder did not start; the log is above"
                fi
            fi
            # The password bot runs only where its token file exists (the unit's
            # ConditionPathExists); the token is the one secret this install has.
            if [ -f /etc/wow2-server.env ] && [ -x "$VENV/bin/wow2-discordbot" ]; then
                chmod 600 /etc/wow2-server.env
                systemctl enable wow2-discordbot
                systemctl restart wow2-discordbot
                sleep 3
                if systemctl is-active --quiet wow2-discordbot; then
                    note "wow2-discordbot is running (journalctl -u wow2-discordbot -f)"
                else
                    journalctl -u wow2-discordbot -n 20 --no-pager || true
                    note "!! wow2-discordbot did not stay up; the log is above (the token, or"
                    note "   [discord] bot_guild in $CONF)"
                fi
            else
                note "no /etc/wow2-server.env, so the Discord password bot is not started;"
                note "DOCS.md 'Discord' says how to set it up"
            fi
        else
            note "units installed; systemd is not running here (a container?), so"
            note "they were not started:  systemctl enable --now wow2-server"
            [ -n "$DNS_ADDR" ] && note "                        systemctl enable --now wow2-nsdns@$DNS_ADDR"
        fi
    else
        note "no systemd on this machine; run the server by hand:"
        note "  sudo -u $SVC_USER WOW2_CONFIG=$CONF $VENV/bin/wow2-server"
    fi
else
    say "configuration"
    write_config "$HERE/wow2-server.toml" "$HERE/wow2-data"
    mkdir -p "$HERE/wow2-data"
fi

# ----------------------------------------------------------------- firewall
# Each port fails in a way that looks like something else: without UDP 3074
# the game browser stays empty forever, without UDP 3078 every console reports
# a STRICT NAT, without UDP 53 a real console never sends a packet, and without
# the relay ports everything works except the join.
# the server's own reading of the file (any valid TOML), not the operator's environment
if [ "$SYSTEM" = 1 ]; then CONF_USED="$CONF"; else CONF_USED="$HERE/wow2-server.toml"; fi
PORTS=$(env -i PATH="$PATH" WOW2_CONFIG="$CONF_USED" "$VENV/bin/python" -P -c \
        'from wow2 import serverconfig as c; print(" ".join(c.firewall_ports()))') \
    || die "$CONF_USED does not load (the server would refuse it too): $VENV/bin/wow2-server says why"
[ -n "$DNS_ADDR" ] && PORTS="$PORTS 53/udp"
say "firewall"
if [ "$OPEN_FW" = 1 ] && [ "$(id -u)" = 0 ]; then
    if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q '^Status: active'; then
        for p in $PORTS; do ufw allow "${p/-/:}" >/dev/null; done
        note "ufw: allowed $PORTS"
    elif command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
        for p in $PORTS; do firewall-cmd -q --permanent --add-port="$p"; done
        firewall-cmd -q --reload
        note "firewalld: opened $PORTS"
    else
        note "no active ufw/firewalld found; open these yourself: $PORTS"
    fi
else
    note "open these (or re-run with --open-firewall): $PORTS"
fi

# --------------------------------------------------------------------- done
say "done"
if [ "$SYSTEM" = 1 ]; then
    note "config   $CONF        (edit, then: systemctl restart wow2-server)"
    note "data     $STATE"
    note "log      journalctl -u wow2-server -f"
    note "accounts sudo -u $SVC_USER $VENV/bin/wow2-account list"
    note "backup   sudo $VENV/bin/wow2-db backup /var/backups/wow2.sqlite3   (as root: /var/backups is not the service user's)"
    if [ -z "$DNS_ADDR" ]; then
        note "a retail PSP needs the DNS responder too:  sudo $0 --system --dns <this machine's public address>"
    fi
else
    note "run       $SHOW/bin/wow2-server        (from anywhere: it reads the"
    note "                                    wow2-server.toml beside .venv, data in wow2-data/)"
    note "accounts  $SHOW/bin/wow2-account list"
    note "backup    $SHOW/bin/wow2-db backup wow2-data/backup.sqlite3"
    note ""
    note "THIS STARTED NOTHING and installed only the game server. A real PSP"
    note "also needs the DNS responder, in a second terminal, as root:"
    note "          sudo $SHOW/bin/wow2-nsdns --bind <this machine's address> --answer <the same>"
    note "and the PSP's DNS setting pointed at that address. An emulator on this"
    note "machine can use /etc/hosts instead (the names are in wow2/nsdns-names)."
    note ""
    note "For a server that real consoles use, install both as services instead:"
    note "          sudo ./setup.sh --system --dns <this machine's public address> --open-firewall"
fi
