#!/usr/bin/env bash
# wow2-server: the whole install in one command.
#
#   ./setup.sh                        a local install: .venv, wow2-server.toml,
#                                     wow2-data/ -- then `.venv/bin/wow2-server`
#   sudo ./setup.sh --system          a service: the `wow2` user, a venv under
#                                     /opt/wow2-server, /etc/wow2-server.toml,
#                                     /var/lib/wow2-server, the systemd unit,
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
"$VENV/bin/python" -m pip install --quiet "$HERE"
# -P: do not put the current directory on sys.path, so this imports the
# INSTALLED package and not the checkout it was installed from.
"$VENV/bin/python" -P - <<'PY'
import wow2.authserver as a
a.check_tiger()
print("    installed; tiger192 self-test ok  (" + a.__file__ + ")")
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
    say "the service user and its state directory"
    if ! id -u "$SVC_USER" >/dev/null 2>&1; then
        useradd --system --home "$STATE" --create-home --shell /usr/sbin/nologin \
            "$SVC_USER" 2>/dev/null \
        || useradd --system --home "$STATE" --create-home "$SVC_USER"
    fi
    mkdir -p "$STATE"
    chown "$SVC_USER:$SVC_USER" "$STATE"
    chmod 750 "$STATE"
    note "user $SVC_USER, data in $STATE"

    say "configuration"
    write_config "$CONF" "$STATE"
    chmod 640 "$CONF"; chown "root:$SVC_USER" "$CONF"

    say "systemd"
    if [ -d /etc/systemd/system ] && command -v systemctl >/dev/null; then
        install -m 644 "$HERE/packaging/wow2-server.service" /etc/systemd/system/
        install -m 644 "$HERE/packaging/wow2-nsdns@.service" /etc/systemd/system/
        if [ -d /run/systemd/system ]; then
            systemctl daemon-reload
            systemctl enable --now wow2-server
            sleep 1
            if systemctl is-active --quiet wow2-server; then
                note "wow2-server is running"
            else
                journalctl -u wow2-server -n 20 --no-pager || true
                die "wow2-server did not start; the log is above"
            fi
            if [ -n "$DNS_ADDR" ]; then
                systemctl enable --now "wow2-nsdns@$DNS_ADDR"
                sleep 1
                if systemctl is-active --quiet "wow2-nsdns@$DNS_ADDR"; then
                    note "wow2-nsdns@$DNS_ADDR is running (UDP 53 on $DNS_ADDR)"
                else
                    journalctl -u "wow2-nsdns@$DNS_ADDR" -n 20 --no-pager || true
                    die "the DNS responder did not start; the log is above"
                fi
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
PORTS="3074/tcp 3074/udp 3078/udp"
[ -n "$DNS_ADDR" ] && PORTS="$PORTS 53/udp"
if [ -f "${CONF}" ] && [ "$SYSTEM" = 1 ] && grep -qE '^\s*relay\s*=\s*true' "$CONF"; then
    PORTS="$PORTS 40000-40031/udp"
fi
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
    note "accounts WOW2_CONFIG=$CONF $VENV/bin/wow2-account list"
    if [ -z "$DNS_ADDR" ]; then
        note "a retail PSP needs the DNS responder too:  sudo $0 --system --dns <this machine's public address>"
    fi
else
    note "run       $SHOW/bin/wow2-server        (from this directory: it reads"
    note "                                    wow2-server.toml here, data in wow2-data/)"
    note "accounts  $SHOW/bin/wow2-account list"
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
