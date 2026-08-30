#!/bin/sh
# turbobond concentrator: starter installer for a bare VPS.
#
# Run this on the server, before you have a gateway. It installs the server
# half, generates a pre-shared key, tunes the kernel, opens the local firewall
# and prints the three values you type into the gateway's sign-in screen.
#
#   sudo sh packaging/concentrator-install.sh
#
# The dashboard on an existing gateway builds a bundle that does the same thing
# with the key already filled in. Use that instead if you have a gateway up:
# it saves you copying the key across by hand.
#
# Options:
#   --psk HEX         use an existing key instead of generating one, for when
#                     the gateway already has a key you want to keep
#   --port N          listen on N instead of 5310
#   --public-ip ADDR  address to print for pairing, if autodetection is wrong
#                     (correct for a NATted VPS, where the local address is not
#                     the one clients dial)
set -eu

PSK=""
PORT=5310
PUBLIC_IP=""

while [ $# -gt 0 ]; do
    case "$1" in
        --psk) PSK="${2:-}"; shift 2 ;;
        --port) PORT="${2:-}"; shift 2 ;;
        --public-ip) PUBLIC_IP="${2:-}"; shift 2 ;;
        -h|--help) awk 'NR>1 && /^#/ {sub(/^# ?/, ""); print; next} NR>1 {exit}' "$0"; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

[ "$(id -u)" -eq 0 ] || { echo "error: run this as root." >&2; exit 1; }

HERE=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

echo "==> installing the turbobond concentrator"

if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y --no-install-recommends \
        python3 python3-venv python3-pip iproute2 iptables ca-certificates
elif command -v dnf >/dev/null 2>&1; then
    dnf install -y python3 python3-pip iproute2 iptables ca-certificates
elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache python3 py3-pip iproute2 iptables ca-certificates
fi

python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' || {
    echo "error: the concentrator needs Python 3.11 or newer." >&2
    exit 1
}

# Ubuntu 24.04 and Debian 12 refuse system-wide pip installs (PEP 668), hence
# the virtualenv. Creating one is the only real test that it can be done:
# 'python3 -m venv --help' succeeds even on images where ensurepip is missing.
VENV=/usr/local/lib/turbobond-concentrator
rm -rf "$VENV"

# setuptools builds in-tree, so installing as root leaves root-owned build/ and
# egg-info/ behind in the checkout. A later unprivileged install then dies on
# "could not delete build/...: Permission denied", which reads like a packaging
# fault rather than a leftover. Clearing them keeps the checkout reusable.
rm -rf "$HERE/build" "$HERE"/*.egg-info
if python3 -m venv "$VENV" 2>/dev/null && [ -x "$VENV/bin/pip" ]; then
    "$VENV/bin/pip" install --quiet --upgrade pip
    "$VENV/bin/pip" install --quiet "$HERE"
    ln -sf "$VENV/bin/turbobond-server" /usr/local/bin/turbobond-server
else
    echo "no usable virtualenv; installing system-wide instead"
    rm -rf "$VENV"
    python3 -m pip install --break-system-packages "$HERE" \
        || python3 -m pip install "$HERE"
fi

command -v turbobond-server >/dev/null 2>&1 || {
    echo "error: turbobond-server was not installed; see the output above." >&2
    exit 1
}

# --psk is passed on only when one was asked for. Minting a key here instead
# would override the key already installed on a re-run, and every client paired
# against the old one would stop authenticating with no visible cause.
# --provision generates a key when there is genuinely none to keep.
set -- --provision --listen "0.0.0.0:$PORT"
[ -n "$PSK" ] && set -- "$@" --psk "$PSK"
[ -n "$PUBLIC_IP" ] && set -- "$@" --public-ip "$PUBLIC_IP"
turbobond-server "$@"

cat <<EOF
If this server sits behind a cloud firewall (DigitalOcean, AWS, Azure, GCP),
open inbound UDP $PORT there as well. That firewall runs outside this machine,
so nothing in here can open it, and a bond that comes up but carries no traffic
is almost always this.

    systemctl status turbobond-concentrator
    journalctl -u turbobond-concentrator -f
EOF
