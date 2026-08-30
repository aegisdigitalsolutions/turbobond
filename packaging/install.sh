#!/bin/sh
# Installs turbobond on the gateway host and leaves it running.
#
#   sudo sh packaging/install.sh
#
# Afterwards the only thing left to do is open http://<host>:8088 and sign in;
# the app installs the rest of its dependencies and activates by itself.
set -eu

REPO_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
PREFIX=${PREFIX:-/usr/local}
CONFIG_DIR=${TURBOBOND_CONFIG_DIR:-/etc/turbobond}

say() { printf '==> %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = "0" ] || die "run as root: sudo sh $0"

# --------------------------------------------------------------- interpreter
PYTHON=""
for candidate in python3.13 python3.12 python3.11 python3; do
    if command -v "$candidate" >/dev/null 2>&1 &&
       "$candidate" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)'; then
        PYTHON=$(command -v "$candidate")
        break
    fi
done
[ -n "$PYTHON" ] || die "Python 3.11 or newer is required but was not found"
say "using $PYTHON"

# ------------------------------------------------------------- system packages
if command -v apt-get >/dev/null 2>&1; then
    say "installing system packages with apt-get"
    DEBIAN_FRONTEND=noninteractive apt-get update -qq || true
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        iproute2 nftables iptables procps iputils-ping python3-venv ca-certificates || true
elif command -v dnf >/dev/null 2>&1; then
    say "installing system packages with dnf"
    dnf install -y iproute nftables iptables procps-ng iputils ca-certificates || true
elif command -v apk >/dev/null 2>&1; then
    say "installing system packages with apk"
    apk add --no-cache iproute2 nftables iptables procps iputils ca-certificates || true
elif command -v pacman >/dev/null 2>&1; then
    say "installing system packages with pacman"
    pacman -S --noconfirm iproute2 nftables iptables procps-ng iputils ca-certificates || true
else
    say "no known package manager; turbobond will check its dependencies at activation"
fi

modprobe tun 2>/dev/null || true

# ------------------------------------------------------------------- install
say "installing turbobond into $PREFIX"
VENV="$PREFIX/lib/turbobond"
rm -rf "$VENV"
# Creating one is the only real test: 'python3 -m venv --help' succeeds even on
# images where ensurepip is missing and creation then fails.
if "$PYTHON" -m venv "$VENV" 2>/dev/null && [ -x "$VENV/bin/pip" ]; then
    "$VENV/bin/pip" install --quiet --upgrade pip
    "$VENV/bin/pip" install --quiet "$REPO_ROOT"
    ln -sf "$VENV/bin/turbobond" "$PREFIX/bin/turbobond"
    ln -sf "$VENV/bin/turbobond-server" "$PREFIX/bin/turbobond-server"
else
    say "python venv is unavailable, installing system-wide"
    rm -rf "$VENV"
    "$PYTHON" -m pip install --upgrade --break-system-packages "$REPO_ROOT" ||
        "$PYTHON" -m pip install --upgrade "$REPO_ROOT"
fi

install -d -m 0750 "$CONFIG_DIR"
[ -f "$CONFIG_DIR/turbobond.yaml" ] || turbobond config --init >/dev/null

# ------------------------------------------------------------------- service
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    say "installing the systemd unit"
    install -m 0644 "$REPO_ROOT/packaging/turbobond.service" /etc/systemd/system/turbobond.service
    systemctl daemon-reload
    systemctl enable --now turbobond.service
    sleep 2
    systemctl --no-pager --lines=0 status turbobond.service || true
else
    say "no systemd here; start it yourself with: turbobond serve"
fi

PORT=$(turbobond config 2>/dev/null | sed -n 's/.*"bind_port": *\([0-9]*\).*/\1/p' | head -n 1)
ADDRESS=$(ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n 1)

echo
say "turbobond is installed."
say "Open http://${ADDRESS:-<this-host>}:${PORT:-8088} and sign in. Everything else is automatic."
