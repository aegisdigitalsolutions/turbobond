#!/bin/sh
# One-command fresh repair for the concentrator host.
#
#   curl -fsSL https://raw.githubusercontent.com/aegisdigitalsolutions/turbobond/main/packaging/revive-concentrator.sh | sudo sh
#
# What it does:
# - updates package indexes
# - upgrades installed packages
# - installs required tooling
# - refreshes /opt/turbobond from the selected branch
# - runs packaging/concentrator-install.sh
# - verifies service health and listener state
set -eu

REPO=${TURBOBOND_REPO:-https://github.com/aegisdigitalsolutions/turbobond.git}
BRANCH=${TURBOBOND_BRANCH:-main}
DEST=${TURBOBOND_DIR:-/opt/turbobond}
PUBLIC_IP=${PUBLIC_IP:-}
PORT=${PORT:-5310}

say() { printf '==> %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root"

if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    export NEEDRESTART_MODE=a
    export NEEDRESTART_SUSPEND=1
    say "updating apt metadata"
    apt-get update -y
    say "upgrading installed packages"
    apt-get upgrade -y
    say "installing required packages"
    apt-get install -y --no-install-recommends git curl ca-certificates
elif command -v dnf >/dev/null 2>&1; then
    say "upgrading installed packages"
    dnf -y upgrade
    say "installing required packages"
    dnf install -y git curl ca-certificates
elif command -v apk >/dev/null 2>&1; then
    say "updating installed packages"
    apk update
    apk upgrade
    say "installing required packages"
    apk add --no-cache git curl ca-certificates
else
    die "no supported package manager found (apt-get, dnf, apk)"
fi

if [ -d "$DEST/.git" ]; then
    say "refreshing repository in $DEST"
    git -C "$DEST" remote set-url origin "$REPO"
    git -C "$DEST" fetch --quiet origin "$BRANCH"
    git -C "$DEST" reset --quiet --hard "origin/$BRANCH"
else
    say "cloning repository into $DEST"
    rm -rf "$DEST"
    git clone --quiet --branch "$BRANCH" "$REPO" "$DEST"
fi

say "running concentrator installer"
set -- --port "$PORT"
[ -n "$PUBLIC_IP" ] && set -- "$@" --public-ip "$PUBLIC_IP"
sh "$DEST/packaging/concentrator-install.sh" "$@"

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    say "verifying service status"
    systemctl enable --now turbobond-concentrator
    sleep 2
    systemctl --no-pager --lines=50 status turbobond-concentrator
fi

say "running concentrator self-check"
turbobond-server --check

say "verifying UDP listener on port $PORT"
ss -lunp | grep ":$PORT " >/dev/null || die "no UDP listener found on port $PORT"

say "done"
turbobond-server --pairing
