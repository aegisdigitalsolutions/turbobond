#!/bin/sh
# turbobond concentrator: one command to stand it up on a bare VPS.
#
#   curl -fsSL https://raw.githubusercontent.com/aegisdigitalsolutions/turbobond/main/packaging/bootstrap.sh | sudo sh
#
# Fetches the source, then hands over to packaging/concentrator-install.sh,
# which does the actual work and prints the pairing values at the end.
#
# To pass options through, give sh something to forward:
#
#   curl -fsSL .../bootstrap.sh | sudo sh -s -- --public-ip 203.0.113.5
#
# Safe to re-run: it updates the checkout in place and keeps the key already
# installed, so re-running does not unpair anything.
#
# Options are the installer's; see packaging/concentrator-install.sh --help.
set -eu

REPO=${TURBOBOND_REPO:-https://github.com/aegisdigitalsolutions/turbobond.git}
BRANCH=${TURBOBOND_BRANCH:-main}
DEST=${TURBOBOND_DIR:-/opt/turbobond}

[ "$(id -u)" -eq 0 ] || {
    echo "error: this needs root. Pipe it into 'sudo sh' rather than 'sh'." >&2
    exit 1
}

echo "==> fetching turbobond"

if ! command -v git >/dev/null 2>&1; then
    echo "  installing git"
    if command -v apt-get >/dev/null 2>&1; then
        # Same reasoning as the installer: without these, a host with pending
        # updates can stop on a dialog that eats the rest of the session.
        DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a NEEDRESTART_SUSPEND=1 \
            apt-get update -qq
        DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a NEEDRESTART_SUSPEND=1 \
            apt-get install -y --no-install-recommends git
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y git
    elif command -v apk >/dev/null 2>&1; then
        apk add --no-cache git
    else
        echo "error: no git and no known package manager to install it." >&2
        exit 1
    fi
fi

# A half-finished clone from an interrupted run would otherwise fail every
# retry, so anything that is not a usable checkout is replaced outright.
if [ -d "$DEST/.git" ]; then
    echo "  updating $DEST"
    git -C "$DEST" remote set-url origin "$REPO"
    git -C "$DEST" fetch --quiet --depth 1 origin "$BRANCH"
    git -C "$DEST" reset --quiet --hard FETCH_HEAD
else
    echo "  cloning into $DEST"
    rm -rf "$DEST"
    git clone --quiet --depth 1 --branch "$BRANCH" "$REPO" "$DEST"
fi

echo "  at $(git -C "$DEST" rev-parse --short HEAD)"

exec sh "$DEST/packaging/concentrator-install.sh" "$@"
