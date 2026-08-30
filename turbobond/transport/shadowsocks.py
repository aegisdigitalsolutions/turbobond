"""Supervises the local shadowsocks client for the `shadow` route.

turbobond writes the client config, starts ``sslocal``, watches it, and restarts
it if it dies. The user never installs or configures anything: if no sslocal
binary is present, :meth:`ShadowsocksManager.ensure_binary` fetches one through
the platform package manager.

Both shadowsocks-rust and shadowsocks-libev are supported; their config files
are compatible for the fields we set, but only rust supports the 2022 AEAD
ciphers, so the cipher is downgraded automatically on libev.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import shutil
import signal
import subprocess
import time
from pathlib import Path
from typing import Any

from turbobond.config import ShadowsocksConfig, ensure_writable_dir
from turbobond.errors import TransportError
from turbobond.logging_setup import get_logger
from turbobond.util import netcheck
from turbobond.util.cmd import is_dry_run, run, which

log = get_logger("transport.shadowsocks")

SSLOCAL_CANDIDATES = ("sslocal", "ss-local", "shadowsocks-libev-local")
# Ciphers only shadowsocks-rust implements.
RUST_ONLY_METHODS = {
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
    "2022-blake3-chacha8-poly1305",
}
LIBEV_FALLBACK_METHOD = "chacha20-ietf-poly1305"

RESTART_BACKOFF_S = (1, 2, 5, 10, 30)


class ShadowsocksManager:
    """Owns the sslocal process lifecycle."""

    def __init__(self, cfg: ShadowsocksConfig, *, run_dir: Path = Path("/run/turbobond")) -> None:
        self.cfg = cfg
        self.run_dir = Path(run_dir)
        self.config_path = self.run_dir / "shadowsocks.json"
        self._process: subprocess.Popen[bytes] | None = None
        self._binary: str = ""
        self._flavour: str = ""
        self._supervisor: asyncio.Task[None] | None = None
        self._stop = asyncio.Event()
        self._restarts = 0
        self._started_ts = 0.0
        self._last_error = ""

    # ----------------------------------------------------------------- binary

    def find_binary(self) -> str:
        for candidate in SSLOCAL_CANDIDATES:
            path = which(candidate)
            if path:
                return path
        return ""

    def detect_flavour(self, binary: str) -> str:
        """"rust" or "libev". Determines which ciphers are usable."""

        if is_dry_run():
            return "rust"
        result = run([binary, "--version"], timeout=6, quiet=True, allow_missing=True)
        text = (result.stdout + result.stderr).lower()
        if "rust" in text or "shadowsocks 1." in text:
            return "rust"
        if "libev" in text:
            return "libev"
        # Newer rust builds print just "shadowsocks <semver>"; assume rust since
        # it is the only actively maintained implementation.
        return "rust" if text.strip() else "libev"

    def ensure_binary(self, *, install: bool = True) -> str:
        """Locate sslocal, installing it if we are allowed to."""

        binary = self.find_binary()
        if binary:
            self._binary = binary
            self._flavour = self.detect_flavour(binary)
            return binary
        if is_dry_run():
            self._binary = "/usr/bin/sslocal"
            self._flavour = "rust"
            return self._binary
        if not install:
            raise TransportError(
                "no shadowsocks client found on PATH",
                remedy="Install shadowsocks-rust (recommended) or shadowsocks-libev.",
            )

        for manager, argv in (
            ("apt-get", ["apt-get", "install", "-y", "--no-install-recommends", "shadowsocks-libev"]),
            ("dnf", ["dnf", "install", "-y", "shadowsocks-libev"]),
            ("apk", ["apk", "add", "--no-cache", "shadowsocks-libev"]),
            ("pacman", ["pacman", "-S", "--noconfirm", "shadowsocks-rust"]),
            ("opkg", ["opkg", "install", "shadowsocks-libev-ss-local"]),
        ):
            if which(manager) is None:
                continue
            log.info("installing a shadowsocks client with %s", manager)
            if manager == "apt-get":
                run(["apt-get", "update", "-qq"], timeout=180, allow_missing=True)
            result = run(argv, timeout=600, allow_missing=True)
            if result.ok:
                break

        binary = self.find_binary()
        if not binary:
            raise TransportError(
                "could not install a shadowsocks client automatically",
                remedy=(
                    "Install shadowsocks-rust from https://github.com/shadowsocks/shadowsocks-rust/releases "
                    "and put 'sslocal' on PATH, then re-run activation."
                ),
            )
        self._binary = binary
        self._flavour = self.detect_flavour(binary)
        log.info("shadowsocks client ready: %s (%s)", binary, self._flavour)
        return binary

    # ----------------------------------------------------------------- config

    def effective_method(self) -> str:
        """Downgrade 2022-series ciphers when running on libev."""

        if self._flavour == "libev" and self.cfg.method in RUST_ONLY_METHODS:
            log.warning(
                "%s is shadowsocks-rust only; falling back to %s for this libev build",
                self.cfg.method,
                LIBEV_FALLBACK_METHOD,
            )
            return LIBEV_FALLBACK_METHOD
        return self.cfg.method

    def build_config(self) -> dict[str, Any]:
        cfg = self.cfg
        data: dict[str, Any] = {
            "server": cfg.host,
            "server_port": cfg.port,
            "password": cfg.password,
            "method": self.effective_method(),
            "timeout": cfg.timeout_s,
            "mode": "tcp_and_udp" if cfg.udp_relay else "tcp_only",
            "fast_open": bool(cfg.fast_open),
            "locals": [
                {"protocol": "socks", "local_address": "0.0.0.0", "local_port": cfg.local_socks_port},
                {"protocol": "http", "local_address": "0.0.0.0", "local_port": cfg.local_http_port},
                # The redirect listener is what makes the route transparent for
                # LAN devices: nftables sends their traffic here.
                {"protocol": "redir", "local_address": "0.0.0.0", "local_port": cfg.local_redir_port},
            ],
        }
        if cfg.plugin:
            data["plugin"] = cfg.plugin
            if cfg.plugin_opts:
                data["plugin_opts"] = cfg.plugin_opts

        if self._flavour == "libev":
            # libev has no "locals" array; it takes a single listener.
            data.pop("locals", None)
            data["local_address"] = "0.0.0.0"
            data["local_port"] = cfg.local_redir_port
        return data

    def write_config(self) -> Path:
        self.run_dir = ensure_writable_dir(self.run_dir)
        self.config_path = self.run_dir / "shadowsocks.json"
        payload = json.dumps(self.build_config(), indent=2)
        if is_dry_run():
            log.info("[dry-run] would write shadowsocks config to %s", self.config_path)
            return self.config_path
        self.config_path.write_text(payload)
        os.chmod(self.config_path, 0o600)
        return self.config_path

    def _argv(self) -> list[str]:
        argv = [self._binary, "-c", str(self.config_path)]
        if self._flavour == "libev":
            # libev needs the transparent-proxy binary explicitly.
            redir = which("ss-redir")
            if redir:
                argv[0] = redir
            argv += ["-u"] if self.cfg.udp_relay else []
        return argv

    # -------------------------------------------------------------- lifecycle

    @property
    def running(self) -> bool:
        return self._process is not None and self._process.poll() is None

    async def start(self) -> None:
        """Start sslocal and keep it running."""

        if not self.cfg.usable:
            raise TransportError(
                "the shadow route needs a shadowsocks server address, port and password",
                remedy="Fill in the Shadowsocks section on the sign-in screen, or turn the shadow route off.",
            )
        if self.running:
            return

        self.ensure_binary()
        self.write_config()
        await self._spawn()

        self._stop.clear()
        if self._supervisor is None:
            self._supervisor = asyncio.create_task(self._supervise(), name="turbobond-ss-supervisor")

    async def _spawn(self) -> None:
        if is_dry_run():
            log.info("[dry-run] would start %s", " ".join(self._argv()))
            self._started_ts = time.time()
            return
        argv = self._argv()
        try:
            self._process = subprocess.Popen(  # noqa: S603
                argv,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
        except OSError as exc:
            self._last_error = str(exc)
            raise TransportError(f"could not start the shadowsocks client: {exc}") from exc

        # Give it a moment to fail fast on a bad config.
        await asyncio.sleep(0.6)
        if self._process.poll() is not None:
            stderr = b""
            if self._process.stderr is not None:
                with contextlib.suppress(Exception):
                    stderr = self._process.stderr.read() or b""
            detail = stderr.decode(errors="replace").strip().splitlines()
            self._last_error = detail[-1] if detail else f"exit code {self._process.returncode}"
            raise TransportError(
                f"the shadowsocks client exited immediately: {self._last_error}",
                remedy="Check the server address, port, password and cipher.",
            )
        self._started_ts = time.time()
        log.info(
            "shadowsocks client running (pid %s): socks :%d, redirect :%d",
            self._process.pid,
            self.cfg.local_socks_port,
            self.cfg.local_redir_port,
        )

    async def _supervise(self) -> None:
        """Restart sslocal with backoff whenever it dies."""

        attempt = 0
        while not self._stop.is_set():
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._stop.wait(), timeout=3.0)
                return
            if is_dry_run() or self.running:
                attempt = 0
                continue
            delay = RESTART_BACKOFF_S[min(attempt, len(RESTART_BACKOFF_S) - 1)]
            log.warning("shadowsocks client is not running; restarting in %ds", delay)
            await asyncio.sleep(delay)
            attempt += 1
            self._restarts += 1
            try:
                await self._spawn()
            except TransportError as exc:
                self._last_error = exc.message
                log.warning("shadowsocks restart failed: %s", exc.message)

    async def stop(self) -> None:
        self._stop.set()
        if self._supervisor is not None:
            self._supervisor.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._supervisor
            self._supervisor = None

        process = self._process
        self._process = None
        if process is None or process.poll() is not None:
            return
        with contextlib.suppress(OSError):
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
        try:
            await asyncio.wait_for(asyncio.to_thread(process.wait), timeout=5.0)
        except TimeoutError:
            with contextlib.suppress(OSError):
                os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        log.info("shadowsocks client stopped")

    # ----------------------------------------------------------------- health

    async def healthy(self) -> bool:
        """The redirect listener must be accepting connections."""

        if is_dry_run():
            return True
        if not self.running:
            return False
        probe = await netcheck.tcp_probe("127.0.0.1", port=self.cfg.local_redir_port, count=1, timeout_s=2.0)
        return probe.reachable

    def snapshot(self) -> dict[str, Any]:
        return {
            "configured": self.cfg.usable,
            "running": self.running or is_dry_run(),
            "binary": self._binary or self.find_binary(),
            "flavour": self._flavour,
            "server": f"{self.cfg.host}:{self.cfg.port}" if self.cfg.host else "",
            "method": self.effective_method(),
            "socks_port": self.cfg.local_socks_port,
            "redir_port": self.cfg.local_redir_port,
            "restarts": self._restarts,
            "uptime_s": round(time.time() - self._started_ts, 1) if self._started_ts else 0,
            "last_error": self._last_error,
        }


def sslocal_available() -> bool:
    return any(shutil.which(name) for name in SSLOCAL_CANDIDATES)
