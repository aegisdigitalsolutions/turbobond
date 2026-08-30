"""Tests for the concentrator's self-check.

These matter more than most: the check exists to be believed when someone is
already stuck, so a wrong 'ok' is worse than no check at all.
"""

from __future__ import annotations

import socket
import subprocess

import pytest

from turbobond.bond import provision, selfcheck
from turbobond.bond.protocol import FrameType, encode_frame
from turbobond.util.crypto import Sealer

PSK = "ab" * 32


def stub_run(monkeypatch, table: dict[str, str]):
    """Answer the check's shell-outs from a table keyed on the binary name."""

    def fake(cmd, *args, **kwargs):
        name = cmd[0].rsplit("/", 1)[-1]
        key = f"{name} {cmd[1]}" if len(cmd) > 1 else name
        for candidate in (key, name):
            if candidate in table:
                return subprocess.CompletedProcess(cmd, 0, table[candidate], "")
        return subprocess.CompletedProcess(cmd, 1, "", "")

    monkeypatch.setattr(selfcheck.subprocess, "run", fake)


class TestService:
    def test_active_passes(self, monkeypatch):
        monkeypatch.setattr(selfcheck.shutil, "which", lambda _: "/bin/systemctl")
        stub_run(monkeypatch, {"systemctl is-active": "active\n"})
        assert selfcheck.check_service().status == selfcheck.OK

    def test_a_stopped_service_fails_and_says_where_to_look(self, monkeypatch):
        monkeypatch.setattr(selfcheck.shutil, "which", lambda _: "/bin/systemctl")
        stub_run(monkeypatch, {"systemctl is-active": "failed\n"})

        result = selfcheck.check_service()

        assert result.status == selfcheck.FAIL
        assert "journalctl" in result.detail

    def test_no_systemd_warns_rather_than_fails(self, monkeypatch):
        monkeypatch.setattr(selfcheck.shutil, "which", lambda _: None)
        assert selfcheck.check_service().status == selfcheck.WARN


class TestListening:
    def test_a_free_port_is_reported_as_nothing_listening(self):
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()

        assert selfcheck.check_listening(port).status == selfcheck.FAIL

    def test_a_held_port_is_reported_as_listening(self):
        held = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        held.bind(("0.0.0.0", 0))
        port = held.getsockname()[1]
        try:
            assert selfcheck.check_listening(port).status == selfcheck.OK
        finally:
            held.close()


class TestLocalFirewall:
    def test_inactive_ufw_blocks_nothing(self, monkeypatch):
        monkeypatch.setattr(
            selfcheck.shutil, "which", lambda name: "/usr/sbin/ufw" if name == "ufw" else None
        )
        stub_run(monkeypatch, {"ufw status": "Status: inactive\n"})
        assert selfcheck.check_local_firewall(5310).status == selfcheck.OK

    def test_active_ufw_with_the_port_open_passes(self, monkeypatch):
        monkeypatch.setattr(
            selfcheck.shutil, "which", lambda name: "/usr/sbin/ufw" if name == "ufw" else None
        )
        stub_run(monkeypatch, {"ufw status": "Status: active\n\n5310/udp  ALLOW  Anywhere\n"})
        assert selfcheck.check_local_firewall(5310).status == selfcheck.OK

    def test_active_ufw_without_the_port_fails_with_the_command_to_run(self, monkeypatch):
        monkeypatch.setattr(
            selfcheck.shutil, "which", lambda name: "/usr/sbin/ufw" if name == "ufw" else None
        )
        stub_run(monkeypatch, {"ufw status": "Status: active\n\n22/tcp  ALLOW  Anywhere\n"})

        result = selfcheck.check_local_firewall(5310)

        assert result.status == selfcheck.FAIL
        assert result.detail == "ufw allow 5310/udp"

    def test_firewalld_without_the_port_fails(self, monkeypatch):
        monkeypatch.setattr(
            selfcheck.shutil,
            "which",
            lambda name: "/usr/bin/firewall-cmd" if name == "firewall-cmd" else None,
        )
        stub_run(monkeypatch, {"firewall-cmd --list-ports": "22/tcp\n"})

        result = selfcheck.check_local_firewall(5310)

        assert result.status == selfcheck.FAIL
        assert "--add-port=5310/udp" in result.detail


class TestAddress:
    @pytest.mark.parametrize("addr", ["10.0.0.4", "172.16.3.9", "192.168.1.50"])
    def test_a_private_address_is_a_failure(self, addr):
        """Clients were told to dial this, and cannot reach it from outside."""

        result = selfcheck.check_address(addr)

        assert result.status == selfcheck.FAIL
        assert "--public-ip" in result.detail

    def test_a_public_address_passes(self):
        assert selfcheck.check_address("45.55.100.1").status == selfcheck.OK

    def test_an_unknown_address_warns(self):
        assert selfcheck.check_address("").status == selfcheck.WARN


class TestHandshake:
    """The check that decides whether the fault is here or on the way here."""

    @staticmethod
    def _responder(psk: str, reply_type: FrameType | None) -> tuple[socket.socket, int]:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]

        def serve():
            _, addr = sock.recvfrom(65535)
            if reply_type is None:
                return
            # Replies under its own key without reading the request, so this
            # can stand in for a server running a key the caller does not have.
            sock.sendto(
                encode_frame(
                    Sealer.from_psk(psk),
                    frame_type=reply_type,
                    session_id=0x7EC0DE,
                    link_id=1,
                    counter=1,
                    seq=0,
                    payload=b"",
                ),
                addr,
            )

        import threading

        threading.Thread(target=serve, daemon=True).start()
        return sock, port

    def test_an_ack_is_success(self):
        sock, port = self._responder(PSK, FrameType.HANDSHAKE_ACK)
        try:
            assert selfcheck.check_handshake(PSK, port).status == selfcheck.OK
        finally:
            sock.close()

    def test_silence_is_a_failure(self):
        sock, port = self._responder(PSK, None)
        try:
            assert selfcheck.check_handshake(PSK, port, timeout=0.4).status == selfcheck.FAIL
        finally:
            sock.close()

    def test_a_reply_under_another_key_does_not_authenticate(self):
        """A server left running on an older key must not be reported healthy."""

        sock, port = self._responder("cd" * 32, FrameType.HANDSHAKE_ACK)
        try:
            result = selfcheck.check_handshake(PSK, port, timeout=1.0)
        finally:
            sock.close()

        assert result.status == selfcheck.FAIL

    def test_an_unusable_key_fails_before_sending(self):
        assert selfcheck.check_handshake("nonsense", 9).status == selfcheck.FAIL


class TestRunChecks:
    def test_nothing_installed_short_circuits(self, tmp_path, monkeypatch):
        monkeypatch.setattr(provision, "UNIT_PATH", tmp_path / "absent.service")

        results, verdict = selfcheck.run_checks()

        assert results[0].status == selfcheck.FAIL
        assert "Nothing to check" in verdict

    def test_the_handshake_is_skipped_when_nothing_listens(self, tmp_path, monkeypatch):
        """Otherwise a dead port is reported twice, as two separate faults."""

        unit = tmp_path / "unit.service"
        unit.write_text(provision.ConcentratorSettings(psk=PSK, port=5310).unit_text())
        monkeypatch.setattr(provision, "UNIT_PATH", unit)
        monkeypatch.setattr(
            selfcheck, "check_listening", lambda _: selfcheck.Result(selfcheck.FAIL, "nothing")
        )

        results, _ = selfcheck.run_checks("45.55.100.1")

        handshake = results[-1]
        assert handshake.status == selfcheck.FAIL
        assert "not attempted" in handshake.title

    def test_a_healthy_server_points_at_the_cloud_firewall_and_the_key(
        self, tmp_path, monkeypatch
    ):
        unit = tmp_path / "unit.service"
        unit.write_text(provision.ConcentratorSettings(psk=PSK, port=5310).unit_text())
        monkeypatch.setattr(provision, "UNIT_PATH", unit)
        for name, ok in (
            ("check_service", "running"),
            ("check_listening", "listening"),
            ("check_local_firewall", "open"),
        ):
            monkeypatch.setattr(
                selfcheck, name, lambda *_, _t=ok: selfcheck.Result(selfcheck.OK, _t)
            )
        monkeypatch.setattr(
            selfcheck, "check_handshake", lambda *a, **k: selfcheck.Result(selfcheck.OK, "paired")
        )

        results, verdict = selfcheck.run_checks("45.55.100.1")

        assert all(r.status == selfcheck.OK for r in results)
        assert "cloud firewall" in verdict
        assert "--pairing" in verdict

    def test_the_report_renders_every_line(self):
        results = [
            selfcheck.Result(selfcheck.OK, "fine"),
            selfcheck.Result(selfcheck.FAIL, "broken", "do this"),
        ]

        report = selfcheck.format_report(results, "verdict")

        assert "[ ok ] fine" in report
        assert "[fail] broken" in report
        assert "do this" in report
        assert "verdict" in report
