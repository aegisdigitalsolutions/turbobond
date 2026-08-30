"""Tests for concentrator host provisioning."""

from __future__ import annotations

import subprocess

import pytest

from turbobond.bond import provision


@pytest.fixture
def settings() -> provision.ConcentratorSettings:
    return provision.ConcentratorSettings(psk="ab" * 32, port=5310)


class TestUnit:
    def test_carries_the_key_and_the_port(self, settings):
        unit = settings.unit_text()
        assert f"TURBOBOND_PSK={'ab' * 32}" in unit
        assert "--listen 0.0.0.0:5310" in unit

    def test_addresses_the_two_ends_of_the_tunnel_consistently(self):
        unit = provision.ConcentratorSettings(psk="00", server_ip="10.9.0.1", peer_ip="10.9.0.2").unit_text()
        assert "--local-cidr 10.9.0.1/30" in unit
        assert "--peer-ip 10.9.0.2" in unit

    def test_drops_privileges_it_does_not_need(self, settings):
        assert "CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW" in settings.unit_text()

    def test_restarts_itself(self, settings):
        assert "Restart=always" in settings.unit_text()


class TestPairingSummary:
    def test_shows_the_three_values_needed_to_pair(self, settings):
        text = provision.pairing_summary(settings, "203.0.113.10")
        assert "203.0.113.10" in text
        assert "5310" in text
        assert "ab" * 32 in text

    def test_says_what_is_missing_when_the_address_is_unknown(self, settings):
        assert "public IP" in provision.pairing_summary(settings, "")


class TestRun:
    def test_a_missing_binary_is_a_failure_not_an_exception(self):
        """Minimal images lack modprobe; that must not abort the install."""

        result = provision._run(["definitely-not-a-real-binary-xyz"])
        assert result.returncode == 127

    def test_reports_output_of_commands_that_do_exist(self):
        assert provision._run(["echo", "hello"]).stdout.strip() == "hello"


class TestProvisionHost:
    def test_writes_tuning_and_unit(self, settings, tmp_path, monkeypatch):
        sysctl = tmp_path / "99-turbobond.conf"
        unit = tmp_path / "turbobond-concentrator.service"
        monkeypatch.setattr(provision, "SYSCTL_PATH", sysctl)
        monkeypatch.setattr(provision, "UNIT_PATH", unit)

        steps = provision.provision_host(settings)

        assert "net.ipv4.ip_forward = 1" in sysctl.read_text()
        assert "bbr" in sysctl.read_text()
        assert "TURBOBOND_PSK" in unit.read_text()
        assert any("wrote" in step for step in steps)

    def test_keeps_going_when_the_kernel_tools_are_absent(self, settings, tmp_path, monkeypatch):
        """A container without modprobe still gets a unit written."""

        monkeypatch.setattr(provision, "SYSCTL_PATH", tmp_path / "sysctl.conf")
        monkeypatch.setattr(provision, "UNIT_PATH", tmp_path / "unit.service")
        monkeypatch.setattr(
            provision,
            "_run",
            lambda cmd: subprocess.CompletedProcess(cmd, 127, "", "not found"),
        )

        steps = provision.provision_host(settings)

        assert (tmp_path / "unit.service").exists()
        assert any("next boot" in step for step in steps)

    def test_the_unit_is_not_world_readable(self, settings, tmp_path, monkeypatch):
        """It holds the pre-shared key."""

        unit = tmp_path / "unit.service"
        monkeypatch.setattr(provision, "SYSCTL_PATH", tmp_path / "sysctl.conf")
        monkeypatch.setattr(provision, "UNIT_PATH", unit)

        provision.provision_host(settings)

        assert unit.stat().st_mode & 0o077 == 0

    def test_says_so_when_there_is_no_systemd(self, settings, tmp_path, monkeypatch):
        monkeypatch.setattr(provision, "SYSCTL_PATH", tmp_path / "sysctl.conf")
        monkeypatch.setattr(provision, "UNIT_PATH", tmp_path / "unit.service")
        monkeypatch.setattr(provision.Path, "exists", lambda self: False)

        steps = provision.provision_host(settings)

        assert any("no systemd" in step for step in steps)


class TestFirewall:
    def test_reports_when_there_is_nothing_to_open(self, monkeypatch):
        monkeypatch.setattr(provision.shutil, "which", lambda _: None)
        assert "no local firewall" in provision.open_firewall(5310)

    def test_opens_the_port_in_ufw_when_it_is_active(self, monkeypatch):
        monkeypatch.setattr(provision.shutil, "which", lambda name: "/usr/sbin/ufw" if name == "ufw" else None)
        calls: list[list[str]] = []

        def fake_run(cmd):
            calls.append(cmd)
            return subprocess.CompletedProcess(cmd, 0, "Status: active", "")

        monkeypatch.setattr(provision, "_run", fake_run)

        assert "ufw" in provision.open_firewall(5310)
        assert ["/usr/sbin/ufw", "allow", "5310/udp"] in calls

    def test_leaves_an_inactive_ufw_alone(self, monkeypatch):
        monkeypatch.setattr(provision.shutil, "which", lambda name: "/usr/sbin/ufw" if name == "ufw" else None)
        monkeypatch.setattr(
            provision, "_run", lambda cmd: subprocess.CompletedProcess(cmd, 0, "Status: inactive", "")
        )
        assert "no local firewall" in provision.open_firewall(5310)


class TestServerCli:
    def test_provision_requires_root(self, monkeypatch, capsys):
        from turbobond.bond import server

        monkeypatch.setattr(provision, "is_root", lambda: False)
        assert server.main(["--provision"]) == 2
        assert "root" in capsys.readouterr().err

    def test_provision_generates_a_key_when_none_is_given(self, monkeypatch, capsys):
        from turbobond.bond import server

        monkeypatch.setattr(provision, "is_root", lambda: True)
        monkeypatch.setattr(provision, "provision_host", lambda s: ["ok"])
        monkeypatch.setattr(provision, "open_firewall", lambda p: "ok")
        monkeypatch.setattr(provision, "detect_public_ip", lambda: "203.0.113.7")

        assert server.main(["--provision"]) == 0
        out = capsys.readouterr().out
        assert "203.0.113.7" in out
        assert "Pre-shared key" in out

    def test_provision_keeps_a_key_that_was_supplied(self, monkeypatch, capsys):
        from turbobond.bond import server

        monkeypatch.setattr(provision, "is_root", lambda: True)
        monkeypatch.setattr(provision, "provision_host", lambda s: [])
        monkeypatch.setattr(provision, "open_firewall", lambda p: "")
        monkeypatch.setattr(provision, "detect_public_ip", lambda: "")

        server.main(["--provision", "--psk", "cd" * 32])
        assert "cd" * 32 in capsys.readouterr().out
