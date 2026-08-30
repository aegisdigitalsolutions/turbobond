"""Tests for concentrator host provisioning."""

from __future__ import annotations

import os
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


class TestFirewallRuleLifecycle:
    """The unit restarts on failure, so rules must not pile up per restart."""

    def _server(self):
        from turbobond.bond.server import ConcentratorServer

        return ConcentratorServer("ab" * 32, egress_interface="eth0")

    def test_puts_the_table_flag_before_the_action(self):
        """'iptables -A -t nat ...' is rejected; the table has to come first."""

        from turbobond.bond.server import ConcentratorServer

        cmd = ConcentratorServer._rule_command(["-t", "nat", "POSTROUTING", "-j", "MASQUERADE"], "-A")
        assert cmd[:4] == ["iptables", "-t", "nat", "-A"]

    def test_leaves_untabled_rules_alone(self):
        from turbobond.bond.server import ConcentratorServer

        cmd = ConcentratorServer._rule_command(["FORWARD", "-j", "ACCEPT"], "-D")
        assert cmd == ["iptables", "-D", "FORWARD", "-j", "ACCEPT"]

    def test_existing_rules_are_not_added_twice(self, monkeypatch):
        from turbobond.bond import server as server_mod

        calls: list[list[str]] = []

        class Result:
            ok = True

        def fake_run(cmd, **kwargs):
            calls.append(cmd)
            return Result()

        monkeypatch.setattr(server_mod, "run", fake_run)
        srv = self._server()
        srv._ensure_rule(["FORWARD", "-j", "ACCEPT"])

        assert all("-A" not in cmd for cmd in calls), "rule already present was appended again"

    def test_missing_rules_are_added(self, monkeypatch):
        from turbobond.bond import server as server_mod

        calls: list[list[str]] = []

        class Result:
            ok = False

        def fake_run(cmd, **kwargs):
            calls.append(cmd)
            return Result()

        monkeypatch.setattr(server_mod, "run", fake_run)
        srv = self._server()
        srv._ensure_rule(["FORWARD", "-j", "ACCEPT"])

        assert any("-A" in cmd for cmd in calls)

    def test_removal_deletes_every_rule_that_was_added(self, monkeypatch):
        from turbobond.bond import server as server_mod

        calls: list[list[str]] = []

        class Result:
            ok = False

        monkeypatch.setattr(server_mod, "run", lambda cmd, **kw: (calls.append(cmd), Result())[1])
        srv = self._server()
        srv._firewall_rules = [
            ["-t", "nat", "POSTROUTING", "-j", "MASQUERADE"],
            ["FORWARD", "-j", "ACCEPT"],
        ]

        srv._remove_firewall_rules()

        deletes = [cmd for cmd in calls if "-D" in cmd]
        assert len(deletes) == 2
        assert srv._firewall_rules == []


class TestInstalledSettings:
    """The key exists only on the server, so reading it back has to work."""

    def test_reads_back_what_was_written(self, settings, tmp_path, monkeypatch):
        unit = tmp_path / "unit.service"
        monkeypatch.setattr(provision, "UNIT_PATH", unit)
        unit.write_text(settings.unit_text())

        found = provision.installed_settings()

        assert found is not None
        assert found.psk == settings.psk
        assert found.port == settings.port

    def test_reads_back_a_non_default_port_and_addresses(self, tmp_path, monkeypatch):
        unit = tmp_path / "unit.service"
        monkeypatch.setattr(provision, "UNIT_PATH", unit)
        unit.write_text(
            provision.ConcentratorSettings(
                psk="ff" * 32, port=9999, server_ip="10.9.0.1", peer_ip="10.9.0.2"
            ).unit_text()
        )

        found = provision.installed_settings()

        assert found is not None
        assert found.port == 9999
        assert found.server_ip == "10.9.0.1"
        assert found.peer_ip == "10.9.0.2"

    def test_returns_nothing_when_not_installed(self, tmp_path, monkeypatch):
        monkeypatch.setattr(provision, "UNIT_PATH", tmp_path / "absent.service")
        assert provision.installed_settings() is None

    def test_returns_nothing_when_the_unit_holds_no_key(self, tmp_path, monkeypatch):
        unit = tmp_path / "unit.service"
        monkeypatch.setattr(provision, "UNIT_PATH", unit)
        unit.write_text("[Service]\nExecStart=/usr/local/bin/turbobond-server\n")

        assert provision.installed_settings() is None

    def test_an_unreadable_unit_is_not_reported_as_missing(
        self, settings, tmp_path, monkeypatch
    ):
        """The unit is mode 0600. Calling that "not installed" invites a
        reinstall, when the caller only needed to be root."""

        unit = tmp_path / "unit.service"
        monkeypatch.setattr(provision, "UNIT_PATH", unit)
        unit.write_text(settings.unit_text())
        unit.chmod(0o000)

        if os.geteuid() == 0:
            pytest.skip("root reads through the mode bits")

        with pytest.raises(PermissionError):
            provision.installed_settings()


class TestPairingCommand:
    def test_prints_the_installed_values(self, settings, tmp_path, monkeypatch, capsys):
        from turbobond.bond import server

        unit = tmp_path / "unit.service"
        monkeypatch.setattr(provision, "UNIT_PATH", unit)
        monkeypatch.setattr(provision, "detect_public_ip", lambda: "203.0.113.9")
        unit.write_text(settings.unit_text())

        assert server.main(["--pairing"]) == 0
        out = capsys.readouterr().out
        assert settings.psk in out
        assert "203.0.113.9" in out

    def test_says_so_when_nothing_is_installed(self, tmp_path, monkeypatch, capsys):
        from turbobond.bond import server

        monkeypatch.setattr(provision, "UNIT_PATH", tmp_path / "absent.service")

        assert server.main(["--pairing"]) == 1
        assert "no installed concentrator" in capsys.readouterr().err

    def test_points_at_sudo_when_the_unit_cannot_be_read(
        self, settings, tmp_path, monkeypatch, capsys
    ):
        from turbobond.bond import server

        unit = tmp_path / "unit.service"
        monkeypatch.setattr(provision, "UNIT_PATH", unit)
        unit.write_text(settings.unit_text())
        unit.chmod(0o000)

        if os.geteuid() == 0:
            pytest.skip("root reads through the mode bits")

        assert server.main(["--pairing"]) == 1
        err = capsys.readouterr().err
        assert "sudo turbobond-server --pairing" in err
        assert settings.psk not in err


class TestReprovisionKeepsTheKey:
    """Re-running the installer must not silently unpair existing clients."""

    def test_an_existing_key_is_reused(self, tmp_path, monkeypatch, capsys):
        from turbobond.bond import server

        unit = tmp_path / "unit.service"
        monkeypatch.setattr(provision, "UNIT_PATH", unit)
        monkeypatch.setattr(provision, "is_root", lambda: True)
        monkeypatch.setattr(provision, "provision_host", lambda s: [])
        monkeypatch.setattr(provision, "open_firewall", lambda p: "")
        monkeypatch.setattr(provision, "detect_public_ip", lambda: "")
        unit.write_text(provision.ConcentratorSettings(psk="1a" * 32).unit_text())

        server.main(["--provision"])

        assert "1a" * 32 in capsys.readouterr().out

    def test_an_explicit_key_overrides_the_installed_one(self, tmp_path, monkeypatch, capsys):
        from turbobond.bond import server

        unit = tmp_path / "unit.service"
        monkeypatch.setattr(provision, "UNIT_PATH", unit)
        monkeypatch.setattr(provision, "is_root", lambda: True)
        monkeypatch.setattr(provision, "provision_host", lambda s: [])
        monkeypatch.setattr(provision, "open_firewall", lambda p: "")
        monkeypatch.setattr(provision, "detect_public_ip", lambda: "")
        unit.write_text(provision.ConcentratorSettings(psk="1a" * 32).unit_text())

        server.main(["--provision", "--psk", "2b" * 32])

        out = capsys.readouterr().out
        assert "2b" * 32 in out
        assert "1a" * 32 not in out


class TestServerCli:
    def test_provision_requires_root(self, monkeypatch, capsys):
        from turbobond.bond import server

        monkeypatch.setattr(provision, "is_root", lambda: False)
        assert server.main(["--provision"]) == 2
        assert "root" in capsys.readouterr().err

    def test_provision_generates_a_key_when_none_is_given(
        self, tmp_path, monkeypatch, capsys
    ):
        from turbobond.bond import server

        monkeypatch.setattr(provision, "UNIT_PATH", tmp_path / "absent.service")
        monkeypatch.setattr(provision, "is_root", lambda: True)
        monkeypatch.setattr(provision, "provision_host", lambda s: ["ok"])
        monkeypatch.setattr(provision, "open_firewall", lambda p: "ok")
        monkeypatch.setattr(provision, "detect_public_ip", lambda: "203.0.113.7")

        assert server.main(["--provision"]) == 0
        out = capsys.readouterr().out
        assert "203.0.113.7" in out
        assert "Pre-shared key" in out

    def test_provision_keeps_a_key_that_was_supplied(self, tmp_path, monkeypatch, capsys):
        from turbobond.bond import server

        monkeypatch.setattr(provision, "UNIT_PATH", tmp_path / "absent.service")
        monkeypatch.setattr(provision, "is_root", lambda: True)
        monkeypatch.setattr(provision, "provision_host", lambda s: [])
        monkeypatch.setattr(provision, "open_firewall", lambda p: "")
        monkeypatch.setattr(provision, "detect_public_ip", lambda: "")

        server.main(["--provision", "--psk", "cd" * 32])
        assert "cd" * 32 in capsys.readouterr().out

    def test_provision_refuses_rather_than_regenerate_an_unreadable_key(
        self, settings, tmp_path, monkeypatch, capsys
    ):
        """Treating an unreadable unit as "no key" would mint a new one and
        unpair every client. Stopping is the recoverable outcome."""

        from turbobond.bond import server

        unit = tmp_path / "unit.service"
        unit.write_text(settings.unit_text())
        unit.chmod(0o000)
        monkeypatch.setattr(provision, "UNIT_PATH", unit)
        monkeypatch.setattr(provision, "is_root", lambda: True)
        monkeypatch.setattr(provision, "provision_host", lambda s: [])

        if os.geteuid() == 0:
            pytest.skip("root reads through the mode bits")

        assert server.main(["--provision"]) == 1
        assert "could not be read" in capsys.readouterr().err
