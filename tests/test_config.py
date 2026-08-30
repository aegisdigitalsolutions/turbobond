from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from turbobond.config import (
    AppConfig,
    ConcentratorConfig,
    LinkConfig,
    RouterConfig,
    ShadowsocksConfig,
    SipConfig,
    load_config,
    save_config,
)
from turbobond.errors import ConfigError


class TestDefaults:
    def test_a_bare_config_is_valid(self) -> None:
        cfg = AppConfig()
        assert cfg.optimization.profile == "wrt-turbo-search"
        assert cfg.optimization.turbo and cfg.optimization.search
        assert cfg.sip.wide_open
        assert cfg.lan.enabled

    def test_both_routes_are_offered_by_default(self) -> None:
        assert AppConfig().available_routes() == ["direct", "shadow"]

    def test_disabling_shadowsocks_leaves_only_the_direct_route(self) -> None:
        cfg = AppConfig()
        cfg.shadowsocks.enabled = False
        assert cfg.available_routes() == ["direct"]


class TestRouterConfig:
    @pytest.mark.parametrize(
        ("given", "expected"),
        [
            ("http://192.168.1.1", "192.168.1.1"),
            ("https://192.168.1.1/", "192.168.1.1"),
            ("  192.168.1.1  ", "192.168.1.1"),
        ],
    )
    def test_host_is_normalised(self, given: str, expected: str) -> None:
        assert RouterConfig(host=given).host == expected

    def test_empty_host_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            RouterConfig(host="   ")

    def test_base_url_includes_the_scheme(self) -> None:
        assert RouterConfig(host="10.0.0.1", scheme="https").base_url == "https://10.0.0.1"


class TestSipConfig:
    def test_default_range_covers_the_usual_rtp_span(self) -> None:
        cfg = SipConfig()
        assert cfg.rtp_port_start == 10000
        assert cfg.rtp_port_end == 65535
        assert 5060 in cfg.signalling_ports

    def test_inverted_rtp_range_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            SipConfig(rtp_port_start=30000, rtp_port_end=20000)

    def test_out_of_range_signalling_port_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            SipConfig(signalling_ports=[70000])


class TestConcentratorConfig:
    def test_enabling_without_a_host_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ConcentratorConfig(enabled=True, host="")

    def test_psk_is_generated_once_and_reused(self) -> None:
        cfg = ConcentratorConfig()
        first = cfg.ensure_psk()
        assert len(first) == 64
        assert cfg.ensure_psk() == first


class TestShadowsocksConfig:
    def test_a_host_without_a_password_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ShadowsocksConfig(host="ss.example.com", password="")

    def test_usable_requires_a_full_endpoint(self) -> None:
        assert not ShadowsocksConfig().usable
        assert ShadowsocksConfig(host="ss.example.com", password="secret").usable


class TestLinkConfig:
    def test_zero_weight_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            LinkConfig(name="wan", interface="eth0", weight=0)

    def test_table_ids_are_unique_and_stable(self) -> None:
        cfg = AppConfig(
            links=[
                LinkConfig(name="a", interface="eth0"),
                LinkConfig(name="b", interface="eth1"),
                LinkConfig(name="c", interface="eth2", table_id=201),
            ]
        )
        cfg.assign_table_ids()
        ids = [link.table_id for link in cfg.links]
        assert len(set(ids)) == 3
        assert all(ids)
        # An explicitly configured id is never reassigned.
        assert cfg.links[2].table_id == 201


class TestPersistence:
    def test_save_then_load_roundtrips(self, tmp_path: Path) -> None:
        cfg = AppConfig(config_dir=tmp_path)
        cfg.router.password = "router-secret"
        cfg.sip.rtp_port_start = 16384
        cfg.links = [LinkConfig(name="wan1", interface="eth0", weight=2.5)]
        path = save_config(cfg)

        loaded = load_config(path)
        assert loaded.router.password == "router-secret"
        assert loaded.sip.rtp_port_start == 16384
        assert loaded.links[0].weight == 2.5

    def test_config_file_is_owner_only(self, tmp_path: Path) -> None:
        """It holds the router password and the tunnel key."""

        cfg = AppConfig(config_dir=tmp_path)
        path = save_config(cfg)
        assert oct(path.stat().st_mode)[-3:] == "600"

    def test_a_missing_file_yields_defaults(self, tmp_path: Path) -> None:
        cfg = load_config(tmp_path / "nope.yaml")
        assert cfg.optimization.profile == "wrt-turbo-search"

    def test_malformed_yaml_reports_the_path(self, tmp_path: Path) -> None:
        path = tmp_path / "broken.yaml"
        path.write_text("router:\n  host: [unclosed\n")
        with pytest.raises(ConfigError) as exc:
            load_config(path)
        assert "broken.yaml" in exc.value.message

    def test_a_non_mapping_document_is_rejected(self, tmp_path: Path) -> None:
        path = tmp_path / "list.yaml"
        path.write_text("- one\n- two\n")
        with pytest.raises(ConfigError):
            load_config(path)

    def test_saved_yaml_omits_runtime_paths(self, tmp_path: Path) -> None:
        cfg = AppConfig(config_dir=tmp_path)
        raw = yaml.safe_load(save_config(cfg).read_text())
        assert "config_dir" not in raw
        assert "state_dir" not in raw


class TestRedaction:
    def test_secrets_are_masked(self) -> None:
        cfg = AppConfig()
        cfg.router.password = "router-secret"
        cfg.shadowsocks.password = "ss-secret"
        cfg.concentrator.psk_hex = "ab" * 32
        cfg.auth.password_hash = "$argon2id$stuff"
        cfg.auth.session_secret = "session-secret"

        data = cfg.redacted()
        assert data["router"]["password"] == "********"
        assert data["shadowsocks"]["password"] == "********"
        assert data["concentrator"]["psk_hex"] == "********"
        assert data["auth"]["password_hash"] == "********"
        assert data["auth"]["session_secret"] == "********"

    def test_empty_secrets_stay_empty(self) -> None:
        data = AppConfig().redacted()
        assert data["router"]["password"] == ""

    def test_non_secret_fields_survive(self) -> None:
        data = AppConfig().redacted()
        assert data["optimization"]["profile"] == "wrt-turbo-search"
        assert data["sip"]["wide_open"] is True


def test_enabled_links_filters_disabled_ones() -> None:
    cfg = AppConfig(
        links=[
            LinkConfig(name="a", interface="eth0", enabled=True),
            LinkConfig(name="b", interface="eth1", enabled=False),
        ]
    )
    assert [link.name for link in cfg.enabled_links()] == ["a"]
