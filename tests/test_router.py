from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from turbobond.config import OptimizationConfig, RouterConfig
from turbobond.errors import RouterError
from turbobond.router.netgear_m7pro import (
    _SIMULATED_MODEL,
    NighthawkAdmin,
    dig,
    first_present,
)
from turbobond.router.provision import (
    NON_DFS_5GHZ,
    router_profile,
    sysctl_profile,
)
from turbobond.util.cmd import dry_run_scope, set_dry_run


class TestPathResolution:
    def test_dig_walks_nested_dicts(self) -> None:
        tree = {"a": {"b": {"c": 42}}}
        assert dig(tree, "a.b.c") == 42

    def test_dig_indexes_into_lists(self) -> None:
        tree = {"items": [{"name": "first"}, {"name": "second"}]}
        assert dig(tree, "items.1.name") == "second"

    def test_dig_returns_none_for_a_missing_path(self) -> None:
        assert dig({"a": 1}, "a.b.c") is None
        assert dig({"a": 1}, "z") is None
        assert dig(None, "a") is None

    def test_first_present_skips_empty_candidates(self) -> None:
        """Field names differ between firmware trains, so aliases matter."""

        tree = {"general": {"model": "", "deviceName": "Nighthawk"}}
        assert first_present(tree, ("general.model", "general.deviceName")) == "Nighthawk"

    def test_first_present_returns_none_when_nothing_matches(self) -> None:
        assert first_present({}, ("a.b", "c.d")) is None


class TestStatusParsing:
    @pytest.fixture
    def admin(self) -> NighthawkAdmin:
        client = NighthawkAdmin(RouterConfig(host="192.168.1.1", password="secret"))
        client._model = _SIMULATED_MODEL
        return client

    def test_reads_identity_and_radio_state(self, admin: NighthawkAdmin) -> None:
        status = admin._build_status()
        assert "M7 Pro" in status.model
        assert status.firmware.startswith("NTG9X75C")
        assert status.wan_state == "Connected"
        assert status.network_type == "5G-SA"
        assert status.rsrp == -88
        assert status.sinr == 14.5
        assert status.battery_pct == 88

    def test_splits_a_carrier_aggregated_band_string(self, admin: NighthawkAdmin) -> None:
        assert admin._build_status().bands == ["n41", "n77"]

    def test_detects_that_sip_alg_is_on(self, admin: NighthawkAdmin) -> None:
        assert admin._build_status().sip_alg_enabled is True

    def test_missing_fields_do_not_raise(self) -> None:
        admin = NighthawkAdmin(RouterConfig())
        admin._model = {}
        status = admin._build_status()
        assert status.model == ""
        assert status.rssi is None
        assert status.bands == []


class TestTokenExtraction:
    def test_finds_the_token_in_the_session_subtree(self) -> None:
        admin = NighthawkAdmin(RouterConfig())
        assert admin._extract_token({"session": {"secToken": "abc123"}}) == "abc123"

    def test_falls_back_to_scanning_the_raw_body(self) -> None:
        """Some firmwares only emit the token inline in the JS payload."""

        admin = NighthawkAdmin(RouterConfig())
        assert admin._extract_token({}, 'var x = {"secToken":"inline-token"};') == "inline-token"

    def test_returns_empty_when_absent(self) -> None:
        assert NighthawkAdmin(RouterConfig())._extract_token({}, "nothing here") == ""


class TestDeviceListing:
    async def test_lists_attached_clients(self) -> None:
        with dry_run_scope():
            admin = NighthawkAdmin(RouterConfig())
            devices = await admin.devices()
        assert len(devices) == 3
        by_name = {d.name: d for d in devices}
        assert by_name["desk-phone"].ip == "192.168.1.20"
        assert by_name["laptop"].rssi == -47

    async def test_entries_without_an_address_are_skipped(self) -> None:
        admin = NighthawkAdmin(RouterConfig())
        admin._model = {"router": {"clientList": [{"name": "ghost"}, {"mac": "aa:bb:cc:dd:ee:ff"}]}}

        async def _fetch() -> dict[str, Any]:
            return admin._model

        admin.fetch_model = _fetch  # type: ignore[method-assign]
        devices = await admin.devices()
        assert [d.mac for d in devices] == ["aa:bb:cc:dd:ee:ff"]


class TestTransport:
    """These exercise the real HTTP path, so dry-run's simulated tree is off."""

    @pytest.fixture(autouse=True)
    def live(self):
        set_dry_run(False)
        yield
        set_dry_run(True)

    async def test_parses_model_json_over_http(self) -> None:
        payload = {"session": {"secToken": "tok"}, "general": {"model": "MR7400"}}

        def handler(request: httpx.Request) -> httpx.Response:
            assert request.url.path == "/api/model.json"
            return httpx.Response(200, json=payload)

        admin = NighthawkAdmin(RouterConfig(host="192.168.1.1"))
        admin._client = httpx.AsyncClient(
            base_url="http://192.168.1.1", transport=httpx.MockTransport(handler)
        )
        model = await admin.fetch_model()
        assert model["general"]["model"] == "MR7400"
        assert admin._token == "tok"
        await admin.close()

    async def test_unwraps_a_javascript_assignment(self) -> None:
        """Older firmware serves the tree as `var model = {...};`."""

        body = "var model = " + json.dumps({"general": {"model": "MR1100"}}) + ";"

        admin = NighthawkAdmin(RouterConfig())
        admin._client = httpx.AsyncClient(
            base_url="http://192.168.1.1",
            transport=httpx.MockTransport(lambda _: httpx.Response(200, text=body)),
        )
        model = await admin.fetch_model()
        assert model["general"]["model"] == "MR1100"
        await admin.close()

    async def test_an_unreachable_router_raises_with_a_remedy(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("no route to host")

        admin = NighthawkAdmin(RouterConfig())
        admin._client = httpx.AsyncClient(
            base_url="http://192.168.1.1", transport=httpx.MockTransport(handler)
        )
        with pytest.raises(RouterError) as exc:
            await admin.fetch_model()
        assert exc.value.remedy
        await admin.close()

    async def test_connect_reports_unreachable_rather_than_raising(self) -> None:
        """Activation must continue even when the router is not answering."""

        admin = NighthawkAdmin(RouterConfig())
        admin._client = httpx.AsyncClient(
            base_url="http://192.168.1.1",
            transport=httpx.MockTransport(lambda _: httpx.Response(500)),
        )
        status = await admin.connect()
        assert not status.reachable
        assert status.error
        await admin.close()


class TestOptimizationProfile:
    def test_turbo_enables_the_throughput_knobs(self) -> None:
        profile = router_profile(OptimizationConfig(turbo=True))
        assert profile["wmm"] is True
        assert profile["power_saving"] is False
        assert profile["port_filter"] is False

    def test_turbo_off_leaves_the_router_alone(self) -> None:
        assert router_profile(OptimizationConfig(turbo=False, prefer_5ghz=False)) == {}

    def test_an_explicit_mtu_is_pushed(self) -> None:
        assert router_profile(OptimizationConfig(wan_mtu=1420))["mtu"] == 1420

    def test_sysctls_cover_congestion_control_and_mptcp(self) -> None:
        sysctls = sysctl_profile(OptimizationConfig(congestion_control="bbr"))
        assert sysctls["net.ipv4.tcp_congestion_control"] == "bbr"
        assert sysctls["net.mptcp.enabled"] == "1"
        assert sysctls["net.ipv4.ip_forward"] == "1"

    def test_reverse_path_filtering_is_loosened(self) -> None:
        """Several default routes with different sources is normal in a bond."""

        sysctls = sysctl_profile(OptimizationConfig())
        assert sysctls["net.ipv4.conf.all.rp_filter"] == "2"

    def test_non_dfs_channels_avoid_radar_vacate(self) -> None:
        assert 52 not in NON_DFS_5GHZ
        assert 149 in NON_DFS_5GHZ
