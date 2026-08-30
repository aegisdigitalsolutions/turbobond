"""NETGEAR Nighthawk web-administrator client (M1/M5/M6/M7 Pro family).

These devices expose their entire configuration tree as JSON at
``/api/model.json`` and accept writes as form posts to ``/Forms/config``, each
carrying the CSRF token that ``model.json`` publishes. Field names differ
between firmware trains, so every read goes through a candidate-path resolver
and every write is attempted against each known alias until one sticks.
"""

from __future__ import annotations

import asyncio
import json
import re
from typing import Any

import httpx

from turbobond.config import RouterConfig
from turbobond.errors import RouterAuthError, RouterError
from turbobond.logging_setup import get_logger
from turbobond.router.base import ConnectedDevice, RouterStatus
from turbobond.util.cmd import is_dry_run

log = get_logger("router.netgear")

MODEL_JSON_PATHS = ("/api/model.json", "/model.json", "/api/model.json?internalapi=1")
CONFIG_FORM_PATH = "/Forms/config"

# Where the CSRF token hides, across firmware generations.
TOKEN_PATHS = (
    "session.secToken",
    "sess.secToken",
    "session.sessionId",
    "secToken",
    "general.secToken",
)
_TOKEN_RE = re.compile(r'"secToken"\s*:\s*"([^"]+)"')

# Read aliases: logical name -> candidate dotted paths in model.json.
FIELD_ALIASES: dict[str, tuple[str, ...]] = {
    "model": ("general.model", "device.model", "general.deviceName", "power.deviceName"),
    "firmware": ("general.FWVersion", "general.fwVersion", "device.FWversion", "general.swVersion"),
    "serial": ("general.SerialNumber", "device.serialNumber", "general.serialNumber"),
    "lan_ip": ("router.ipv4.IP", "router.gatewayIp", "router.ipAddress", "lan.ipAddress"),
    "wan_ip": ("wwan.IP", "wwan.ipAddr", "wan.IP", "ethernet.wan.IP", "failover.wan.IP"),
    "wan_state": ("wwan.connection", "wwan.connectionText", "wan.state", "failover.state"),
    "carrier": ("wwan.registerNetworkDisplay", "wwan.currentNWserviceType", "custom.carrierName"),
    "network_type": ("wwan.currentPSserviceType", "wwan.currentNWserviceType", "wwan.dataClass"),
    "rssi": ("wwan.signalStrength.rssi", "wwan.signalStrength.rssi0", "signal.rssi"),
    "rsrp": ("wwan.signalStrength.rsrp", "wwan.signalStrength.lteRsrp", "signal.rsrp"),
    "rsrq": ("wwan.signalStrength.rsrq", "wwan.signalStrength.lteRsrq", "signal.rsrq"),
    "sinr": ("wwan.signalStrength.sinr", "wwan.signalStrength.lteSinr", "signal.sinr"),
    "battery_pct": ("power.battChargeLevel", "power.batteryLevel"),
    "uptime_s": ("general.upTime", "wwan.sessDuration", "general.uptime"),
    "rx_bytes": ("wwan.dataTransferredRx", "wwan.dataTransferred.rx", "wwan.dataUsage.generic.rxBytes"),
    "tx_bytes": ("wwan.dataTransferredTx", "wwan.dataTransferred.tx", "wwan.dataUsage.generic.txBytes"),
    "sip_alg": ("router.sipalg.enabled", "router.sipALG", "firewall.sipalg", "router.SIPALG"),
    "bands": ("wwan.band", "wwan.currentBand", "wwan.signalStrength.bars5g"),
    "clients": ("router.clientList", "wifi.clientList", "router.clients", "wifi.clients"),
}

# Write aliases: logical setting -> candidate dotted keys accepted by /Forms/config.
WRITE_ALIASES: dict[str, tuple[str, ...]] = {
    "sip_alg": ("router.sipalg.enabled", "router.sipALG", "firewall.sipalg", "router.SIPALG"),
    "upnp": ("router.upnp.enabled", "upnp.enabled"),
    "dmz_enabled": ("router.dmz.enabled", "firewall.dmz.enabled"),
    "dmz_host": ("router.dmz.ipAddress", "firewall.dmz.host"),
    "port_filter": ("router.portFiltering.enabled", "firewall.portFilter.enabled"),
    "wifi_band": ("wifi.band", "wifi.5ghz.enabled"),
    "wifi_channel_24": ("wifi.24ghz.channel", "wifi.channel"),
    "wifi_channel_5": ("wifi.5ghz.channel", "wifi.channel5g"),
    "wifi_mode_5": ("wifi.5ghz.mode", "wifi.mode5g"),
    "wifi_bandwidth_5": ("wifi.5ghz.bandwidth", "wifi.channelWidth5g"),
    "wifi_power": ("wifi.txPower", "wifi.power"),
    "wmm": ("wifi.wmm.enabled", "wifi.wmm"),
    "band_lock": ("wwan.bandLock", "wwan.band.selection", "wwan.prefNetwork"),
    "network_pref": ("wwan.prefNetwork", "wwan.networkPreference"),
    "mtu": ("wwan.mtu", "router.mtu", "ethernet.wan.mtu"),
    "ethernet_failover": ("failover.autoSwitch", "failover.enabled"),
    "jumbo_frames": ("router.jumboFrame", "ethernet.jumboFrame"),
    "power_saving": ("power.powerSaving", "power.autoSleep"),
    "lan_dhcp_lease": ("router.dhcp.leaseTime", "lan.dhcp.leaseTime"),
    "ipv6_enabled": ("router.ipv6.enabled", "wwan.ipv6.enabled"),
}


def dig(tree: Any, dotted: str) -> Any:
    """Resolve a dotted path inside a nested dict/list structure."""

    node = tree
    for part in dotted.split("."):
        if isinstance(node, dict):
            if part not in node:
                return None
            node = node[part]
        elif isinstance(node, list):
            try:
                node = node[int(part)]
            except (ValueError, IndexError):
                return None
        else:
            return None
    return node


def first_present(tree: Any, paths: tuple[str, ...]) -> Any:
    for path in paths:
        value = dig(tree, path)
        if value not in (None, ""):
            return value
    return None


def _as_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(float(str(value).strip().split()[0]))
    except (ValueError, IndexError):
        return None


def _as_float(value: Any) -> float | None:
    if value is None:
        return None
    try:
        return float(str(value).strip().split()[0])
    except (ValueError, IndexError):
        return None


def _as_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if value is None:
        return None
    text = str(value).strip().lower()
    if text in {"1", "true", "on", "enabled", "yes"}:
        return True
    if text in {"0", "false", "off", "disabled", "no"}:
        return False
    return None


def _form_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


class NighthawkAdmin:
    """Async client for a NETGEAR Nighthawk router's web administrator."""

    def __init__(self, cfg: RouterConfig) -> None:
        self.cfg = cfg
        self._client: httpx.AsyncClient | None = None
        self._token: str = ""
        self._model: dict[str, Any] = {}
        self._authenticated = False
        self._lock = asyncio.Lock()
        # Populated as we learn which alias a given firmware actually accepts.
        self._write_key_cache: dict[str, str] = {}

    # ---------------------------------------------------------------- plumbing

    @property
    def base_url(self) -> str:
        return self.cfg.base_url

    async def _http(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                timeout=httpx.Timeout(self.cfg.timeout_s),
                verify=self.cfg.verify_tls,
                follow_redirects=True,
                headers={
                    "User-Agent": "turbobond/1.0 (router-admin)",
                    "Referer": f"{self.base_url}/index.html",
                    "Origin": self.base_url,
                    "Accept": "application/json, text/javascript, */*; q=0.01",
                    "X-Requested-With": "XMLHttpRequest",
                },
            )
        return self._client

    async def close(self) -> None:
        if self._client is not None and not self._client.is_closed:
            await self._client.aclose()
        self._client = None
        self._authenticated = False

    # ------------------------------------------------------------- model.json

    async def fetch_model(self) -> dict[str, Any]:
        """Pull the router's full state tree."""

        if is_dry_run():
            self._model = _SIMULATED_MODEL
            return self._model

        client = await self._http()
        last_error: Exception | None = None
        for path in MODEL_JSON_PATHS:
            try:
                resp = await client.get(path)
            except httpx.HTTPError as exc:
                last_error = exc
                continue
            if resp.status_code != 200:
                last_error = RouterError(f"GET {path} returned HTTP {resp.status_code}")
                continue
            text = resp.text.strip()
            # Some firmwares wrap the payload in a JS assignment.
            if text.startswith("var "):
                text = text.split("=", 1)[-1].strip().rstrip(";")
            try:
                data = json.loads(text)
            except json.JSONDecodeError as exc:
                last_error = exc
                continue
            if isinstance(data, dict):
                self._model = data
                self._token = self._extract_token(data, resp.text) or self._token
                return data
        raise RouterError(
            f"could not read the router state tree from {self.base_url}: {last_error}",
            remedy=(
                "Confirm the router is reachable at that address and that the app's host is on its LAN. "
                "For a Nighthawk hotspot the default is http://192.168.1.1."
            ),
        )

    def _extract_token(self, model: dict[str, Any], raw_text: str = "") -> str:
        for path in TOKEN_PATHS:
            value = dig(model, path)
            if isinstance(value, str) and value:
                return value
        if raw_text:
            match = _TOKEN_RE.search(raw_text)
            if match:
                return match.group(1)
        return ""

    # ------------------------------------------------------------------- auth

    async def connect(self) -> RouterStatus:
        """Log into the web administrator and return the resulting status."""

        async with self._lock:
            try:
                await self.fetch_model()
            except RouterError as exc:
                return RouterStatus(reachable=False, error=exc.message)

            if not self.cfg.password:
                log.info("no router password configured; continuing in read-only mode")
                status = self._build_status()
                status.reachable = True
                status.authenticated = False
                return status

            ok = await self._login()
            self._authenticated = ok
            if ok:
                await self.fetch_model()
            status = self._build_status()
            status.reachable = True
            status.authenticated = ok
            if not ok:
                status.error = "router rejected the administrator password"
            return status

    async def _login(self) -> bool:
        if is_dry_run():
            return True
        client = await self._http()
        attempts = [
            {"session.password": self.cfg.password, "token": self._token},
            {"session.password": self.cfg.password, "err_redirect": "/index.html", "token": self._token},
            {
                "session.username": self.cfg.username,
                "session.password": self.cfg.password,
                "token": self._token,
            },
        ]
        for payload in attempts:
            payload = {k: v for k, v in payload.items() if v}
            try:
                resp = await client.post(CONFIG_FORM_PATH, data=payload)
            except httpx.HTTPError as exc:
                log.debug("login attempt failed at transport level: %s", exc)
                continue
            if resp.status_code >= 500:
                continue
            if await self._verify_session():
                log.info("authenticated to router web administrator at %s", self.base_url)
                return True
        return False

    async def _verify_session(self) -> bool:
        """A logged-in session exposes the privileged half of model.json."""

        try:
            model = await self.fetch_model()
        except RouterError:
            return False
        for marker in ("session.userRole", "session.loginState", "sess.loginState"):
            value = dig(model, marker)
            if isinstance(value, str) and value.lower() in {"admin", "true", "loggedin", "1"}:
                return True
            if value is True:
                return True
        # Fallback: privileged subtrees only render for an authenticated session.
        return any(dig(model, p) is not None for p in ("wifi.password", "sim.pin", "router.dhcp"))

    def require_auth(self) -> None:
        if not self._authenticated and not is_dry_run():
            raise RouterAuthError(
                "not signed in to the router web administrator",
                remedy="Enter the router admin password on the turbobond sign-in screen.",
            )

    # ---------------------------------------------------------------- reading

    def _build_status(self) -> RouterStatus:
        model = self._model
        bands_raw = first_present(model, FIELD_ALIASES["bands"])
        if isinstance(bands_raw, str):
            bands = [b.strip() for b in re.split(r"[,\s+]+", bands_raw) if b.strip()]
        elif isinstance(bands_raw, list):
            bands = [str(b) for b in bands_raw]
        else:
            bands = []

        return RouterStatus(
            model=str(first_present(model, FIELD_ALIASES["model"]) or ""),
            firmware=str(first_present(model, FIELD_ALIASES["firmware"]) or ""),
            serial=str(first_present(model, FIELD_ALIASES["serial"]) or ""),
            lan_ip=str(first_present(model, FIELD_ALIASES["lan_ip"]) or ""),
            wan_ip=str(first_present(model, FIELD_ALIASES["wan_ip"]) or ""),
            wan_state=str(first_present(model, FIELD_ALIASES["wan_state"]) or ""),
            carrier=str(first_present(model, FIELD_ALIASES["carrier"]) or ""),
            network_type=str(first_present(model, FIELD_ALIASES["network_type"]) or ""),
            bands=bands,
            rssi=_as_int(first_present(model, FIELD_ALIASES["rssi"])),
            rsrp=_as_int(first_present(model, FIELD_ALIASES["rsrp"])),
            rsrq=_as_int(first_present(model, FIELD_ALIASES["rsrq"])),
            sinr=_as_float(first_present(model, FIELD_ALIASES["sinr"])),
            battery_pct=_as_int(first_present(model, FIELD_ALIASES["battery_pct"])),
            uptime_s=_as_int(first_present(model, FIELD_ALIASES["uptime_s"])) or 0,
            rx_bytes=_as_int(first_present(model, FIELD_ALIASES["rx_bytes"])) or 0,
            tx_bytes=_as_int(first_present(model, FIELD_ALIASES["tx_bytes"])) or 0,
            sip_alg_enabled=_as_bool(first_present(model, FIELD_ALIASES["sip_alg"])),
            raw={},
        )

    async def status(self) -> RouterStatus:
        try:
            await self.fetch_model()
        except RouterError as exc:
            return RouterStatus(reachable=False, error=exc.message)
        status = self._build_status()
        status.reachable = True
        status.authenticated = self._authenticated
        return status

    async def devices(self) -> list[ConnectedDevice]:
        """Enumerate attached clients so every one of them can be bonded."""

        try:
            model = await self.fetch_model()
        except RouterError:
            return []
        raw = first_present(model, FIELD_ALIASES["clients"])
        entries: list[dict[str, Any]] = []
        if isinstance(raw, list):
            entries = [e for e in raw if isinstance(e, dict)]
        elif isinstance(raw, dict):
            entries = [e for e in raw.values() if isinstance(e, dict)]

        devices: list[ConnectedDevice] = []
        for entry in entries:
            mac = str(entry.get("mac") or entry.get("macAddress") or entry.get("MAC") or "").lower()
            ip = str(entry.get("ip") or entry.get("ipAddress") or entry.get("IP") or "")
            if not mac and not ip:
                continue
            devices.append(
                ConnectedDevice(
                    mac=mac,
                    ip=ip,
                    name=str(entry.get("name") or entry.get("hostname") or entry.get("deviceName") or ""),
                    connection=str(entry.get("type") or entry.get("connection") or entry.get("media") or ""),
                    rssi=_as_int(entry.get("rssi") or entry.get("signal")),
                    rx_bytes=_as_int(entry.get("rxBytes") or entry.get("rx")) or 0,
                    tx_bytes=_as_int(entry.get("txBytes") or entry.get("tx")) or 0,
                )
            )
        return devices

    # ---------------------------------------------------------------- writing

    async def _post_config(self, values: dict[str, Any]) -> bool:
        if is_dry_run():
            log.info("[dry-run] router set %s", values)
            return True
        client = await self._http()
        payload = {k: _form_value(v) for k, v in values.items()}
        if self._token:
            payload["token"] = self._token
        try:
            resp = await client.post(CONFIG_FORM_PATH, data=payload)
        except httpx.HTTPError as exc:
            log.warning("router write failed: %s", exc)
            return False
        if resp.status_code >= 400:
            log.debug("router rejected %s with HTTP %s", list(values), resp.status_code)
            return False
        # The token rotates after each successful write on some firmwares.
        new_token = self._extract_token({}, resp.text)
        if new_token:
            self._token = new_token
        return True

    async def set_setting(self, logical_name: str, value: Any) -> bool:
        """Write a logical setting, trying each firmware alias until one works."""

        cached = self._write_key_cache.get(logical_name)
        candidates = (cached,) if cached else WRITE_ALIASES.get(logical_name, (logical_name,))
        for key in candidates:
            if not key:
                continue
            if await self._post_config({key: value}) and await self._confirm_written(key, value):
                self._write_key_cache[logical_name] = key
                log.info("router: %s = %s (via %s)", logical_name, value, key)
                return True
        log.warning("router did not accept setting '%s' (tried %s)", logical_name, list(candidates))
        return False

    async def _confirm_written(self, key: str, expected: Any) -> bool:
        """Read the key back. Unreadable keys are treated as accepted."""

        if is_dry_run():
            return True
        try:
            model = await self.fetch_model()
        except RouterError:
            return False
        actual = dig(model, key)
        if actual is None:
            return True
        expected_bool = _as_bool(expected)
        if expected_bool is not None:
            return _as_bool(actual) == expected_bool
        return str(actual).strip().lower() == str(expected).strip().lower()

    async def set_values(self, values: dict[str, Any]) -> dict[str, bool]:
        self.require_auth()
        results: dict[str, bool] = {}
        for name, value in values.items():
            results[name] = await self.set_setting(name, value)
        return results

    async def set_sip_alg(self, enabled: bool) -> bool:
        """Turn the router's SIP ALG on/off.

        Leaving SIP ALG on is the usual cause of failed registrations and one-way
        audio, because it rewrites SDP bodies it does not fully understand.
        """

        self.require_auth()
        current = _as_bool(first_present(self._model, FIELD_ALIASES["sip_alg"]))
        if current is None:
            log.info("router does not expose a SIP ALG toggle; relying on host firewall handling")
            return True
        if current == enabled:
            log.info("router SIP ALG already %s", "on" if enabled else "off")
            return True
        return await self.set_setting("sip_alg", enabled)

    async def apply_optimization(self, profile: dict[str, Any]) -> dict[str, bool]:
        """Push the tuning profile's router-side half."""

        self.require_auth()
        results: dict[str, bool] = {}
        for name, value in profile.items():
            if value is None:
                continue
            results[name] = await self.set_setting(name, value)
        return results

    async def reboot(self) -> bool:
        self.require_auth()
        for key, value in (("general.shutdown", "Reboot"), ("router.reboot", "1"), ("general.reboot", "1")):
            if await self._post_config({key: value}):
                return True
        return False


def build_router_admin(cfg: RouterConfig) -> NighthawkAdmin:
    """Factory. Only the Nighthawk family is implemented today."""

    return NighthawkAdmin(cfg)


# Shape mirrors a real M7 Pro model.json closely enough to exercise every read
# path in dry-run mode and in the test-suite.
_SIMULATED_MODEL: dict[str, Any] = {
    "session": {"secToken": "simulated-token", "userRole": "Admin", "loginState": "loggedin"},
    "general": {
        "model": "MR7400 (Nighthawk M7 Pro)",
        "FWVersion": "NTG9X75C_12.01.20.00",
        "SerialNumber": "SIM000000000",
        "upTime": 12345,
        "deviceName": "Nighthawk-M7Pro",
    },
    "router": {
        "gatewayIp": "192.168.1.1",
        "ipv4": {"IP": "192.168.1.1"},
        "sipalg": {"enabled": True},
        "dhcp": {"leaseTime": 3600},
        "upnp": {"enabled": False},
        "clientList": [
            {"mac": "aa:bb:cc:00:00:01", "ip": "192.168.1.20", "name": "desk-phone", "type": "ethernet"},
            {"mac": "aa:bb:cc:00:00:02", "ip": "192.168.1.21", "name": "laptop", "type": "wifi-5", "rssi": -47},
            {"mac": "aa:bb:cc:00:00:03", "ip": "192.168.1.22", "name": "handset", "type": "wifi-6", "rssi": -55},
        ],
    },
    "wwan": {
        "IP": "100.64.12.34",
        "connection": "Connected",
        "registerNetworkDisplay": "Simulated Carrier",
        "currentPSserviceType": "5G-SA",
        "band": "n41+n77",
        "signalStrength": {"rssi": -62, "rsrp": -88, "rsrq": -11, "sinr": 14.5},
        "dataTransferredRx": 987654321,
        "dataTransferredTx": 123456789,
    },
    "wifi": {"password": "simulated", "5ghz": {"channel": 149, "bandwidth": "80"}},
    "power": {"battChargeLevel": 88},
    "sim": {"status": "Ready", "pin": ""},
}
