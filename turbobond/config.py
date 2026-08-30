"""Configuration model and on-disk persistence.

Everything the operator could conceivably need to tune lives here, but every field
has a working default so a fresh install activates with an empty config file.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator

from turbobond.errors import ConfigError

DEFAULT_CONFIG_DIR = Path(os.environ.get("TURBOBOND_CONFIG_DIR", "/etc/turbobond"))
DEFAULT_STATE_DIR = Path(os.environ.get("TURBOBOND_STATE_DIR", "/var/lib/turbobond"))
DEFAULT_RUN_DIR = Path(os.environ.get("TURBOBOND_RUN_DIR", "/run/turbobond"))
CONFIG_FILENAME = "turbobond.yaml"

RouteName = Literal["direct", "shadow"]


class RouterConfig(BaseModel):
    """Credentials and behaviour for the router web administrator session."""

    model: str = "nighthawk-m7pro"
    host: str = "192.168.1.1"
    scheme: Literal["http", "https"] = "http"
    password: str = ""
    username: str = "admin"
    verify_tls: bool = False
    timeout_s: float = 12.0
    # The app drives the router itself; set to False only for read-only diagnostics.
    manage: bool = True
    # Optional secondary admin surfaces (e.g. an upstream ISP ONT or a second modem).
    additional_hosts: list[str] = Field(default_factory=list)

    @field_validator("host")
    @classmethod
    def _strip_host(cls, value: str) -> str:
        value = value.strip().rstrip("/")
        for prefix in ("http://", "https://"):
            if value.startswith(prefix):
                value = value[len(prefix) :]
        if not value:
            raise ValueError("router host must not be empty")
        return value

    @property
    def base_url(self) -> str:
        return f"{self.scheme}://{self.host}"


class OptimizationConfig(BaseModel):
    """The 'wrt-turbo-search' tuning profile.

    `turbo` raises throughput ceilings (buffers, congestion control, offloads, MTU).
    `search` continuously probes bands/channels/paths and re-pins the best ones.
    """

    profile: str = "wrt-turbo-search"
    turbo: bool = True
    search: bool = True
    # Interval between active re-optimization sweeps.
    search_interval_s: float = 180.0
    congestion_control: str = "bbr"
    qdisc: str = "fq"
    # 0 = leave the interface MTU alone; otherwise clamp to this value.
    wan_mtu: int = 0
    tcp_rmem: tuple[int, int, int] = (4096, 262144, 33554432)
    tcp_wmem: tuple[int, int, int] = (4096, 262144, 33554432)
    # Clamp TCP MSS to the tunnel path MTU so bonded flows never blackhole.
    clamp_mss: bool = True
    prefer_5ghz: bool = True
    band_search: bool = True

    @field_validator("wan_mtu")
    @classmethod
    def _check_mtu(cls, value: int) -> int:
        if value and not (576 <= value <= 9216):
            raise ValueError("wan_mtu must be 0 (auto) or between 576 and 9216")
        return value


class LinkConfig(BaseModel):
    """A single WAN uplink participating in the bond."""

    name: str
    interface: str
    # Blank means "learn it from the routing table / DHCP".
    gateway: str = ""
    weight: float = 1.0
    # Measured/limited capacity in megabits per second; 0 means auto-measure.
    uplink_mbps: float = 0.0
    downlink_mbps: float = 0.0
    metered: bool = False
    enabled: bool = True
    # Routing table id used for this link's dedicated policy-routing table.
    table_id: int = 0

    @field_validator("weight")
    @classmethod
    def _positive_weight(cls, value: float) -> float:
        if value <= 0:
            raise ValueError("link weight must be > 0")
        return value


class ConcentratorConfig(BaseModel):
    """Remote endpoint that re-assembles the bonded packet stream.

    Packet-level aggregation of several uplinks into one logical pipe is only
    possible with a peer on the far side; without it turbobond falls back to
    per-flow balancing plus MPTCP, which is configured automatically.
    """

    enabled: bool = False
    host: str = ""
    port: int = 5310
    # 32-byte key, hex encoded. Generated on first activation if left blank.
    psk_hex: str = ""
    tunnel_ip_local: str = "10.77.0.2/30"
    tunnel_ip_remote: str = "10.77.0.1"
    tunnel_mtu: int = 1380
    tun_device: str = "tbond0"
    keepalive_s: float = 1.0
    # Packets are held at most this long while waiting for an earlier sequence.
    reorder_timeout_ms: float = 90.0
    reorder_capacity: int = 2048
    # Duplicate small/latency-critical packets (SIP signalling) across all links.
    duplicate_critical: bool = True

    @model_validator(mode="after")
    def _require_host(self) -> ConcentratorConfig:
        if self.enabled and not self.host:
            raise ValueError("concentrator.host is required when concentrator.enabled is true")
        return self

    def ensure_psk(self) -> str:
        if not self.psk_hex:
            self.psk_hex = secrets.token_hex(32)
        return self.psk_hex


class ShadowsocksConfig(BaseModel):
    """Upstream shadowsocks server used by the `shadow` route."""

    enabled: bool = True
    host: str = ""
    port: int = 8388
    password: str = ""
    method: str = "2022-blake3-aes-256-gcm"
    # Local SOCKS5 + transparent redirect listeners created by the app.
    local_socks_port: int = 1080
    local_http_port: int = 1081
    local_redir_port: int = 1082
    local_dns_port: int = 1053
    plugin: str = ""
    plugin_opts: str = ""
    timeout_s: int = 300
    fast_open: bool = True
    udp_relay: bool = True

    @model_validator(mode="after")
    def _needs_endpoint(self) -> ShadowsocksConfig:
        if self.enabled and self.host and not self.password:
            raise ValueError("shadowsocks.password is required when a host is configured")
        return self

    @property
    def usable(self) -> bool:
        return bool(self.enabled and self.host and self.password)


class RoutePolicy(BaseModel):
    """How traffic is split between the two available routes."""

    default_route: RouteName = "direct"
    # Destinations/CIDRs/ports that must always take the shadow route.
    shadow_domains: list[str] = Field(default_factory=list)
    shadow_cidrs: list[str] = Field(default_factory=list)
    # Traffic that must never be tunnelled (SIP peers, LAN, RFC1918).
    direct_cidrs: list[str] = Field(
        default_factory=lambda: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"]
    )
    # Fail over to the other route when the active one is unhealthy.
    auto_failover: bool = True
    failover_after_failures: int = 3
    probe_interval_s: float = 5.0
    probe_targets: list[str] = Field(default_factory=lambda: ["1.1.1.1", "8.8.8.8", "9.9.9.9"])


class SipConfig(BaseModel):
    """SIP/RTP handling.

    `wide_open` accepts SIP signalling and the RTP media range unconditionally in
    both directions and skips connection tracking for them, which is what VoIP
    endpoints behind carrier-grade NAT need to register and stay registered.
    """

    enabled: bool = True
    wide_open: bool = True
    signalling_ports: list[int] = Field(default_factory=lambda: [5060, 5061, 5062, 5080, 5090])
    tls_ports: list[int] = Field(default_factory=lambda: [5061])
    rtp_port_start: int = 10000
    rtp_port_end: int = 65535
    # SIP ALG mangles SDP bodies and is the single most common cause of one-way
    # audio; the app turns it off on the router and in conntrack.
    disable_alg: bool = True
    disable_conntrack_helper: bool = True
    # DSCP marks: EF (46) for media, CS3 (24) for signalling.
    dscp_media: int = 46
    dscp_signalling: int = 24
    # SIP is pinned to a single uplink so the far end never sees a source flap.
    pin_to_link: str = ""
    # Keep NAT bindings alive so inbound INVITEs are not dropped.
    keepalive_s: float = 25.0

    @model_validator(mode="after")
    def _validate_ports(self) -> SipConfig:
        if not (1 <= self.rtp_port_start <= self.rtp_port_end <= 65535):
            raise ValueError("invalid RTP port range")
        for port in [*self.signalling_ports, *self.tls_ports]:
            if not 1 <= port <= 65535:
                raise ValueError(f"invalid SIP port {port}")
        return self


class LanConfig(BaseModel):
    """Turns the host into the bonded gateway for every device on the LAN."""

    enabled: bool = True
    interface: str = ""
    # Advertise ourselves as the default gateway so clients need zero setup.
    take_over_gateway: bool = True
    nat: bool = True
    ipv4_forward: bool = True
    ipv6_forward: bool = True
    # Per-device route assignment: device MAC/IP -> "direct" | "shadow".
    device_routes: dict[str, RouteName] = Field(default_factory=dict)
    # DNS the app serves to clients (goes through the active route).
    dns_servers: list[str] = Field(default_factory=lambda: ["1.1.1.1", "8.8.8.8"])
    dhcp_lease_s: int = 3600


class AuthConfig(BaseModel):
    """Sign-in for the app itself. This is the only thing a user ever touches."""

    username: str = "admin"
    # Argon2id hash; populated on first sign-in (first credentials win).
    password_hash: str = ""
    session_secret: str = ""
    session_ttl_s: int = 86400
    # Bind to the LAN by default; the app is a privileged control plane.
    bind_host: str = "0.0.0.0"
    bind_port: int = 8088

    def ensure_secret(self) -> str:
        if not self.session_secret:
            self.session_secret = secrets.token_urlsafe(48)
        return self.session_secret


class AppConfig(BaseModel):
    """Root configuration object."""

    version: int = 1
    log_level: str = "INFO"
    # When true nothing touches the system; every command is logged instead.
    dry_run: bool = False
    # Activate the whole stack as soon as the user signs in.
    auto_activate_on_login: bool = True
    auth: AuthConfig = Field(default_factory=AuthConfig)
    router: RouterConfig = Field(default_factory=RouterConfig)
    optimization: OptimizationConfig = Field(default_factory=OptimizationConfig)
    links: list[LinkConfig] = Field(default_factory=list)
    # Empty list means "discover every usable uplink automatically".
    auto_discover_links: bool = True
    concentrator: ConcentratorConfig = Field(default_factory=ConcentratorConfig)
    shadowsocks: ShadowsocksConfig = Field(default_factory=ShadowsocksConfig)
    routes: RoutePolicy = Field(default_factory=RoutePolicy)
    sip: SipConfig = Field(default_factory=SipConfig)
    lan: LanConfig = Field(default_factory=LanConfig)

    config_dir: Path = DEFAULT_CONFIG_DIR
    state_dir: Path = DEFAULT_STATE_DIR
    run_dir: Path = DEFAULT_RUN_DIR

    @property
    def config_path(self) -> Path:
        return self.config_dir / CONFIG_FILENAME

    def enabled_links(self) -> list[LinkConfig]:
        return [link for link in self.links if link.enabled]

    def available_routes(self) -> list[RouteName]:
        """Always two routes: plain bonded, and bonded through shadowsocks."""

        routes: list[RouteName] = ["direct"]
        if self.shadowsocks.enabled:
            routes.append("shadow")
        return routes

    def assign_table_ids(self, base: int = 200) -> None:
        """Give every link a stable, unique policy-routing table id."""

        used = {link.table_id for link in self.links if link.table_id}
        next_id = base
        for link in self.links:
            if link.table_id:
                continue
            while next_id in used:
                next_id += 1
            link.table_id = next_id
            used.add(next_id)
            next_id += 1

    def redacted(self) -> dict[str, Any]:
        """Config safe to hand to the UI."""

        data = self.model_dump(mode="json")
        for path in (
            ("auth", "password_hash"),
            ("auth", "session_secret"),
            ("router", "password"),
            ("shadowsocks", "password"),
            ("concentrator", "psk_hex"),
        ):
            node = data
            for key in path[:-1]:
                node = node.get(key, {})
            if node.get(path[-1]):
                node[path[-1]] = "********"
        return data


def default_config_path(config_dir: Path | None = None) -> Path:
    return (config_dir or DEFAULT_CONFIG_DIR) / CONFIG_FILENAME


def load_config(path: Path | None = None) -> AppConfig:
    """Read the YAML config, returning defaults when the file does not exist."""

    path = Path(path) if path else default_config_path()
    if not path.exists():
        cfg = AppConfig(config_dir=path.parent)
        cfg.assign_table_ids()
        return cfg
    try:
        raw = yaml.safe_load(path.read_text()) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(
            f"{path} is not valid YAML: {exc}",
            remedy="Fix the indentation/quoting, or delete the file to regenerate defaults.",
        ) from exc
    if not isinstance(raw, dict):
        raise ConfigError(f"{path} must contain a YAML mapping at the top level")
    raw.setdefault("config_dir", str(path.parent))
    try:
        cfg = AppConfig.model_validate(raw)
    except Exception as exc:
        raise ConfigError(f"invalid configuration in {path}: {exc}") from exc
    cfg.assign_table_ids()
    return cfg


def save_config(cfg: AppConfig, path: Path | None = None) -> Path:
    """Atomically persist the config with owner-only permissions."""

    path = Path(path) if path else cfg.config_path
    path.parent.mkdir(parents=True, exist_ok=True)
    data = cfg.model_dump(mode="json", exclude={"config_dir", "state_dir", "run_dir"})
    tmp = path.with_suffix(".tmp")
    tmp.write_text(yaml.safe_dump(data, sort_keys=False, default_flow_style=False))
    os.chmod(tmp, 0o600)
    tmp.replace(path)
    return path
