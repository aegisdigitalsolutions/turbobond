"""Makes every device on the LAN use the bond without touching the device.

Three pieces:

1. **Forwarding and NAT** so LAN traffic can leave through the bond at all.
2. **Transparent redirection** of LAN traffic that should take the shadow route
   into the local shadowsocks redirect listener. Devices keep pointing at the
   gateway; the gateway decides which route each one takes.
3. **Per-device marks** so an individual phone or laptop can be pinned to a
   route without any client-side configuration.

The result is that a device only has to obtain a DHCP lease from this gateway.
Everything else - bonding, route selection, voice prioritisation - happens here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from turbobond.config import LanConfig, RoutePolicy, ShadowsocksConfig, SipConfig
from turbobond.logging_setup import get_logger
from turbobond.util.cmd import is_dry_run, run, which

log = get_logger("lan.gateway")

NFT_TABLE = "turbobond_lan"

# Marks matching the ones policy routing looks for.
MARK_SHADOW = 0x12
MARK_SIP = 0x13


@dataclass
class GatewayReport:
    forwarding: bool = False
    nat: bool = False
    transparent_proxy: bool = False
    lan_interface: str = ""
    egress_interfaces: list[str] = field(default_factory=list)
    device_rules: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.forwarding and not self.errors

    def as_dict(self) -> dict[str, Any]:
        return {
            "forwarding": self.forwarding,
            "nat": self.nat,
            "transparent_proxy": self.transparent_proxy,
            "lan_interface": self.lan_interface,
            "egress_interfaces": self.egress_interfaces,
            "device_rules": self.device_rules,
            "errors": self.errors,
            "ok": self.ok,
        }


def detect_lan_interface(exclude: list[str]) -> str:
    """Guess the LAN side: an up interface with an address that is not an uplink."""

    if is_dry_run():
        return "br-lan"
    import os

    excluded = set(exclude)
    candidates: list[str] = []
    try:
        names = sorted(os.listdir("/sys/class/net"))
    except OSError:
        return ""
    for name in names:
        if name == "lo" or name in excluded or name.startswith(("tbond", "tun", "docker", "veth")):
            continue
        try:
            with open(f"/sys/class/net/{name}/operstate") as fh:
                if fh.read().strip() not in ("up", "unknown"):
                    continue
        except OSError:
            continue
        candidates.append(name)

    # A bridge is almost always the LAN side on a gateway box.
    for name in candidates:
        if name.startswith(("br", "lan")):
            return name
    return candidates[0] if candidates else ""


class LanGateway:
    """Programs forwarding, NAT and per-device route steering."""

    def __init__(
        self,
        cfg: LanConfig,
        routes: RoutePolicy,
        shadowsocks: ShadowsocksConfig,
        sip: SipConfig,
        *,
        egress_interfaces: list[str] | None = None,
        tunnel_interface: str = "",
    ) -> None:
        self.cfg = cfg
        self.routes = routes
        self.shadowsocks = shadowsocks
        self.sip = sip
        self.egress_interfaces = egress_interfaces or []
        self.tunnel_interface = tunnel_interface
        self.lan_interface = cfg.interface or detect_lan_interface(self.egress_interfaces)
        self.last_report = GatewayReport()

    @property
    def backend(self) -> str:
        if is_dry_run() or which("nft"):
            return "nftables"
        if which("iptables"):
            return "iptables"
        return "none"

    # ----------------------------------------------------------- ip forwarding

    def enable_forwarding(self) -> bool:
        ok = True
        if self.cfg.ipv4_forward:
            result = run(["sysctl", "-w", "net.ipv4.ip_forward=1"], quiet=True, allow_missing=True)
            ok = ok and (result.ok or result.skipped)
        if self.cfg.ipv6_forward:
            run(["sysctl", "-w", "net.ipv6.conf.all.forwarding=1"], quiet=True, allow_missing=True)
        # Devices reach the internet through several source addresses; strict
        # reverse-path filtering would drop the asymmetric replies.
        for knob in ("net.ipv4.conf.all.rp_filter", "net.ipv4.conf.default.rp_filter"):
            run(["sysctl", "-w", f"{knob}=2"], quiet=True, allow_missing=True)
        return ok

    # ------------------------------------------------------------------ rules

    def build_nft_ruleset(self, *, active_route: str) -> str:
        """NAT plus route steering for LAN clients."""

        lan = self.lan_interface
        egress = self.egress_interfaces or []
        redir_port = self.shadowsocks.local_redir_port
        lines = [
            f"table inet {NFT_TABLE} {{",
            "",
            "  # Devices explicitly pinned to the shadow route.",
            "  set shadow_devices {",
            "    type ipv4_addr",
            "    flags interval",
            "  }",
            "",
            "  set direct_networks {",
            "    type ipv4_addr",
            "    flags interval",
        ]
        direct = [c for c in self.routes.direct_cidrs if c]
        if direct:
            lines.append("    elements = { " + ", ".join(direct) + " }")
        lines += [
            "  }",
            "",
            "  chain forward {",
            "    type filter hook forward priority filter; policy accept;",
            "    # The tunnel MTU is below the LAN MTU, so clamp MSS or large",
            "    # transfers through the bond stall instead of failing cleanly.",
            "    tcp flags syn tcp option maxseg size set rt mtu",
            "    ct state established,related accept",
            "  }",
            "",
            "  chain postrouting {",
            "    type nat hook postrouting priority srcnat; policy accept;",
        ]
        if self.cfg.nat:
            if self.tunnel_interface:
                lines.append(f"    oifname \"{self.tunnel_interface}\" masquerade")
            for iface in egress:
                lines.append(f"    oifname \"{iface}\" masquerade")
            if not egress and not self.tunnel_interface:
                lines.append("    masquerade")
        lines += ["  }", ""]

        if self.shadowsocks.usable and lan:
            lines += [
                "  # Transparent redirection into the local shadowsocks listener.",
                "  # LAN devices keep their default gateway; the decision is made here.",
                "  chain prerouting_redirect {",
                "    type nat hook prerouting priority dstnat; policy accept;",
                f"    iifname \"{lan}\" ip daddr @direct_networks return",
            ]
            for port in sorted(set(self.sip.signalling_ports) | set(self.sip.tls_ports)):
                lines.append(f"    udp dport {port} return")
                lines.append(f"    tcp dport {port} return")
            lines.append(
                f"    udp dport {self.sip.rtp_port_start}-{self.sip.rtp_port_end} return"
            )
            if active_route == "shadow":
                lines.append(f"    iifname \"{lan}\" meta l4proto tcp redirect to :{redir_port}")
            lines.append(f"    iifname \"{lan}\" ip saddr @shadow_devices meta l4proto tcp redirect to :{redir_port}")
            lines += ["  }", ""]

        lines += [
            "  chain mark_devices {",
            "    type filter hook prerouting priority mangle; policy accept;",
            f"    udp dport {self.sip.rtp_port_start}-{self.sip.rtp_port_end} meta mark set {hex(MARK_SIP)}",
        ]
        for port in sorted(set(self.sip.signalling_ports) | set(self.sip.tls_ports)):
            lines.append(f"    udp dport {port} meta mark set {hex(MARK_SIP)}")
            lines.append(f"    tcp dport {port} meta mark set {hex(MARK_SIP)}")
        lines.append(f"    ip saddr @shadow_devices meta mark set {hex(MARK_SHADOW)}")
        lines += ["  }", "}", ""]
        return "\n".join(lines)

    def apply(self, *, active_route: str = "direct") -> GatewayReport:
        report = GatewayReport(lan_interface=self.lan_interface, egress_interfaces=list(self.egress_interfaces))
        if not self.cfg.enabled:
            report.errors.append("LAN gateway mode is disabled in the configuration")
            self.last_report = report
            return report

        report.forwarding = self.enable_forwarding()
        if not self.lan_interface:
            report.errors.append(
                "could not identify the LAN interface; set lan.interface if the gateway has an unusual layout"
            )

        backend = self.backend
        if backend == "nftables":
            run(["nft", "delete", "table", "inet", NFT_TABLE], quiet=True, allow_missing=True)
            ruleset = self.build_nft_ruleset(active_route=active_route)
            result = run(["nft", "-f", "-"], input_text=ruleset, timeout=20, allow_missing=True)
            if result.ok or result.skipped:
                report.nat = self.cfg.nat
                report.transparent_proxy = self.shadowsocks.usable
            else:
                report.errors.append(f"LAN ruleset rejected: {result.stderr.strip()}")
        elif backend == "iptables":
            report.nat = self._apply_iptables(active_route)
            report.transparent_proxy = self.shadowsocks.usable
        else:
            report.errors.append("neither nft nor iptables is installed, so LAN NAT was not configured")

        report.device_rules = self.apply_device_routes()
        self.last_report = report
        if report.ok:
            log.info(
                "LAN gateway active on %s: every attached device now egresses through the bond",
                self.lan_interface or "auto",
            )
        return report

    def _apply_iptables(self, active_route: str) -> bool:
        ok = False
        targets = [*self.egress_interfaces]
        if self.tunnel_interface:
            targets.insert(0, self.tunnel_interface)
        for iface in targets:
            check = run(
                ["iptables", "-t", "nat", "-C", "POSTROUTING", "-o", iface, "-j", "MASQUERADE"],
                quiet=True,
                allow_missing=True,
            )
            if not check.ok:
                result = run(
                    ["iptables", "-t", "nat", "-A", "POSTROUTING", "-o", iface, "-j", "MASQUERADE"],
                    quiet=True,
                    allow_missing=True,
                )
                ok = ok or result.ok or result.skipped
            else:
                ok = True
        run(
            ["iptables", "-t", "mangle", "-A", "FORWARD", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
             "-j", "TCPMSS", "--clamp-mss-to-pmtu"],
            quiet=True,
            allow_missing=True,
        )
        if self.shadowsocks.usable and self.lan_interface and active_route == "shadow":
            run(
                ["iptables", "-t", "nat", "-A", "PREROUTING", "-i", self.lan_interface, "-p", "tcp",
                 "-j", "REDIRECT", "--to-ports", str(self.shadowsocks.local_redir_port)],
                quiet=True,
                allow_missing=True,
            )
        return ok

    # ---------------------------------------------------------- device routing

    def apply_device_routes(self) -> int:
        """Push per-device route pins into the nftables set."""

        shadow_ips = [ip for ip, route in self.cfg.device_routes.items() if route == "shadow" and _looks_like_ip(ip)]
        if self.backend != "nftables":
            return 0
        run(["nft", "flush", "set", "inet", NFT_TABLE, "shadow_devices"], quiet=True, allow_missing=True)
        if not shadow_ips:
            return 0
        elements = "{ " + ", ".join(shadow_ips) + " }"
        result = run(
            ["nft", "add", "element", "inet", NFT_TABLE, "shadow_devices", elements],
            quiet=True,
            allow_missing=True,
        )
        if result.ok or result.skipped:
            log.info("%d device(s) pinned to the shadow route", len(shadow_ips))
            return len(shadow_ips)
        return 0

    def set_device_route(self, address: str, route: str) -> bool:
        if route not in ("direct", "shadow"):
            return False
        self.cfg.device_routes[address] = route  # type: ignore[assignment]
        self.apply_device_routes()
        return True

    def switch_route(self, active_route: str) -> bool:
        """Re-point LAN traffic when the selector changes routes."""

        report = self.apply(active_route=active_route)
        return report.ok

    def teardown(self) -> None:
        if self.backend == "nftables":
            run(["nft", "delete", "table", "inet", NFT_TABLE], quiet=True, allow_missing=True)
        log.info("LAN gateway rules removed")

    def snapshot(self) -> dict[str, Any]:
        return {
            "enabled": self.cfg.enabled,
            "backend": self.backend,
            "lan_interface": self.lan_interface,
            "egress_interfaces": self.egress_interfaces,
            "tunnel_interface": self.tunnel_interface,
            "nat": self.cfg.nat,
            "device_routes": dict(self.cfg.device_routes),
            "report": self.last_report.as_dict(),
        }


def _looks_like_ip(value: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False
