"""Policy routing for the bond.

Three things are programmed here:

1. **Per-link tables.** Every uplink gets its own routing table plus a rule that
   forces traffic sourced from that link's address back out that same link.
   Without this, reply packets take the default route and the far end sees an
   asymmetric path (and drops them).

2. **ECMP default route.** A multipath default route weighted by link quality.
   This is per-flow balancing - it does not aggregate a single connection, but
   it works with no concentrator and survives any link going down.

3. **Route switching.** Moving the default route into the bonded tunnel when the
   tunnel is up, and back out to ECMP when it is not.

Everything is idempotent: re-running an activation converges rather than
accumulating duplicate rules.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from turbobond.links.model import Link
from turbobond.logging_setup import get_logger
from turbobond.util.cmd import CommandResult, is_dry_run, run, which

log = get_logger("bond.routing")

# Rule priorities. Lower runs first.
PRIO_LINK_SOURCE = 1000
PRIO_SIP_PIN = 900
PRIO_DIRECT_BYPASS = 800
PRIO_SHADOW_MARK = 850

# Firewall marks used to steer traffic between routes.
MARK_DIRECT = 0x11
MARK_SHADOW = 0x12
MARK_SIP = 0x13
MARK_TUNNEL_BYPASS = 0x14

TABLE_BOND = 100
TABLE_SIP = 101


@dataclass
class RoutingReport:
    tables: dict[str, bool] = field(default_factory=dict)
    rules: list[str] = field(default_factory=list)
    default_route: str = ""
    ecmp_members: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors

    def as_dict(self) -> dict[str, Any]:
        return {
            "tables": self.tables,
            "rules": self.rules,
            "default_route": self.default_route,
            "ecmp_members": self.ecmp_members,
            "errors": self.errors,
            "ok": self.ok,
        }


def _ip(*args: str, quiet: bool = True) -> CommandResult:
    return run(["ip", *args], quiet=quiet, allow_missing=True)


def iproute2_available() -> bool:
    return is_dry_run() or which("ip") is not None


def ensure_rt_tables(links: list[Link], path: str = "/etc/iproute2/rt_tables.d/turbobond.conf") -> bool:
    """Give the numeric tables readable names so `ip route show table x` works."""

    if is_dry_run():
        return True
    lines = ["# Managed by turbobond.", f"{TABLE_BOND} turbobond_bond", f"{TABLE_SIP} turbobond_sip"]
    lines += [f"{link.table_id} turbobond_{link.name}" for link in links if link.table_id]
    try:
        import os

        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fh:
            fh.write("\n".join(lines) + "\n")
        return True
    except OSError as exc:
        # Purely cosmetic; numeric table ids work regardless.
        log.debug("could not write %s: %s", path, exc)
        return False


def program_link_tables(links: list[Link]) -> RoutingReport:
    """One routing table and one source rule per uplink."""

    report = RoutingReport()
    if not iproute2_available():
        report.errors.append("iproute2 ('ip') is not installed")
        return report

    ensure_rt_tables(links)

    for link in links:
        if not link.enabled or not link.table_id:
            continue
        table = str(link.table_id)
        _ip("route", "flush", "table", table)

        if link.gateway:
            _ip("route", "add", "default", "via", link.gateway, "dev", link.interface, "table", table)
        else:
            # Point-to-point / modem links have no next hop address.
            _ip("route", "add", "default", "dev", link.interface, "table", table)

        # The on-link subnet must resolve inside the table too, or the gateway
        # itself is unreachable from it.
        if link.source_ip:
            subnet = _subnet_of(link.source_ip)
            if subnet:
                _ip("route", "add", subnet, "dev", link.interface, "scope", "link", "src", link.source_ip, "table", table)

            _ip("rule", "del", "from", link.source_ip, "table", table, "priority", str(PRIO_LINK_SOURCE))
            result = _ip("rule", "add", "from", link.source_ip, "table", table, "priority", str(PRIO_LINK_SOURCE))
            ok = result.ok or result.skipped
            report.tables[link.name] = ok
            if ok:
                report.rules.append(f"from {link.source_ip} lookup {table}")
            else:
                report.errors.append(f"source rule for {link.name} failed: {result.stderr.strip()}")
        else:
            report.tables[link.name] = False
            report.errors.append(f"{link.name} has no source address yet")

        # Also key off the firewall mark, which is how per-device pinning works.
        mark = hex(0x100 + link.table_id)
        _ip("rule", "del", "fwmark", mark, "table", table, "priority", str(PRIO_LINK_SOURCE + 1))
        _ip("rule", "add", "fwmark", mark, "table", table, "priority", str(PRIO_LINK_SOURCE + 1))

    _ip("route", "flush", "cache")
    log.info("policy routing programmed for %d uplink(s)", len(report.tables))
    return report


def _subnet_of(address: str, prefix: int = 24) -> str:
    import ipaddress

    try:
        network = ipaddress.ip_network(f"{address}/{prefix}", strict=False)
        return str(network)
    except ValueError:
        return ""


def install_ecmp_default(links: list[Link], *, table: int = TABLE_BOND) -> RoutingReport:
    """Weighted multipath default route across every healthy uplink.

    This is the no-concentrator fallback. Each flow is hashed onto one uplink,
    so aggregate throughput scales with concurrent flows even though a single
    connection stays on one link.
    """

    report = RoutingReport()
    if not iproute2_available():
        report.errors.append("iproute2 ('ip') is not installed")
        return report

    usable = [link for link in links if link.usable]
    if not usable:
        report.errors.append("no usable uplink for the default route")
        return report

    total_weight = sum(link.effective_weight() for link in usable) or 1.0
    argv = ["route", "replace", "default", "table", str(table)]
    for link in usable:
        # Kernel nexthop weights are integers in 1..255.
        weight = max(1, min(255, round((link.effective_weight() / total_weight) * 100)))
        argv += ["nexthop"]
        if link.gateway:
            argv += ["via", link.gateway]
        argv += ["dev", link.interface, "weight", str(weight)]
        report.ecmp_members.append(f"{link.name}(w={weight})")

    result = _ip(*argv, quiet=False)
    if not (result.ok or result.skipped):
        # Older kernels reject multipath with a mix of on-link and gateway hops;
        # a single best link still gives a working default route.
        log.warning("multipath default route rejected (%s); falling back to a single uplink", result.stderr.strip())
        best = max(usable, key=lambda link: link.effective_weight())
        single = ["route", "replace", "default", "table", str(table)]
        if best.gateway:
            single += ["via", best.gateway]
        single += ["dev", best.interface]
        fallback = _ip(*single)
        if not (fallback.ok or fallback.skipped):
            report.errors.append(f"default route install failed: {fallback.stderr.strip()}")
            return report
        report.ecmp_members = [f"{best.name}(single)"]

    _ip("rule", "del", "table", str(table), "priority", "32000")
    _ip("rule", "add", "table", str(table), "priority", "32000")
    report.default_route = " ".join(report.ecmp_members)
    _ip("route", "flush", "cache")
    log.info("ECMP default route active: %s", report.default_route)
    return report


def install_tunnel_default(tun_device: str, peer_ip: str, concentrator_host: str, links: list[Link]) -> RoutingReport:
    """Send everything through the bonded tunnel.

    The concentrator's own address must keep taking the physical uplinks, or the
    tunnel would try to carry the packets that build it.
    """

    report = RoutingReport()
    if not iproute2_available():
        report.errors.append("iproute2 ('ip') is not installed")
        return report

    for link in links:
        if not link.usable or not link.table_id:
            continue
        argv = ["route", "replace", f"{concentrator_host}/32"]
        if link.gateway:
            argv += ["via", link.gateway]
        argv += ["dev", link.interface, "table", str(link.table_id)]
        _ip(*argv)

    # Pin the concentrator to the best uplink in the main table as well, so the
    # handshake has somewhere to go before the bond is fully up.
    usable = [link for link in links if link.usable]
    if usable:
        best = max(usable, key=lambda link: link.effective_weight())
        argv = ["route", "replace", f"{concentrator_host}/32"]
        if best.gateway:
            argv += ["via", best.gateway]
        argv += ["dev", best.interface]
        result = _ip(*argv)
        if not (result.ok or result.skipped):
            report.errors.append(f"could not pin the concentrator route: {result.stderr.strip()}")

    result = _ip("route", "replace", "default", "via", peer_ip, "dev", tun_device, "table", str(TABLE_BOND), quiet=False)
    if not (result.ok or result.skipped):
        report.errors.append(f"tunnel default route failed: {result.stderr.strip()}")
        return report

    _ip("rule", "del", "table", str(TABLE_BOND), "priority", "32000")
    _ip("rule", "add", "table", str(TABLE_BOND), "priority", "32000")
    _ip("route", "flush", "cache")
    report.default_route = f"default via {peer_ip} dev {tun_device}"
    log.info("default route now runs through the bonded tunnel (%s)", tun_device)
    return report


def pin_traffic_to_link(link: Link, *, mark: int, priority: int = PRIO_SIP_PIN) -> bool:
    """Force marked traffic onto one specific uplink.

    Used for SIP: a registration that flaps between source addresses gets
    dropped by most SBCs, so signalling stays nailed to a single link even while
    everything else is bonded.
    """

    if not link.table_id:
        return False
    _ip("rule", "del", "fwmark", hex(mark), "table", str(link.table_id), "priority", str(priority))
    result = _ip("rule", "add", "fwmark", hex(mark), "table", str(link.table_id), "priority", str(priority))
    ok = result.ok or result.skipped
    if ok:
        log.info("traffic marked %s pinned to %s", hex(mark), link.name)
    return ok


def add_bypass_routes(cidrs: list[str], links: list[Link]) -> list[str]:
    """Keep these destinations off the tunnel (LAN, RFC1918, SIP peers)."""

    installed: list[str] = []
    usable = [link for link in links if link.usable]
    if not usable:
        return installed
    best = max(usable, key=lambda link: link.effective_weight())
    for cidr in cidrs:
        argv = ["route", "replace", cidr]
        if best.gateway:
            argv += ["via", best.gateway]
        argv += ["dev", best.interface]
        result = _ip(*argv)
        if result.ok or result.skipped:
            installed.append(cidr)
    return installed


def teardown(links: list[Link]) -> None:
    """Remove everything this module installed."""

    if not iproute2_available():
        return
    for link in links:
        if not link.table_id:
            continue
        if link.source_ip:
            _ip("rule", "del", "from", link.source_ip, "table", str(link.table_id), "priority", str(PRIO_LINK_SOURCE))
        _ip("rule", "del", "fwmark", hex(0x100 + link.table_id), "table", str(link.table_id), "priority", str(PRIO_LINK_SOURCE + 1))
        _ip("route", "flush", "table", str(link.table_id))
    for table in (TABLE_BOND, TABLE_SIP):
        _ip("rule", "del", "table", str(table), "priority", "32000")
        _ip("route", "flush", "table", str(table))
    _ip("route", "flush", "cache")
    log.info("policy routing torn down")


def current_state() -> dict[str, Any]:
    """Snapshot of the live routing configuration, for the dashboard."""

    if not iproute2_available():
        return {"available": False}
    rules = run(["ip", "rule", "show"], quiet=True, allow_missing=True)
    bond_table = run(["ip", "route", "show", "table", str(TABLE_BOND)], quiet=True, allow_missing=True)
    main = run(["ip", "route", "show", "default"], quiet=True, allow_missing=True)
    return {
        "available": True,
        "rules": [line.strip() for line in rules.stdout.splitlines() if line.strip()],
        "bond_table": [line.strip() for line in bond_table.stdout.splitlines() if line.strip()],
        "main_default": [line.strip() for line in main.stdout.splitlines() if line.strip()],
    }
