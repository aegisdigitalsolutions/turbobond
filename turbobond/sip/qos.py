"""Queue shaping so voice is never stuck behind a bulk transfer.

Marking packets EF is only half the job: something has to act on the mark. This
installs a three-band priority qdisc on each uplink, puts DSCP-EF media in the
top band, signalling in the middle, and everything else in the bottom band.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from turbobond.config import SipConfig
from turbobond.logging_setup import get_logger
from turbobond.util.cmd import is_dry_run, run, which

log = get_logger("sip.qos")

# prio band 0 = highest.
BAND_MEDIA = 0
BAND_SIGNALLING = 1
BAND_BULK = 2


@dataclass
class QosReport:
    interfaces: dict[str, bool] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return bool(self.interfaces) and all(self.interfaces.values())

    def as_dict(self) -> dict[str, Any]:
        return {"interfaces": self.interfaces, "errors": self.errors, "ok": self.ok}


def _tc(*args: str) -> bool:
    result = run(["tc", *args], quiet=True, allow_missing=True)
    return result.ok or result.skipped


def apply_sip_qos(interfaces: list[str], cfg: SipConfig) -> QosReport:
    """Install the priority queue on every uplink."""

    report = QosReport()
    if not interfaces:
        return report
    if which("tc") is None and not is_dry_run():
        report.errors.append("tc (iproute2) is not installed, so voice prioritisation was skipped")
        log.info(report.errors[-1])
        return report

    for iface in interfaces:
        # Replace whatever is there; prio is cheap and always available.
        ok = _tc("qdisc", "replace", "dev", iface, "root", "handle", "1:", "prio", "bands", "3")
        if not ok:
            report.interfaces[iface] = False
            report.errors.append(f"could not install the priority qdisc on {iface}")
            continue

        # Match on the DSCP bits in the IPv4 TOS byte. DSCP occupies the top six
        # bits, so the value is shifted left by two and masked with 0xfc.
        media_tos = f"0x{cfg.dscp_media << 2:02x}"
        signalling_tos = f"0x{cfg.dscp_signalling << 2:02x}"
        _tc(
            "filter", "add", "dev", iface, "parent", "1:", "protocol", "ip", "prio", "1",
            "u32", "match", "ip", "tos", media_tos, "0xfc", "flowid", f"1:{BAND_MEDIA + 1}",
        )
        _tc(
            "filter", "add", "dev", iface, "parent", "1:", "protocol", "ip", "prio", "2",
            "u32", "match", "ip", "tos", signalling_tos, "0xfc", "flowid", f"1:{BAND_SIGNALLING + 1}",
        )
        # RTP arriving without a usable DSCP mark still gets priority by port.
        _tc(
            "filter", "add", "dev", iface, "parent", "1:", "protocol", "ip", "prio", "3",
            "u32", "match", "ip", "protocol", "17", "0xff",
            "match", "ip", "dport", str(cfg.rtp_port_start), "0xc000",
            "flowid", f"1:{BAND_MEDIA + 1}",
        )
        report.interfaces[iface] = True
        log.info("voice prioritisation active on %s", iface)

    return report


def teardown_qos(interfaces: list[str]) -> None:
    for iface in interfaces:
        _tc("qdisc", "del", "dev", iface, "root")
    log.info("voice prioritisation removed")


def qos_state(interfaces: list[str]) -> dict[str, str]:
    state: dict[str, str] = {}
    for iface in interfaces:
        result = run(["tc", "qdisc", "show", "dev", iface], quiet=True, allow_missing=True)
        state[iface] = result.stdout.strip().splitlines()[0] if result.stdout.strip() else "unknown"
    return state
