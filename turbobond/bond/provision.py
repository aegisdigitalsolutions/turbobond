"""Everything needed to stand a concentrator up on a host.

The concentrator is installed two ways: from the bundle the dashboard builds
once a gateway exists, and from ``packaging/concentrator-install.sh`` on a bare
VPS before there is a gateway to build anything. Both paths have to produce the
same tuning, the same unit and the same pairing details, so the content lives
here once rather than in a shell script and a string template that drift apart.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

#: Everything the server half imports. The web app's dependencies are not among
#: them, so the concentrator host does not have to carry them.
CONCENTRATOR_REQUIREMENTS = ("cryptography>=42", "pydantic>=2.6", "PyYAML>=6")

SYSCTL_PATH = Path("/etc/sysctl.d/99-turbobond-concentrator.conf")
UNIT_PATH = Path("/etc/systemd/system/turbobond-concentrator.service")
SERVER_BIN = "/usr/local/bin/turbobond-server"

# The concentrator terminates every uplink at once and NATs the client's whole
# LAN, so the defaults are sized well below what it has to absorb. Written as a
# drop-in so it survives reboots and applies before the service starts.
SYSCTL_DROP_IN = """# Forward the tunnel's traffic out to the internet.
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
net.ipv6.conf.default.forwarding = 1

# Socket buffers sized to match the client's, so neither end caps the window.
net.core.rmem_max = 33554432
net.core.wmem_max = 33554432
net.ipv4.tcp_rmem = 4096 262144 33554432
net.ipv4.tcp_wmem = 4096 262144 33554432

# Every uplink delivers into one NIC queue here, so the backlog has to be deep
# enough that reassembly is never what drops a packet.
net.core.netdev_max_backlog = 10000
net.core.somaxconn = 4096

# BBR on this side is what sets download throughput: return traffic is paced
# from here, across all of the client's links.
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# Recycle TIME_WAIT quickly and keep long-lived streams from re-entering slow
# start every time they idle - which voice does constantly.
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_mtu_probing = 1

# NAT for a whole LAN behind the bond needs a far bigger table than the default.
net.netfilter.nf_conntrack_max = 262144
"""


@dataclass(frozen=True)
class ConcentratorSettings:
    """The handful of values both ends of the bond have to agree on."""

    psk: str
    port: int = 5310
    server_ip: str = "10.77.0.1"
    peer_ip: str = "10.77.0.2"
    mtu: int = 1380
    reorder_ms: float = 90.0

    def unit_text(self) -> str:
        return f"""[Unit]
Description=turbobond bonding concentrator
Documentation=https://github.com/aegisdigitalsolutions/turbobond
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment=TURBOBOND_PSK={self.psk}
ExecStart={SERVER_BIN} \\
    --listen 0.0.0.0:{self.port} \\
    --local-cidr {self.server_ip}/30 \\
    --peer-ip {self.peer_ip} \\
    --mtu {self.mtu} \\
    --reorder-ms {self.reorder_ms}
Restart=always
RestartSec=3
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
LimitNOFILE=131072

[Install]
WantedBy=multi-user.target
"""


def pairing_summary(settings: ConcentratorSettings, public_ip: str) -> str:
    """What to type into the gateway's sign-in screen to reach this host.

    The pre-shared key is the whole of the trust between the two ends, so it is
    printed once, here, rather than left for someone to go digging out of a
    unit file over SSH.
    """

    host = public_ip or "<this server's public IP>"
    return f"""
    ------------------------------------------------------------------
    Pair your gateway with this server using these three values:

        Concentrator host : {host}
        Concentrator port : {settings.port}
        Pre-shared key    : {settings.psk}

    Enter them on the gateway's sign-in screen, under "Concentrator".
    Anyone holding that key can open a bonded session here, so send it
    to yourself over something private.
    ------------------------------------------------------------------
"""


def detect_public_ip() -> str:
    """Best guess at the address a client would dial, from local state only.

    Deliberately does not call out to an echo service: this runs as root during
    install, and a silent outbound request to a third party is not something an
    installer should do without being asked.
    """

    ip = shutil.which("ip")
    if not ip:
        return ""
    out = _run([ip, "-4", "route", "get", "1.1.1.1"]).stdout.split()
    if "src" in out:
        return out[out.index("src") + 1]
    return ""


def open_firewall(port: int) -> str:
    """Allow the bonded session in through whatever local firewall is running.

    Returns a note about what still needs doing by hand. A cloud firewall sits
    outside the guest and cannot be opened from in here, which is the single
    most common reason a bond comes up and then carries nothing.
    """

    ufw = shutil.which("ufw")
    if ufw and "inactive" not in _run([ufw, "status"]).stdout:
        _run([ufw, "allow", f"{port}/udp"])
        return f"opened UDP {port} in ufw"

    firewall_cmd = shutil.which("firewall-cmd")
    if firewall_cmd:
        _run([firewall_cmd, "--permanent", f"--add-port={port}/udp"])
        _run([firewall_cmd, "--reload"])
        return f"opened UDP {port} in firewalld"

    return f"no local firewall found; UDP {port} was already reachable"


def _run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    """Run a command, treating a missing binary as an ordinary failure.

    Minimal images ship without modprobe or sysctl. That is worth reporting but
    is not a reason to abandon the steps that follow, which is what an
    uncaught OSError from here would cause.
    """

    try:
        return subprocess.run(cmd, capture_output=True, text=True, check=False)  # noqa: S603
    except (OSError, subprocess.SubprocessError) as exc:
        return subprocess.CompletedProcess(cmd, returncode=127, stdout="", stderr=str(exc))


def provision_host(settings: ConcentratorSettings) -> list[str]:
    """Write the tuning and the unit, then start the service.

    Returns a line per step for the installer to print. Steps that a container
    or an unprivileged shell cannot do are reported rather than raised: a host
    without systemd can still run the server by hand, and saying so is more
    use than an exception.
    """

    steps: list[str] = []

    try:
        SYSCTL_PATH.parent.mkdir(parents=True, exist_ok=True)
        SYSCTL_PATH.write_text(SYSCTL_DROP_IN)
        steps.append(f"wrote kernel tuning to {SYSCTL_PATH}")
    except OSError as exc:
        steps.append(f"could not write kernel tuning: {exc}")

    # conntrack has to be loaded before its sysctls exist, and tun before the
    # server can open the tunnel at all.
    for module in ("nf_conntrack", "tun"):
        _run(["modprobe", module])

    if _run(["sysctl", "--system"]).returncode == 0:
        steps.append("applied kernel tuning")
    else:
        steps.append("kernel tuning written; it applies on next boot")

    try:
        UNIT_PATH.write_text(settings.unit_text())
        UNIT_PATH.chmod(0o600)
        steps.append(f"wrote {UNIT_PATH}")
    except OSError as exc:
        steps.append(f"could not write the service unit: {exc}")
        return steps

    if not Path("/run/systemd/system").exists():
        steps.append("no systemd here; run turbobond-server yourself to start the concentrator")
        return steps

    _run(["systemctl", "daemon-reload"])
    started = _run(["systemctl", "enable", "--now", "turbobond-concentrator"])
    if started.returncode == 0:
        steps.append("enabled and started turbobond-concentrator")
    else:
        steps.append(f"could not start the service: {started.stderr.strip()}")
    return steps


def is_root() -> bool:
    return os.geteuid() == 0
