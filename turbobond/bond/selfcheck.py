"""Answer, on the server itself, why a client cannot pair with it.

The concentrator drops unauthenticated datagrams without replying, which is
correct but leaves nothing to diagnose with: a closed port, a stopped service
and a mistyped key are all just silence from the client's side. These checks run
where the answer actually is, and end with a real handshake over the loopback
using the installed key, so "the server works, the path to it does not" can be
told apart from "the server is broken" without guessing.
"""

from __future__ import annotations

import ipaddress
import shutil
import socket
import subprocess
from dataclasses import dataclass

from turbobond.bond import provision
from turbobond.bond.protocol import FrameType, decode_frame, encode_frame
from turbobond.util.crypto import Sealer

OK = "ok"
WARN = "warn"
FAIL = "fail"


@dataclass
class Result:
    status: str
    title: str
    detail: str = ""

    def line(self) -> str:
        mark = {OK: "[ ok ]", WARN: "[warn]", FAIL: "[fail]"}[self.status]
        text = f"  {mark} {self.title}"
        return f"{text}\n         {self.detail}" if self.detail else text


def _run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, check=False)  # noqa: S603
    except (OSError, subprocess.SubprocessError) as exc:
        return subprocess.CompletedProcess(cmd, returncode=127, stdout="", stderr=str(exc))


def check_service() -> Result:
    systemctl = shutil.which("systemctl")
    if not systemctl:
        return Result(WARN, "systemd not present", "start the server yourself")

    state = _run([systemctl, "is-active", "turbobond-concentrator"]).stdout.strip()
    if state == "active":
        return Result(OK, "service is running")
    return Result(
        FAIL,
        f"service is {state or 'not installed'}",
        "journalctl -u turbobond-concentrator -n 50 --no-pager",
    )


def check_listening(port: int) -> Result:
    """Bind the port to see if anything already holds it.

    A successful bind means nothing is listening, so the service is not up
    however healthy it may look elsewhere.
    """

    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        probe.bind(("0.0.0.0", port))
    except OSError:
        return Result(OK, f"something is listening on UDP {port}")
    else:
        return Result(
            FAIL,
            f"nothing is listening on UDP {port}",
            "the concentrator is not running, so every client sees silence",
        )
    finally:
        probe.close()


def check_local_firewall(port: int) -> Result:
    ufw = shutil.which("ufw")
    if ufw:
        status = _run([ufw, "status"]).stdout
        if "inactive" in status:
            return Result(OK, "ufw is inactive, so it blocks nothing")
        if f"{port}/udp" in status:
            return Result(OK, f"ufw allows UDP {port}")
        return Result(FAIL, f"ufw is active and has no rule for UDP {port}", f"ufw allow {port}/udp")

    firewall_cmd = shutil.which("firewall-cmd")
    if firewall_cmd:
        ports = _run([firewall_cmd, "--list-ports"]).stdout
        if f"{port}/udp" in ports:
            return Result(OK, f"firewalld allows UDP {port}")
        return Result(
            FAIL,
            f"firewalld has no rule for UDP {port}",
            f"firewall-cmd --permanent --add-port={port}/udp && firewall-cmd --reload",
        )

    return Result(OK, "no local firewall is running")


def check_address(public_ip: str) -> Result:
    """A private address here is one a phone on the internet cannot dial."""

    if not public_ip:
        return Result(WARN, "could not work out this server's address", "pass --public-ip")

    try:
        parsed = ipaddress.ip_address(public_ip)
    except ValueError:
        return Result(WARN, f"unrecognised address {public_ip}")

    if parsed.is_private:
        # is_private covers the documentation ranges as well as RFC1918, so the
        # wording stays true for both rather than naming the wrong reason.
        return Result(
            FAIL,
            f"{public_ip} is not a publicly routable address",
            "this is the address clients were told to dial, and it is not "
            "reachable from the internet. Re-run the installer with "
            "--public-ip <the address your provider shows>",
        )
    return Result(OK, f"clients should dial {public_ip}")


def check_handshake(psk: str, port: int, timeout: float = 3.0) -> Result:
    """Pair with the running concentrator over the loopback.

    This is the check that matters: it uses the installed key and the real wire
    format, so an ack proves the service, the key and the protocol are all
    good, and narrows anything still failing to the network path in between.
    """

    try:
        sealer = Sealer.from_psk(psk)
    except Exception as exc:  # noqa: BLE001
        return Result(FAIL, "the installed key is not usable", str(exc))

    frame = encode_frame(
        sealer,
        frame_type=FrameType.HANDSHAKE,
        session_id=0x7EC0DE,
        link_id=1,
        counter=1,
        seq=0,
        payload=b"",
    )

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(frame, ("127.0.0.1", port))
        data, _ = sock.recvfrom(65535)
    except TimeoutError:
        return Result(
            FAIL,
            "the concentrator did not answer its own handshake",
            "it is listening but not replying; check the log",
        )
    except OSError as exc:
        return Result(FAIL, "could not reach the concentrator locally", str(exc))
    finally:
        sock.close()

    reply = decode_frame(sealer, data)
    if reply is None:
        return Result(FAIL, "the reply did not authenticate", "the running key differs from the installed one")
    if reply.type is not FrameType.HANDSHAKE_ACK:
        return Result(WARN, f"unexpected reply {reply.type.name}")
    return Result(OK, "handshake succeeded using the installed key")


def run_checks(public_ip: str = "") -> tuple[list[Result], str]:
    settings = provision.installed_settings()
    if settings is None:
        return (
            [Result(FAIL, "no concentrator is installed", "run the installer first")],
            "Nothing to check.",
        )

    port = settings.port
    listening = check_listening(port)
    results = [
        check_service(),
        listening,
        check_local_firewall(port),
        check_address(public_ip or provision.detect_public_ip()),
        # Dialling a port with no listener would report a timeout as the server
        # failing to answer, which reads as a second, separate fault.
        check_handshake(settings.psk, port)
        if listening.status == OK
        else Result(FAIL, "handshake not attempted", "nothing is listening to answer it"),
    ]
    return results, _verdict(results)


def _verdict(results: list[Result]) -> str:
    """Say what to do next, rather than leaving a list of marks to interpret."""

    if any(r.status == FAIL for r in results):
        return (
            "Something above is broken on this server. Fix the [fail] lines "
            "first; a client cannot pair until they pass."
        )
    return (
        "This server is healthy: it is listening and it pairs with itself using "
        "the installed key.\n\n"
        "If a client still cannot connect, the fault is on the path in between, "
        "and there are only two ends left to check:\n"
        "  - the cloud firewall (DigitalOcean, AWS, Azure, GCP), which runs "
        "outside this machine and cannot be seen from in here. It needs "
        "inbound UDP allowed.\n"
        "  - the key the client is using. Compare it against "
        "'sudo turbobond-server --pairing' character for character.\n\n"
        "To tell those apart, watch 'journalctl -u turbobond-concentrator -f' "
        "while the client tries. A 'failed to authenticate' line means the "
        "packets are arriving and the key is wrong. Silence means they are not "
        "arriving at all, which is the firewall."
    )


def format_report(results: list[Result], verdict: str) -> str:
    body = "\n".join(r.line() for r in results)
    return f"\nturbobond concentrator self-check\n\n{body}\n\n{verdict}\n"
