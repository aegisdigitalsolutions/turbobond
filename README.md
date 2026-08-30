# turbobond

Multi-WAN bandwidth bonding gateway for a NETGEAR Nighthawk M7 Pro (and the
rest of the Nighthawk family), with SIP-transparent firewalling, two selectable
egress routes, and a control panel whose only required interaction is signing
in.

Install it on the box that sits between your router and your LAN, open the web
UI, choose a password. From there the app discovers the uplinks, signs into the
router's web administrator, applies its tuning profile, programs policy
routing, brings up the bond, opens the firewall for voice, and puts every
attached device on the bonded path by itself.

## Install

```bash
sudo sh packaging/install.sh
```

The installer picks a Python 3.11+ interpreter, installs the system packages it
needs (`iproute2`, `nftables`, `iptables`, `procps`, `iputils-ping`), installs
turbobond into a virtualenv under `/usr/local/lib/turbobond`, writes
`/etc/turbobond/turbobond.yaml`, and enables the systemd unit. It finishes by
printing the URL to open.

Then browse to `http://<gateway>:8088` and sign in. The first sign-in claims the
account: whatever password you type becomes the password.

Nothing else is required. The optional fields on the sign-in screen (router
admin password, concentrator address, shadowsocks server) only need to be filled
in once, and each one unlocks the corresponding feature.

To try it without touching the system, run it in dry-run mode, where every
privileged command is logged instead of executed and a simulated router and
uplinks stand in for the real ones:

```bash
turbobond --dry-run serve --port 8088
```

## What activation does

Activation is a ten-stage state machine. Each stage reports `ok`, `degraded`, or
fails; a degraded stage never stops the ones behind it.

| Stage | What happens |
| --- | --- |
| preflight | Checks Python, privileges, tools, TUN, MPTCP, conntrack. Installs missing packages. |
| router | Signs into the Nighthawk web administrator and reads its state. |
| links | Discovers every WAN uplink and starts continuous health probing. |
| optimization | Applies the `wrt-turbo-search` profile to the router and the local stack. |
| routing | Programs a policy-routing table per link, plus MPTCP endpoints. |
| bond | Brings up the bonded tunnel, or weighted ECMP when no concentrator is set. |
| transport | Starts the shadowsocks client for the second route. |
| sip | Installs the wide-open SIP/RTP ruleset and disables every SIP ALG. |
| lan | Turns the host into a gateway so attached devices egress over the bond. |
| selector | Starts route selection, failover, and the continuous optimization sweep. |

## Bonding

Two modes, chosen automatically:

**Packet-level bonding (`tunnel`)** — with a concentrator configured, turbobond
opens a UDP socket per uplink to it, wraps each IP packet in a ChaCha20-Poly1305
frame with a sequence number, and spreads the frames across the links with a
weighted deficit round-robin scheduler. The concentrator resequences them and
NATs them out. Return traffic is fanned back across the same set of links, which
is what makes *download* aggregation work — without a peer doing that, inbound
packets only ever arrive over whichever single link the remote server picked.
One TCP connection genuinely uses every uplink at once.

**Weighted multipath (`ecmp`)** — with no concentrator, turbobond installs a
weighted ECMP default route and configures MPTCP endpoints. This aggregates
across connections and is entirely local, but a single connection still rides
one link. The dashboard marks this mode as degraded so the distinction is never
hidden from you.

The concentrator is the server half, and the dashboard hands you a tarball of it
already paired with this install's key:

```bash
# on a VPS with one fat uplink
tar xzf turbobond-concentrator.tar.gz
cd turbobond-concentrator && sudo sh install.sh
```

The bundle carries the turbobond source inside it, so the VPS installs without
reaching a package index for it and the two halves of the bond are always the
same version. It creates a virtualenv (Ubuntu 24.04 and Debian 12 refuse
system-wide pip installs) and pulls only the three libraries the server half
imports, not the gateway's web stack.

That installer also tunes the VPS for the job, in a
`/etc/sysctl.d/99-turbobond-concentrator.conf` drop-in that survives reboots:
forwarding, socket buffers sized to match the client's so neither end caps the
window, a deep netdev backlog because every uplink lands in one queue there,
BBR with `fq` (return traffic is paced from this side, so this is what sets
download throughput), no slow start after idle, and a conntrack table sized for
NATing a whole LAN.

Link weights follow measured quality: capacity, latency, jitter, and loss, with
metered links (cellular) penalised so they carry overflow rather than baseline.
A link that fails its probes is drained and the traffic redistributes; when it
recovers it rejoins.

## The two routes

Both routes run over the same bond. Switch between them from the dashboard, or
leave automatic failover on.

- **Bonded direct** — the aggregated pipe with no extra hop. Fastest, and the
  route voice traffic always takes.
- **Bonded + Shadowsocks** — the same pipe, then wrapped in a shadowsocks tunnel
  (`sslocal`, AEAD-2022 ciphers where the binary supports them) for an
  encrypted, obfuscated egress. Costs roughly 8 ms and ~8% of throughput.

Individual devices can be pinned to either route, so the office handset can stay
on the direct path while a laptop goes out through shadowsocks.

## SIP and RTP

Voice is treated as a first-class citizen rather than something the firewall
tolerates.

- `sip.wide_open` (on by default) accepts SIP signalling and the whole RTP range
  in both directions, on every interface.
- Voice traffic is exempted from connection tracking with `notrack`, so inbound
  INVITEs without a matching outbound flow are not dropped and long-lived
  registrations do not expire out of the conntrack table.
- Every SIP ALG is disabled: the kernel helpers (`nf_nat_sip`,
  `nf_conntrack_sip`) are unloaded, and the router's own ALG is turned off
  through its web administrator. ALGs rewrite SDP bodies they do not fully
  understand, which is the usual cause of one-way audio.
- Signalling is marked CS3 and RTP EF, and `tc` gives voice a priority band.
- In tunnel mode, SIP signalling packets are duplicated across every uplink, so
  a lost packet on one link costs nothing.

This is deliberately permissive. `sip.wide_open: false` keeps the ALG handling
and QoS but returns to stateful filtering.

## The router profile

`wrt-turbo-search` is a tuning profile, not third-party firmware. The M7 Pro
runs NETGEAR's own firmware and cannot be reflashed with OpenWrt or DD-WRT, so
turbobond drives it through the same web administrator API the stock UI uses,
and pairs that with the local kernel tuning an OpenWrt build would give you:

- *turbo*: BBR congestion control, `fq`/`cake` queueing, larger buffers, a
  bigger conntrack table, MSS clamping, disabled SIP ALG and UPnP.
- *search*: a sweep every few minutes that re-measures every link, re-weights
  the bond, and re-pins the best band and channel on the router.

## Command line

`turbobond serve` is what the service runs; the rest is for inspection.

```
turbobond serve        # run the web app
turbobond up           # activate without the web app
turbobond down         # tear down and restore
turbobond status       # current state as JSON
turbobond preflight    # dependency check (--install to fix)
turbobond links        # discovered uplinks
turbobond routes       # the two routes
turbobond sip          # show or apply the SIP ruleset
turbobond gen-psk      # fresh concentrator key
```

Add `--dry-run` to any of them to see exactly what would be executed.

## Configuration

`/etc/turbobond/turbobond.yaml`, written with mode `0600`. The UI writes it for
you; edit it directly only if you want to. Everything the app does to the system
is recorded and exposed at `/api/commands`, and the dashboard's diagnostics
download bundles the status, config (redacted), logs, command history, and the
generated firewall ruleset into one file.

## Requirements

- Linux with Python 3.11+, running as root (it programs routing, nftables, and
  a TUN device)
- Two or more WAN uplinks for bonding to mean anything
- `/dev/net/tun` for packet-level bonding; without it turbobond uses ECMP
- A host running `turbobond-server` for per-packet aggregation
- A shadowsocks server for the second route

## Development

```bash
pip install -e '.[dev]'
pytest        # 261 tests, no privileges needed
ruff check .
```

The test suite runs the real datapath: `tests/test_bonding_datapath.py` starts a
concentrator and a client on loopback and pushes packets through genuine UDP
sockets, AEAD framing, scheduler, and reorder buffer, then asserts the burst
arrives complete, in order, and spread across every uplink.

## License

MIT
