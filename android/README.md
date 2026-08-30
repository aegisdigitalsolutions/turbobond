# turbobond for Android

The client half of the bond, as an Android app. It bonds the phone's WiFi and
mobile data across your own concentrator, with no root and no subscription.

This exists because the Linux gateway needs a machine to run on. If you do not
have one, this puts the client on hardware you already own.

## What it does and does not do

It bonds **this phone's own traffic**. Every app on the phone goes out over
both radios at once, resequenced by your concentrator.

Devices on the phone's hotspot are not bonded *automatically*. Android forwards
tethered traffic in the kernel, outside the VPN interface any app can create,
so a tablet on the hotspot would bypass this app entirely. That is an Android
design decision and the app cannot opt out of it.

The proxy is the way around it, and it is why one is built in.

## Bringing other devices onto the bond

Traffic the kernel *forwards* skips the tunnel, but traffic that **originates**
from an app on the phone goes through it. A proxy turns the first into the
second: another device's connection terminates at the proxy, and the onward
connection the proxy makes is the phone's own, so it is bonded like anything
else.

So: turn on the phone's hotspot, connect the other device to it, and point that
device's proxy client at the address the app displays.

### Surge (iOS and iPadOS)

A complete profile is in [`surge/turbobond.conf`](surge/turbobond.conf). Copy
it into Surge and change one line: the address in `[Proxy]`, to whatever the
app is showing.

Four settings in it are load-bearing, and each fails quietly rather than
loudly if you drop it:

- `ipv6 = false`. The bond is IPv4. Left on, the device opens IPv6 connections
  that bypass the proxy entirely and are never bonded, with nothing to see.
- `skip-proxy` and the local `IP-CIDR` rules. The proxy is on the local
  network, so without these the device tries to reach the proxy through itself.
- `udp-relay=false`. Only CONNECT is implemented, so UDP cannot traverse the
  proxy. Announcing support for it would send UDP somewhere it silently dies.
- The `fallback` proxy group. If the phone goes out of range or turbobond
  disconnects, this device drops to an ordinary direct connection instead of
  losing internet, and rejoins the bond by itself afterwards.

Hostnames are passed to the proxy rather than resolved locally, so DNS for
proxied connections resolves at your concentrator too.

Any SOCKS5-capable client works the same way; Surge is not special here.

### What the proxy does not carry

Only TCP. SOCKS5 can carry UDP through ASSOCIATE, which is not implemented, so
UDP still leaves the other device unbonded. In practice that means web
browsing, streaming and most apps go over the bond, while some games and some
video-call protocols do not.

Covering every device on the network including UDP, with nothing to configure
per device, is what the Linux gateway does.

## When it does not connect

The app reaches the concentrator *before* it takes over the phone's traffic,
and only brings the interface up once the server has answered. A bond that
cannot form therefore leaves the connection alone and says why, rather than
installing a default route into a tunnel with no working far end — which
presents as the phone losing the internet outright, with nothing on screen to
explain it.

| What it says | What it means |
| --- | --- |
| `No reply from HOST:PORT` | Datagrams left the phone and nothing came back. Either UDP is blocked before it reaches the server, or the server is not running. |
| `Bad pre-shared key` | The key is not 64 hex characters. Nothing was sent. |
| `Cannot find HOST` | The host did not resolve. Use the server's IP address. |
| `No usable network` | Neither WiFi nor cellular offered a usable link. |
| `Server stopped responding` | The bond was up and went silent, so it was released to give the phone its connection back. |

`No reply` is the ambiguous one, because a wrong key looks identical from the
phone: unauthenticated datagrams are dropped without a reply. The server tells
the two apart. Watch it while you press Connect:

```bash
sudo journalctl -u turbobond-concentrator -f
```

A datagram that arrives but does not authenticate logs `failed to authenticate`
and names the source, which means the port is open and the key is wrong — read
the real one back with `sudo turbobond-server --pairing`. Complete silence
means nothing arrived at all, so the traffic is being dropped before it gets
there: check the cloud firewall first, since it sits outside the machine and
the installer cannot open it.

## What you do not have to configure

The app never signs in to your router. To it, the router is just a WiFi network
the phone has joined, indistinguishable from any other. There is nowhere to put
a router admin password, and none is needed. (The Linux gateway does sign in to
the router, to disable its SIP ALG and apply tuning. That is the gateway's job,
not this app's.)

There is no account, no sign-in, and no username or password for the server
either. The pre-shared key is the entire credential: holding it is what proves
a client is allowed to open a session. Nothing else is exchanged.

None of the router's inbound-traffic features need to be touched, because every
connection in this design is opened *outbound* by the phone. The phone dials the
concentrator on UDP 5310; the concentrator only ever replies to the address and
port the phone's NAT already created. That is an ordinary outbound UDP flow, the
same shape as a DNS query, so it traverses the router's NAT (and the carrier's,
on the cellular link) without any mapping being configured ahead of time.

| Router setting | Needed | Why |
| --- | --- | --- |
| Port forwarding | No | Forwarding exists to let the internet reach in. Nothing dials the phone. |
| UPnP | No, leave off | Only useful for opening inbound ports, which we never need. It also lets any device on the LAN punch holes in the firewall, so off is both sufficient and safer. Off is the M7's default. |
| DMZ | No, leave off | Exposes a device wholesale to the internet, in exchange for an inbound path we have no use for. Pure downside here. |
| VPN passthrough | Irrelevant | Concerns IPsec and PPTP (ESP, AH, GRE). The tunnel is plain UDP, which passthrough does not govern. Enabled by default; leaving it that way changes nothing either way. |
| DNS rebind protection | Leave on | Blocks public hostnames resolving to private addresses. The app is pointed at a public IP, so it is never in the path. Only relevant if you later give the concentrator a hostname pointing at a private address. |
| IP passthrough | No | Hands the carrier IP to one downstream device and restarts the hotspot. It solves double-NAT for a downstream router; it does not help a phone making outbound connections. |

Idle UDP mappings do get reaped — carriers are aggressive, often within a
minute. The client sends a keepalive every 15 seconds, comfortably inside that
window, which is what holds the mapping open on both the router and the carrier.

One caveat if you go on to run SIP through this: the M7 Pro's documentation
describes no SIP ALG toggle, and the field probe in `turbobond/router` returns
false when the model exposes no such key. If the firmware does mangle SIP
headers, there is no setting to stop it. That is an argument for carrying SIP
inside the tunnel, where the router sees only opaque UDP and cannot rewrite
anything, rather than sending it in the clear and hoping.

## Build

Needs JDK 17 and the Android SDK. `ANDROID_HOME` must point at the SDK, or
`local.properties` must contain `sdk.dir`.

```bash
cd android
./gradlew :app:assembleDebug
```

The APK lands at `app/build/outputs/apk/debug/app-debug.apk`. It is signed with
the standard debug key, which is enough to sideload but not to publish.

## Install

The build runs in CI, so a ready-made APK is attached to the `latest` release:

    https://github.com/aegisdigitalsolutions/turbobond/releases/latest

Open that on the phone and download `turbobond.apk`. Android will ask you to
allow installing from unknown sources, since this is not from the Play Store.

Then enter the three values the concentrator's installer printed — host, port
and pre-shared key — and press Connect. Android asks once for permission to
create a VPN connection; that prompt is the system's, and it appears for every
VPN app.

The notification shows which radios have joined: `Bonded over 2 of 2: wifi,
cellular` means both are carrying traffic.

## How it works

`UplinkManager` asks Android for a WiFi network and a cellular network
*separately*. That explicit request is the important part: without it Android
tears down the cellular radio as soon as WiFi connects, and there is nothing to
bond. Each uplink gets its own socket, which is `protect()`ed so it stays
outside our own tunnel and then bound to its specific network so its packets
leave over that radio rather than the system default.

`BondVpnService` reads IP packets from the TUN interface Android grants to a
VPN app, seals each one with ChaCha20-Poly1305, and spreads them across the
uplinks. Replies are decoded, put back in order by `ReorderBuffer`, and written
back to the TUN.

Small packets are sent over every uplink rather than one. Duplicating them is
cheap, and they are usually call signalling, where a single loss is expensive.

## Testing

The wire protocol is in `:core`, a plain JVM module with no Android
dependencies, so it can be tested on a build machine:

```bash
./gradlew :core:test
```

Those tests pin the exact bytes the Python implementation produces. The two
ends derive their key independently and never compare notes, so a divergence
would show up only as the concentrator silently dropping everything — pinning
the bytes is what stops that shipping.

`:core` also builds a runnable check that dials a real concentrator, which is
how the protocol was verified against a live server before any of it went near
a phone:

```bash
./gradlew :core:run --args="<host> <port> <psk-hex> 3"
```

## Status

The protocol layer is verified against a live concentrator. The Android layer
compiles and is structured the way Android's own documentation prescribes, but
it has not been run on a physical device — there was no phone available to the
build. Treat the first install as a test: if something is wrong, remove the VPN
profile in Android's settings and connectivity returns immediately.
