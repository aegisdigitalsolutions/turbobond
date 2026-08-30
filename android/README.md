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

## What you do not have to configure

The app never signs in to your router. To it, the router is just a WiFi network
the phone has joined, indistinguishable from any other. There is nowhere to put
a router admin password, and none is needed. (The Linux gateway does sign in to
the router, to disable its SIP ALG and apply tuning. That is the gateway's job,
not this app's.)

There is no account, no sign-in, and no username or password for the server
either. The pre-shared key is the entire credential: holding it is what proves
a client is allowed to open a session. Nothing else is exchanged.

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
