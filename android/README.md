# turbobond for Android

The client half of the bond, as an Android app. It bonds the phone's WiFi and
mobile data across your own concentrator, with no root and no subscription.

This exists because the Linux gateway needs a machine to run on. If you do not
have one, this puts the client on hardware you already own.

## What it does and does not do

It bonds **this phone's own traffic**. Every app on the phone goes out over
both radios at once, resequenced by your concentrator.

It does **not** cover your other devices. Android forwards hotspot and USB
tethering traffic in the kernel, outside the VPN interface any app can create,
so a tablet on this phone's hotspot bypasses this app entirely. That is an
Android design decision, not something the app can opt out of. Covering every
device still needs the Linux gateway.

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

Copy the APK to the phone and open it. Android will ask you to allow installing
from unknown sources, since this is not from the Play Store.

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
