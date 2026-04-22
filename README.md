# Strix

> **⚠️ DEVELOPMENT STATUS:** This project is currently under active development and is not yet considered stable.

Strix is an Android network security assessment suite — a modern, ground-up rewrite of the ideas behind [cSploit](https://github.com/cSploit/android), built for current Android versions with a Kotlin + Jetpack Compose stack.

It bundles a full offensive toolchain (Nmap, Hydra, Ettercap, tcpdump, arpspoof) and a cross-compiled Ruby + Metasploit Framework runtime inside a single APK, and exposes them through a unified mobile UI.

> **Strix is intended strictly for authorized security testing, education, and research on networks you own or have explicit written permission to assess. Running these tools against systems you do not control is illegal in most jurisdictions.**

## Why this project exists

cSploit — once the reference "pentest on your phone" app — has been effectively unmaintained for years. Android evolved (SELinux, scoped storage, API 29+ restrictions, 64-bit-only, Compose) and the old C-and-Java codebase stopped keeping up.

Strix is a clean-slate take on the same idea:

- **Everything a pentester needs on a rooted Android phone, in one APK.** No external binaries to sideload, no Termux pipelines, no manual Ruby/Metasploit install. First launch extracts the toolchain into `filesDir/` and you are ready to scan, MITM, brute-force, and run exploit modules.
- **A modern Android codebase.** Kotlin, Coroutines + `Flow`, Jetpack Compose, Hilt DI, MVVM. Every long-running tool is a `Flow<ProcessEvent>` — cancel the collector and the underlying native process dies. No leaked `Process.destroy()` paths.
- **Real tools, not reimplementations.** Nmap is Nmap. Metasploit is Metasploit (6.4.x, via `msfrpcd` + MessagePack RPC). Hydra is Hydra. The UI is a frontend; the engines are the canonical upstream projects, cross-compiled for `aarch64-linux-android`.
- **Offline-capable.** Once installed, Strix does not need network access to the outside world to operate against a local LAN — all binaries, libraries, wordlists, and the entire MSF `vendor/bundle` ship inside the APK.

## What Strix does

| Area | What it gives you |
|------|---|
| **Host discovery** | ARP + ICMP sweeps of the local subnet, OUI vendor lookup, live host list |
| **Port / service scan** | Nmap frontend with service + version detection, per-host port list |
| **MITM** | Ettercap + arpspoof driven from the UI, DNS spoofing, packet interception |
| **Packet capture** | On-device tcpdump with live pcap output |
| **Packet forging** | Craft and replay custom packets |
| **Brute force** | Hydra frontend covering all supported service modules (SSH, FTP, HTTP-Form, SMB, RDP, MySQL, Postgres, VNC, Telnet, …) with credential lists |
| **Exploitation** | Full Metasploit Framework running natively on the device via `msfrpcd`; module browser, exploit runner, interactive Meterpreter sessions |
| **Traceroute** | UDP / ICMP traceroute with hop-by-hop render |
| **Router analysis** | Default credential probing against common router admin panels |
| **WiFi keygen** | Offline WPA/WEP default-key recovery — port of cSploit's `WirelessMatcher` with per-vendor algorithms (Alice, Thomson, Huawei, Dlink, Pirelli, Eircom, Sky, Verizon, Ono, Tecom, Telsey, Zyxel, Comtrend, Andared, Infostrada, Megared, Conn, Discus, EasyBox, PBS, OTE, Wlan2, Wlan6) |

## Requirements

- Android **API 29+** (Android 10 or newer)
- **ARM64** device (`aarch64`)
- **Root** (`su` must be available — every offensive feature needs raw socket / kernel access the platform does not grant to regular apps)

Non-rooted or 32-bit devices are not supported and will not be — this is a deliberate scope choice, not an omission.

## What this project is trying to show

1. **The mobile platform is viable for serious offensive security work.** A current-generation Android phone has more than enough CPU, RAM, and storage to host a full pentest rig. What was missing was the software glue. Strix is one answer to that.
2. **Legacy open-source security tools deserve modern frontends.** Nmap, Hydra, and Ettercap are excellent engines wrapped in aging UIs. Compose makes it cheap to build good UIs on top of them.
3. **The Metasploit Framework can run natively on Android.** Cross-compiling Ruby 3.3.6 + the entire MSF gem bundle for `aarch64-linux-android` — and shipping it inside an APK — is the headline technical result of this repo. The `strix/ruby-msf/` Docker pipeline is the reproducible recipe.
4. **Security tooling should be auditable.** The whole thing is open source: the Kotlin app, the Docker build pipelines for the native bundles, and the patches applied to upstream tools (see `strix/tools/patches/`). No binary blobs of unknown provenance.

## Repository layout

```
strix/
├── app/                  # Android app (Kotlin + Compose)
│   └── src/main/
│       ├── assets/       # Wordlists + compressed tool/MSF bundles
│       └── kotlin/org/csploit/strix/
│           ├── core/     # ProcessManager, RootChecker, logging
│           ├── data/     # One class per integrated tool (PortScanner, MitmRunner, Hydra*, MsfDaemon, MsfRpcClient, …)
│           ├── domain/   # Pure data models
│           ├── di/       # Hilt bindings
│           └── ui/       # One folder per screen, Compose + ViewModel
├── tools/                # Docker pipeline: nmap/hydra/ettercap/tcpdump/arpspoof + deps
└── ruby-msf/             # Docker pipeline: Ruby 3.3.6 + Metasploit 6.4.x for aarch64-linux-android
```

See [`CLAUDE.md`](CLAUDE.md) for the detailed architecture notes.

## Building

```bash
cd strix
./gradlew assembleDebug                # debug APK
./gradlew installDebug                 # install on a connected rooted ARM64 device
./gradlew :app:lint                    # Android lint
```

Rebuilding the native bundles (only needed when upstream tool/lib versions change):

```bash
# Pentest binaries
cd strix/tools && ./build.sh && ./create-bundle.sh
# Output: tools/tools-bundle.tar.gz → copy to app/src/main/assets/tools-bundle.tar.gz.bin

# Ruby + Metasploit
cd strix/ruby-msf && ./build.sh && ./create-bundle.sh
# Output: ruby-msf/ruby-msf-bundle.tar.gz → copy to app/src/main/assets/ruby-msf-bundle.tar.gz.bin
```

Both pipelines run in Docker on an `x86_64` host — no Android device is needed to build them.

## Credits and lineage

- **cSploit** — the original Android pentest suite and the direct conceptual ancestor. Strix inherits its WiFi keygen algorithms and overall product idea.
- **dSploit** — cSploit's predecessor.
- **Nmap, Hydra, Ettercap, tcpdump, arpspoof, Metasploit Framework, Ruby** — the actual engines Strix ships and drives. All credit for the scanning/exploitation capability goes to those projects and their maintainers.

## License

See `LICENSE` (to be added).

## Disclaimer

This software is provided for educational and authorized security testing purposes only. The authors accept no responsibility for misuse. You are solely responsible for ensuring that any use of this tool complies with applicable local, state, national, and international laws.
