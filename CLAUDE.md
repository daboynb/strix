# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repo layout

- `strix/` — the Android app (Kotlin + Jetpack Compose). Sole module.

The Gradle root is `strix/`; the `:app` module is the only project. Kotlin sources live under `app/src/main/kotlin/org/csploit/strix/` (note: `kotlin/`, not `java/`). `compileSdk 35`, `minSdk 29`, `targetSdk 34`. The release build signs only when `strix/keystore.properties` exists — otherwise `signingConfig` is null. All `gradlew` commands below run from `strix/`.

## Build / run

```bash
cd strix
./gradlew assembleDebug                # debug APK
./gradlew installDebug                 # install on connected device (must be ARM64, root, API 29+)
./gradlew :app:lint                    # Android lint
./gradlew :app:test                    # unit tests (JVM)
./gradlew :app:connectedAndroidTest    # instrumented tests
```

No test runner is wired beyond Gradle's defaults — there are currently no test sources under `app/src/test` or `app/src/androidTest`.

## Native tooling pipelines (Docker, host x86_64)

The APK ships two large `.tar.gz.bin` blobs in `app/src/main/assets/` that are extracted to `filesDir/` on first run. Both are produced by Docker pipelines under `strix/`:

```bash
# Pentest binaries: nmap, hydra, ettercap, tcpdump, arpspoof + libs
cd strix/tools && ./build.sh && ./create-bundle.sh
# Output: tools/tools-bundle.tar.gz  →  copy to app/src/main/assets/tools-bundle.tar.gz.bin

# Ruby 3.3.6 + Metasploit Framework 6.4.x cross-compiled for aarch64-linux-android
cd strix/ruby-msf && ./build.sh && ./create-bundle.sh
# Output: ruby-msf/ruby-msf-bundle.tar.gz  →  copy to app/src/main/assets/ruby-msf-bundle.tar.gz.bin
```

Bundles are large — `.tar.gz` is excluded from APK compression (`androidResources.noCompress`). Don't rebuild bundles unless the underlying tool/lib needs to change.

## Architecture

Single-module Android app (`:app`, namespace `org.csploit.strix`). MVVM with Hilt DI, Compose UI, coroutine `Flow`-based pipelines.

### Three layers under `org.csploit.strix`

- **`core/`** — process execution, root detection, logging, and scan-lifecycle plumbing. `ProcessManager.execute()` is the canonical way to run a binary: it spawns `su -c` (or `sh -c` when `asSu=false`), wraps stdout/stderr/exit/kill into a `Flow<ProcessEvent>`, and kills the process when the collector cancels. Every long-running tool integration goes through this. `ScanRegistry` (`@Singleton`) tracks active scan tasks as a `StateFlow`; `ScanService` is a foreground `Service` that observes it to keep the process alive while a scan runs; `StrixNotifications` owns the notification channels.
- **`data/`** — one Kotlin class per integrated tool/capability (`PortScanner`, `MitmRunner`, `HydraModules`, `CredentialTester`, `MsfDaemon`, `MsfRpcClient`, `PacketCaptureRunner`, `TracerouteRunner`, `PacketForger`, `DnsSpoofServer`, `RouterAnalyzer`, `HttpProbe`, `NetworkScanner`, `NetworkManager`, `OuiLookup`, `TargetRepository`, `AppSettings`), plus extractors (`ToolsExtractor`, `RubyExtractor`, `ToolManager`) and in-memory session stores (`BruteForceSessionStore`, `MitmSessionStore`). Each is `@Singleton`-injected and exposes `Flow`/`StateFlow` to the UI. The `wifi/` subpackage is the cSploit WPA/WEP keygen port (`WirelessMatcher` + per-vendor `algorithms/`).
- **`ui/<feature>/`** — one folder per screen (`hostlist`, `hostdetail`, `portscan`, `mitm`, `bruteforce`, `msf`, `packetcapture`, `packetforger`, `traceroute`, `wifikeygen`, `settings`, `splash`). Routes and string args are centralized in `ui/navigation/StrixNavigation.kt` (`Routes` object).
- **`domain/model/`** — pure data classes shared across layers.
- **`di/AppModule.kt`** — Hilt bindings.

### Asset extraction lifecycle

`SplashScreen` → `ToolManager` decides what to extract. `ToolsExtractor` and `RubyExtractor` each open their `.tar.gz.bin` from assets, gunzip + untar into `filesDir/tools/`, `filesDir/ruby/`, `filesDir/msf/`, and chmod binaries executable. `ToolManager.is*Installed()` checks for sentinel binaries to skip re-extraction. Paths consumed by runners:

- `toolsPath` → `filesDir/tools/` (contains `bin/nmap`, `bin/hydra`, `bin/ettercap`, `bin/tcpdump`, `bin/arpspoof`, `lib/`, `share/`, `etc/ettercap/etter.conf`)
- `rubyPath` → `filesDir/ruby/` (`bin/ruby`, `lib/libpq.so.5`, stdlib)
- `msfPath` → `filesDir/msf/` (`msfconsole`, `msfrpcd`, `vendor/bundle`)

`ToolsExtractor.patchEtterConf` rewrites `etter.conf` post-extract because absolute paths inside it must point at the device's `filesDir`.

### MSF integration

`MsfDaemon` is a singleton that owns the `msfrpcd` lifecycle (`STOPPED → STARTING → READY/FAILED`) via `ProcessManager`. `MsfRpcClient` speaks MessagePack RPC (`org.msgpack:msgpack-core`) over HTTP to the local daemon. UI talks only to those two — never spawns msf processes directly.

### Root requirement

Every offensive feature requires `su`. `RootChecker` gates the splash flow; runners assume `asSu=true` by default in `ProcessManager`. The app cannot function on non-rooted devices.

## Conventions specific to this codebase

- Long-running tool runs are exposed as `Flow<ProcessEvent>` from `data/` and collected in ViewModels — cancelling collection terminates the underlying process. Don't add manual `Process.destroy()` paths in parallel.
- New tool integrations should add a class under `data/`, route subprocess calls through `ProcessManager`, and avoid hardcoding paths — use `ToolManager.toolsPath`/`rubyPath`/`msfPath`.
- New screens go under `ui/<feature>/`, register in `StrixNavigation.kt`'s `Routes`, and inject ViewModels via Hilt (`hilt-navigation-compose`).
- Reuse before reinventing: `WirelessMatcher`/`Keygen` already cover WiFi keygen; `MsfRpcClient` already wraps msfrpcd; `HydraModules` already enumerates supported hydra services. Recent commit history flags what's still open.
- `StrixApplication.onCreate` pre-warms a throwaway `WebView` on a posted main-thread tick — this works around the BruteForce WebView first-expand sizing bug (Chromium lazy-init during Compose measurement sizes the `AndroidView` with wrong constraints). Don't remove it.
- Assets ending in `.tar.gz` are not compressed by aapt — keep that exemption when adding similar blobs.
- App is Italian-leaning in comments/docs but code identifiers are English; keep new code English.
