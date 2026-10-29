# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repo layout

- `strix/` — the Android app (Kotlin + Jetpack Compose). Sole module.

The Gradle root is `strix/`; the `:app` module is the only project. Kotlin sources live under `app/src/main/kotlin/org/csploit/strix/` (note: `kotlin/`, not `java/`). `compileSdk 35`, `minSdk 29`, `targetSdk 34`. The release build signs only when `~/.strix/keystore.properties` exists — otherwise `signingConfig` is null. All `gradlew` commands below run from `strix/`.

## Build / run

```bash
cd strix
./gradlew assembleDebug                # debug APK
./gradlew installDebug                 # install on connected device (must be ARM64, root, API 29+)
./gradlew :app:lint                    # Android lint
./gradlew :app:test                    # unit tests (JVM)
./gradlew :app:connectedAndroidTest    # instrumented tests
```

JVM unit tests live under `app/src/test/kotlin` (JUnit 4; `unitTests.isReturnDefaultValues = true` stubs `android.util.Log`, and `org.json:json` is a test dependency because android.jar's copy is a stub). Run them with `./gradlew :app:testDebugUnitTest`. There are no instrumented tests under `app/src/androidTest`.

## Native tooling pipelines (Docker, host x86_64)

Two native bundles: `tools-bundle.tar.gz.bin` (+ `tools-bundle.json`) is committed in `app/src/main/assets/` and shipped in the APK; `ruby-msf-bundle.tar.gz.bin` is NOT packaged (`ignoreAssetsPattern`) — the app downloads it from the latest `bundles-msf-*` release (see Asset extraction lifecycle). Both come from Docker pipelines under `strix/` (need Docker with buildx; NDK host is linux-x86_64, so no ARM hosts):

```bash
# Pentest binaries: nmap, hydra, ettercap, tcpdump, arpspoof + libs
cd strix/tools && ./build.sh && ALLOW_UNSIGNED=1 ./create-bundle.sh
# build.sh: docker buildx build -> exports to tools/output/ (wiped each run), log in tools/build.log
# create-bundle.sh: tools/tools-bundle.tar.gz + tools-bundle.json(.sig), copied to app/src/main/assets/tools-bundle.tar.gz.bin

# Ruby + Metasploit Framework cross-compiled for aarch64-linux-android (one multi-stage Dockerfile: ruby -> msf -> export)
cd strix/ruby-msf && ./build.sh && ALLOW_UNSIGNED=1 ./create-bundle.sh
# build.sh: exports to ruby-msf/output/ (override with BUILD_OUTPUT), log in ruby-msf/build.log
# create-bundle.sh: ruby-msf/ruby-msf-bundle.tar.gz + ruby-msf-bundle.json(.sig), copied to app/src/main/assets/ruby-msf-bundle.tar.gz.bin
```

- `tools/build.sh` / `ruby-msf/build.sh` are the host entry points; `tools/build-all.sh`, `ruby-msf/01-ruby/build-ruby.sh`, `ruby-msf/02-msf/build-msf.sh` run inside the image build. All scripts are `set -euo pipefail`: a failed download, checksum, make, missing binary or non-cross-compiled gem fails the build. Stripping uses the NDK `llvm-strip` inside the container.
- **`strix/versions.env` is the only place versions live**: base image (`ubuntu:24.04@sha256:...`), NDK, API level, every library/tool version + `*_SHA256` of its tarball, `RTMPDUMP_COMMIT`, `MSF_REF` (tag) + `MSF_COMMIT` (verified after clone), and the manifests' `*_BUNDLE_MIN_APP`. `scripts/lib.sh` passes it to `docker buildx build` as build args; Dockerfiles have no defaults. Bumping a version means updating its SHA256 too (`scripts/check-updates.sh <msf|deps|all>` does both; the weekly automation runs it).
- Downloads go through `scripts/fetch.sh` (SHA256-verified), injected via the `strix-scripts` build context — build through `build.sh`, not plain `docker build`.
- **Manifest + signature** (`scripts/sign-bundle.sh`): `<bundle>.json` = `{"format":1,"id":"tools"|"msf","version":...,"file":"<asset>.tar.gz.bin","sha256":...,"size":...,"unpacked":<tar bytes>,"minApp":...,"built":<UTC epoch seconds>}`. `built` (signing time, override with `BUNDLE_BUILT`) is what the app orders bundles by — version strings of the tools bundle aren't comparable — so it must grow with every release of a bundle id; manifests without it count as oldest. The committed `assets/tools-bundle.json` uses `built` = mtime of the committed `tools-bundle.tar.gz.bin` (1776241523 = 2026-04-15T08:25:23Z). `<bundle>.json.sig` = ECDSA P-256/SHA256 DER signature, verified against `scripts/bundle-signing.pub` right after signing. Key path from `BUNDLE_SIGNING_KEY`; without it the script fails unless `ALLOW_UNSIGNED=1` (local test builds only).
- **Smoke checks** (`scripts/smoke-bundle.sh <tools|msf> <bundle> <manifest>`, also run on every CI build): signature + sha256/size vs manifest, safe extraction (`scripts/tar_safe_extract.py`: no absolute/`..` paths, no links escaping the root), expected files, every ELF aarch64 (MSF payload data excluded); msf also `VERSION` = `MSF_REF` / `RUBY_VERSION`, native .so + `gem.build_complete` for nokogiri/pg/sqlite3/pcaprub/ffi and every gem declaring extensions, and no gem installed in two versions. `build-msf.sh` removes Ruby's own default/bundled gemspecs that `vendor/bundle` ships in another version (they caused RubyGems' "Unresolved or ambiguous specs" warning at msfrpcd start).
- **CI** (`.github/workflows/`; default token is read-only, every job declares its permissions):
  - `ci.yml` — PRs to `main` and pushes to `main`: `:app:testDebugUnitTest` + `:app:assembleDebug`, `:app:lintDebug` (non-blocking, report uploaded), pinned shellcheck/actionlint, `bash -n`. On PRs, changed pipeline inputs (`strix/tools/**`, `strix/ruby-msf/**`, build-related `strix/scripts/*`, `versions.env` keys — mapping in `scripts/bundle-meta.sh`) also build + smoke-check the affected bundle(s), unsigned, nothing published.
  - `bundle-build.yml` — reusable (`workflow_call`): build, create/sign, smoke-check, upload artifacts `<prefix>bundle-<id>`.
  - `update-bundles.yml` — the automation. Friday 06:00 UTC (Rapid7 usually tags Metasploit on Thursday) + `workflow_dispatch` (track all/msf/deps). Two tracks via `update-track.yml`, run in sequence so the second starts from what the first merged: **msf** (only `MSF_REF`/`MSF_COMMIT`) and **deps** (every other pin; builds tools and/or msf depending on the changed keys), so a broken lib bump never blocks a Metasploit update. Per track: `scripts/update-prepare.sh` commits the bump to `automation/<track>-update` and opens a draft PR → `bundle-build.yml` → `scripts/update-finish.sh` publishes `bundles-msf-<MSF_REF>-r<N>` / `bundles-tools-r<N>` (next free N), marks the PR ready and squash-merges it. Failure: nothing published, PR stays draft, `scripts/update-report.sh` opens/comments the single issue "Automated bundle update failed" (closed again by the next clean run). Idempotent: each release notes an inputs fingerprint (bundle's versions.env lines + git trees of its pipeline dir and `strix/scripts`), identical inputs are never rebuilt or re-released. To fix a failed bump, push to `automation/<track>-update` and re-run the workflow: a branch whose head isn't a bot commit is built as-is. Everything is chained inside one run because events made with `GITHUB_TOKEN` (the bot PR, the merge, release tags) don't trigger other workflows — so `ci.yml` does not run on bot PRs.
  - `build-bundles.yml` — manual: dispatch (artifacts, or `publish` = next free tag) or push a tag `bundles-msf-<MSF_REF>-r<N>` / `bundles-tools-r<N>`. Release assets: `<bundle>.tar.gz.bin`, `<bundle>.json`, `<bundle>.json.sig`; the app finds releases by tag prefix `bundles-msf-` / `bundles-tools-`.
  - `build-apk.yml` — **cutting an APK release**: bump `versionCode`/`versionName` in `app/build.gradle.kts`, merge, then `git tag v<version> && git push origin v<version>` (or dispatch for an artifact only). It embeds the newest verified `bundles-tools-*` release (fallback: committed asset), runs unit tests, builds the signed release APK, verifies it with `apksigner` and attaches it to the `v*` release.
  - Secrets: `BUNDLE_SIGNING_KEY`, `STRIX_KEYSTORE_B64`, `STRIX_KEYSTORE_PASSWORD`, `STRIX_KEY_ALIAS`, `STRIX_KEY_PASSWORD`. The automation needs "Allow GitHub Actions to create and approve pull requests" and no branch protection that blocks the bot's squash merge.

Bundles are large — `.tar.gz.bin` is excluded from APK compression (`androidResources.noCompress`). Don't rebuild bundles unless the underlying tool/lib needs to change.

## Architecture

Single-module Android app (`:app`, namespace `org.csploit.strix`). MVVM with Hilt DI, Compose UI, coroutine `Flow`-based pipelines.

### Three layers under `org.csploit.strix`

- **`core/`** — process execution, root detection, logging, and scan-lifecycle plumbing. `ProcessManager.execute()` is the canonical way to run a binary: it spawns `su -c` (or `sh -c` when `asSu=false`), wraps stdout/stderr/exit/kill into a `Flow<ProcessEvent>`, and kills the process when the collector cancels. Every long-running tool integration goes through this. `ScanRegistry` (`@Singleton`) tracks active scan tasks as a `StateFlow`; `ScanService` is a foreground `Service` that observes it to keep the process alive while a scan runs; `StrixNotifications` owns the notification channels. `Logger` (all app logging, tag `STRIX[caller]`) writes logcat and, once `StrixApplication.onCreate` calls `Logger.init`, also `filesDir/logs/strix.log` via `LogFileSink` (single background writer thread, 1 MB rotation to `strix.log.1`, line format in `LogFormat`); the app's uncaught-exception handler writes crashes there synchronously. `LogExporter` builds `cacheDir/exports/strix-log-*.txt` (device/app/bundle header + log, SSID/BSSID redacted by `LogFormat.redact`) shared through the `${applicationId}.fileprovider` FileProvider.
- **`data/`** — one Kotlin class per integrated tool/capability (`PortScanner`, `MitmRunner`, `HydraModules`, `CredentialTester`, `MsfDaemon`, `MsfRpcClient`, `PacketCaptureRunner`, `TracerouteRunner`, `PacketForger`, `DnsSpoofServer`, `RouterAnalyzer`, `HttpProbe`, `NetworkScanner`, `NetworkManager`, `OuiLookup`, `TargetRepository`, `AppSettings`), bundle specs + paths (`ToolsExtractor`, `RubyExtractor`, `ToolManager`; the generic installer/downloader/updater live in `data/bundle/`) and in-memory session stores (`BruteForceSessionStore`, `MitmSessionStore`). Each is `@Singleton`-injected and exposes `Flow`/`StateFlow` to the UI. The `wifi/` subpackage is the cSploit WPA/WEP keygen port (`WirelessMatcher` + per-vendor `algorithms/`).
- **`ui/<feature>/`** — one folder per screen (`hostlist`, `hostdetail`, `portscan`, `mitm`, `bruteforce`, `msf`, `packetcapture`, `packetforger`, `traceroute`, `wifikeygen`, `settings`, `splash`, `logs`). The Logs screen (host list overflow menu or Settings → Diagnostics) shows the log file live with level filter/search and Share/Copy/Clear. Routes and string args are centralized in `ui/navigation/StrixNavigation.kt` (`Routes` object).
- **`domain/model/`** — pure data classes shared across layers.
- **`di/AppModule.kt`** — Hilt bindings.

### Asset extraction lifecycle (native bundles)

Two bundles, both installed by the generic `data/bundle/BundleInstaller` and both updatable at runtime from GitHub releases. Ordering everywhere (APK copy vs installed vs remote, rollback protection) is `BundleVersions.compare`: by manifest `built`, a manifest without it is older, ties fall back to the version string; the same archive (id + sha256) is never "newer".

- **tools** ships in the APK as the offline baseline: `assets/tools-bundle.tar.gz.bin` + `assets/tools-bundle.json`. On every start `SplashViewModel` → `ToolManager.extractTools()` applies `BundleVersions.shouldInstallApkCopy`: install the APK copy when nothing usable is installed, the install is legacy (no `.bundle-version`) or predates `built`, or the APK copy is not older than the installed one; a downloaded bundle newer than the APK survives app updates. Settings → Bundles shows version + source (`ToolManager.toolsSource()`: "APK"/"downloaded"), update/download/progress/cancel, and "Reinstall tools from APK" (forces the APK copy; refused while a scan is registered).
- **msf** (Ruby + Metasploit, ~375 MB gz / ~780 MB unpacked) is **not** in the APK: `ignoreAssetsPattern` in `app/build.gradle.kts` excludes `ruby-msf-bundle.*` even if a local build left it in `assets/`. It is downloaded on demand from the Metasploit screen (the Exploit Finder routes there when MSF is missing).

Updates: `data/bundle/BundleUpdateManager` (`@Singleton`) owns one `BundleChannel` per bundle (`tools`: prefix `bundles-tools-`, `msf`: `bundles-msf-`); bundle-specific behaviour is plugged in via `BundleHooks` (installed manifest, swap blocker, before/after swap, lock). Check: ONE GitHub API call `GET /repos/daboynb/strix/releases?per_page=30` (60/h unauthenticated) serves both channels → per prefix the newest non-draft release with a single `.json` asset + `.json.sig` (`GitHubReleases`) → fetch both (asset downloads, not API calls) → verify the ECDSA P-256 signature against the key pinned in `SignatureVerifier` **before** anything else → reject wrong id, asset size ≠ manifest size, `minApp` > installed versionCode (`CandidateVerifier`). Install additionally rejects a candidate not newer than the installed one unless forced → `BundleDownloader` (timeouts, manual redirects re-sending Range, https only, Range resume into `filesDir/downloads/<file>.part`, size + sha256 check, mismatch deletes the partial) → stage → swap. A daily check runs at app start (only if the last one is >24h old, Wi-Fi only when `AppSettings.bundleWifiOnly`); it only records/announces newer versions (`AppSettings.availableManifest(id)`, banner in the host list, Settings, MSF screen), it never downloads.

Install steps (`BundleInstaller`): free-space check (`unpacked * 1.15`) → stream-extract into `filesDir/.staging-<id>/` while hashing the archive (`SafeTarExtractor` rejects absolute paths, `..`, symlinks/hardlinks escaping the root and writes through such links) → per-bundle patches on the staged tree (`ToolsExtractor.spec`: `patchEtterConf`; `RubyExtractor.spec`: extension symlinks, nokogiri `<major.minor>/` link, vendor json over stdlib, `msfrpcd` wrapper — always rewritten) → write `.bundle-version` (the manifest json) into the primary dir → swap: live dirs → `.old-<id>/`, staging → live, delete `.old-<id>` (via `su rm -rf` for root-owned leftovers, `RootFs`). The msf bundle swaps `msf/` and `ruby/` together. `cleanupLeftovers()` (once per process, before the tools step) restores a live dir from an interrupted swap and deletes stale `.staging-*`/`.old-*`. Swap gates (`BundleHooks.swapBlocker`): msf only when `MsfDaemon` is STOPPED/FAILED and `ScanRegistry` has no active task; tools only when `ScanRegistry` is empty and no process runs a binary from `toolsPath` (`su pgrep -f`). Otherwise the staged update waits (`BundleOp.PendingSwap` with the reason) until the user taps "Install now". Before the msf swap `MsfDaemon.beginMaintenance()` stops the daemon, kills stray `msfrpcd` and refuses `start()` until `endMaintenance()`; tools stage/swap is serialized with the APK install by `ToolManager.toolsLock`.

`ToolManager.installedVersion(spec)` returns the manifest version, `"legacy"` for bundles extracted by older APKs (sentinels present, no `.bundle-version`; an update is offered), or null. `isMsfInstalled()` = sentinels (`ruby/bin/ruby`, `msf/msfconsole`) + manifest or legacy. Paths consumed by runners:

- `toolsPath` → `filesDir/tools/` (contains `bin/nmap`, `bin/hydra`, `bin/ettercap`, `bin/tcpdump`, `bin/arpspoof`, `lib/`, `share/`, `etc/ettercap/etter.conf`)
- `rubyPath` → `filesDir/ruby/` (`bin/ruby`, `lib/libpq.so.5`, stdlib)
- `msfPath` → `filesDir/msf/` (`msfconsole`, `msfrpcd`, `vendor/bundle`)
- `msfHomePath` → `filesDir/msf-home/`: `HOME` of the root `msfrpcd`, so `~/.msf4` (user data, root-owned) survives bundle swaps. An old `ruby/.msf4` is migrated once (`su cp -a` + `rm -rf`) by `MsfDaemon`.

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
- Assets ending in `.tar.gz.bin` are stored uncompressed (`androidResources.noCompress`; aapt matches name suffixes, so `.tar.gz` alone never matched) — keep that exemption when adding similar blobs.
- App is Italian-leaning in comments/docs but code identifiers are English; keep new code English.
