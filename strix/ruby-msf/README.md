# Ruby + Metasploit Framework per Android ARM64

Cross-compilazione di Ruby 3.3.6 e Metasploit Framework 6.4.x per `aarch64-linux-android`.

## Cosa include

| Componente | Versione | Note |
|-----------|---------|------|
| Ruby | 3.3.6 | Cross-compilato per `aarch64-linux-android` con NDK r27c |
| Metasploit Framework | 6.4.x | 303 gem, 30+ ext native cross-compilate |
| OpenSSL | 3.2.1 | Statico, linkato in Ruby |
| SQLite3 | 3.45.1 | Per database MSF locale |
| PostgreSQL client | 16.2 | `libpq.so.5` per connessioni DB remote |
| Nokogiri | 1.18.10 | Con libxml2 2.12.9 + libxslt 1.1.42 |
| Pcaprub | 0.13.3 | Con libpcap 1.10.5 per cattura pacchetti |

## Build

```bash
./build.sh          # docker buildx multi-stage (ruby -> msf -> export), ~1-3 h
ALLOW_UNSIGNED=1 ./create-bundle.sh   # locale; in CI firma con BUNDLE_SIGNING_KEY
```

Versioni, checksum SHA256, tag+commit MSF e immagine base (con digest) sono in
`../versions.env` (unica fonte). Un solo `Dockerfile` multi-stage:
1. **ruby**: `01-ruby/build-ruby.sh` cross-compila Ruby + dipendenze (OpenSSL, zlib, libyaml, libffi)
2. **msf**: `02-msf/build-msf.sh` clona MSF al tag pinnato, bundle install, cross-compila le ext native, strip con `llvm-strip` dell'NDK
3. **export**: il risultato viene esportato in `output/` (svuotata a ogni build; override con `BUILD_OUTPUT`)

Qualsiasi errore (download, checksum, make, gem non cross-compilata) fa fallire la build.
`create-bundle.sh` produce `ruby-msf-bundle.tar.gz` + `ruby-msf-bundle.json` (manifest) + `.json.sig`
(ECDSA P-256, vedi `../scripts/sign-bundle.sh`).

## Struttura

```
ruby-msf/
├── build.sh              # Orchestratore host (docker buildx)
├── create-bundle.sh      # Crea asset per APK + manifest firmato
├── Dockerfile            # Multi-stage ruby -> msf -> export
├── 01-ruby/build-ruby.sh
└── 02-msf/build-msf.sh
```

## Sul device (dopo estrazione da APK)

```
filesDir/ruby/bin/ruby              # Ruby 3.3.6 ARM64
filesDir/ruby/lib/ruby/3.3.0/      # stdlib
filesDir/ruby/lib/libpq.so.5       # PostgreSQL client
filesDir/msf/                       # MSF 6.4 + vendor/bundle
filesDir/msf/msfrpcd                # RPC daemon (compat wrapper)
```

L'app Strix gestisce l'estrazione tramite `RubyExtractor.kt`.

## Requisiti

- Docker + ~15 GB spazio disco (host x86_64)
- Device ARM64 rootato, API 29+ (Android 10+)
- ~600 MB spazio su device
