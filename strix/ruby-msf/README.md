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
./build.sh          # Docker pipeline (~30-45 min)
./create-bundle.sh  # crea ruby-msf-bundle.tar.gz.bin per APK assets
```

Due stage Docker in sequenza:
1. **01-ruby**: Cross-compila Ruby 3.3.6 + dipendenze (OpenSSL, zlib, libyaml, libffi)
2. **02-msf**: Scarica MSF, bundle install, cross-compila tutte le ext native

Output in `/tmp/ruby-android-output/`.

## Struttura

```
ruby-msf/
├── build.sh              # Orchestratore
├── create-bundle.sh      # Crea asset per APK
├── 01-ruby/
│   ├── Dockerfile
│   └── build-ruby.sh
└── 02-msf/
    ├── Dockerfile
    └── build-msf.sh
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
