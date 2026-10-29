#!/bin/bash
# Verify a detached OpenPGP signature against ONE pinned project keyring.
#   verify-sig.sh <keyring> <file> <sig-file>
# <keyring> names keys/<keyring>.asc + its line in keys/fingerprints. The keyring gpgv
# sees is built only from that file, and a signature counts only if gpgv reports it
# good (VALIDSIG) for a primary key listed in keys/fingerprints. Any BADSIG, no good
# signature, or a signature made after its key expired fails. Signatures by expired
# keys made before expiry are accepted (gpgv's EXPKEYSIG + KEYEXPIRED). Signatures by
# keys not in the keyring (e.g. a co-signer) are reported and ignored if a pinned one
# is good. Needs only gpgv + base64 (no gpg). Keys dir: $STRIX_KEYS_DIR or ./keys.
set -euo pipefail

[ $# -eq 3 ] || { echo "usage: $0 <keyring> <file> <sig-file>" >&2; exit 2; }
name=$1 file=$2 sig=$3
keys_dir=${STRIX_KEYS_DIR:-"$(dirname "$(readlink -f "$0")")/keys"}
asc="${keys_dir}/${name}.asc"
err() { echo "SIGNATURE ERROR ($name, $(basename "$file")): $*" >&2; exit 1; }

[ -f "$asc" ] || err "no key file $asc"
read -r -a pinned < <(awk -v n="$name" '$1==n { $1=""; print; exit }' "${keys_dir}/fingerprints")
[ "${#pinned[@]}" -gt 0 ] || err "no pinned fingerprint for '$name' in ${keys_dir}/fingerprints"
[ -s "$sig" ] || err "missing/empty signature file"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
# Dearmor (every block): drop armor lines, header lines up to the blank line, CRC line.
awk '/^-----BEGIN PGP PUBLIC KEY BLOCK-----/ { inb=1; hdr=1; next }
     /^-----END PGP PUBLIC KEY BLOCK-----/   { inb=0; next }
     inb && hdr { if ($0 ~ /^[ \t\r]*$/) hdr=0; next }
     inb && /^=/ { next }
     inb { print }' "$asc" | base64 -d > "$tmp/keyring.gpg" || err "cannot dearmor $asc"
[ -s "$tmp/keyring.gpg" ] || err "empty keyring from $asc"

rc=0
gpgv --keyring "$tmp/keyring.gpg" --status-fd 3 "$sig" "$file" 3> "$tmp/status" 2> "$tmp/log" || rc=$?

grep -q '^\[GNUPG:\] BADSIG ' "$tmp/status" && { cat "$tmp/log" >&2; err "BAD signature"; }
# Per signature (NEWSIG block): "<primary fpr> <sig timestamp> <key expiry or 0>"
good=""
while read -r primary sig_ts exp_ts; do
  pin=""
  for fp in "${pinned[@]}"; do [ "$primary" = "$fp" ] && pin=$fp; done
  [ -n "$pin" ] || { cat "$tmp/log" >&2; err "good signature by unpinned key $primary"; }
  # KEYEXPIRED: the signing key has expired since; the signature must predate that
  [ "$exp_ts" -eq 0 ] || [ "$sig_ts" -lt "$exp_ts" ] \
    || err "signature ($sig_ts) made after key $primary expired ($exp_ts)"
  good=$pin
done < <(awk '$2=="NEWSIG" { e=0 } $2=="KEYEXPIRED" { e=$3 }
              $2=="VALIDSIG" { print $12, $5, e+0 }' "$tmp/status")

if [ -z "$good" ]; then
  cat "$tmp/log" >&2
  err "no good signature by a pinned key (${pinned[*]}); if upstream changed its signing key, verify the new key at the official source and pin it in strix/scripts/keys/"
fi
if [ "$rc" -ne 0 ]; then
  # Only acceptable failure: extra signatures by keys we don't carry
  if grep -qvE '^\[GNUPG:\] (NEWSIG|KEY_CONSIDERED|SIG_ID|GOODSIG|EXPKEYSIG|VALIDSIG|KEYEXPIRED|TRUST_UNDEFINED|ERRSIG|NO_PUBKEY|PLAINTEXT|NOTATION_|POLICY_URL|VERIFICATION_COMPLIANCE_MODE)' "$tmp/status"; then
    cat "$tmp/log" >&2; err "gpgv failed (exit $rc)"
  fi
  echo "note: ignored signature(s) by keys not pinned for $name: $(awk '$2=="NO_PUBKEY"{printf "%s ", $3}' "$tmp/status")"
fi
echo "signature OK: $(basename "$file") signed by pinned $name key $good"
