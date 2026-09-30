#!/usr/bin/env bash
# Make the virtual phone trust a certificate authority of ours, so the game's
# TLS to Konami can be read in the clear.
#
# This replaces the memory scan, which cannot work: the serialised request
# exists for about a microsecond and no sampling interval can reliably catch
# one. Traffic is different -- every command that goes out is captured whole,
# every time, at full speed.
#
# Android distinguishes user-added CAs from system ones, and apps on modern
# Android do not trust the user set by default. The system set is what a normal
# build trusts, so the CA goes there. That requires the image to be writable and
# a reboot to pick it up, which is why this is explicit about failing loudly
# rather than pretending it worked.
#
# Usage:  bash setup_ca.sh <container> <outdir>
set -euo pipefail

CONTAINER="${1:?container name required}"
OUT="${2:?output directory required}"
mkdir -p "$OUT"

echo "=== generating a CA and a server key for pes22-game.cs.konami.net ==="
# The subject/SAN must match the host the game dials, or hostname verification
# fails and the game simply refuses to connect.
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
  -keyout "$OUT/ca.key" -out "$OUT/ca.crt" \
  -subj "/CN=kgs-intercept-ca" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null

openssl req -newkey rsa:2048 -nodes \
  -keyout "$OUT/leaf.key" -out "$OUT/leaf.csr" \
  -subj "/CN=pes22-game.cs.konami.net" 2>/dev/null

cat > "$OUT/ext.cnf" <<'EOF'
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:pes22-game.cs.konami.net,DNS:*.konami.net,DNS:konami.net,DNS:*.cs.konami.net,DNS:*.jp,DNS:localhost,IP:127.0.0.1
EOF

openssl x509 -req -in "$OUT/leaf.csr" -CA "$OUT/ca.crt" -CAkey "$OUT/ca.key" \
  -CAcreateserial -out "$OUT/leaf.crt" -days 3650 \
  -extfile "$OUT/ext.cnf" 2>/dev/null

cat "$OUT/leaf.crt" "$OUT/ca.crt" > "$OUT/chain.pem"
echo "wrote: $(ls "$OUT" | tr '\n' ' ')"

echo
echo "=== installing the CA into the SYSTEM trust store ==="
# Android requires the filename to be the hash of the subject's old
# colons, uppercased and suffixed .0 -- that is how cacerts lookup works.
HASH=$(openssl x509 -in "$OUT/ca.crt" -noout -subject_hash_old 2>/dev/null \
       || openssl x509 -in "$OUT/ca.crt" -noout -subject_hash)
echo "subject hash: $HASH"
sudo docker exec "$CONTAINER" mkdir -p /data/local/tmp/cacerts
sudo docker cp "$OUT/ca.crt" "$CONTAINER:/data/local/tmp/cacerts/${HASH}.0"

echo "--- system cacerts dir ---"
sudo docker exec "$CONTAINER" ls -ld /system/etc/security/cacerts
sudo docker exec "$CONTAINER" sh -c 'mount | grep -w /system'

if sudo docker exec "$CONTAINER" sh -c '[ -w /system/etc/security/cacerts ]'; then
  sudo docker exec "$CONTAINER" cp "/data/local/tmp/cacerts/${HASH}.0" \
    "/system/etc/security/cacerts/${HASH}.0"
  echo "INSTALLED into /system/etc/security/cacerts"
  # Android caches trust decisions per-process in some builds; a fresh boot of
  # the game process is enough here because the cert is read at process start.
  echo "note: verify with: ls /system/etc/security/cacerts/${HASH}.0"
else
  echo "=== /system is read-only: the CA could NOT be installed ==="
  echo "remount attempt:"
  sudo docker exec "$CONTAINER" sh -c 'mount -o remount,rw /system 2>&1 || true'
  if sudo docker exec "$CONTAINER" sh -c '[ -w /system/etc/security/cacerts ]'; then
    sudo docker exec "$CONTAINER" cp "/data/local/tmp/cacerts/${HASH}.0" \
      "/system/etc/security/cacerts/${HASH}.0"
    echo "INSTALLED after remount"
  else
    echo "FAILED to install; the CA is staged at /data/local/tmp/cacerts/${HASH}.0"
    echo "An alternative is the app-private store, which also needs a write, or"
    echo "patching the network stack. Report this and pick the next route."
    exit 1
  fi
fi
