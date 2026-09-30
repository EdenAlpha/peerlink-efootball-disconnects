#!/usr/bin/env bash
# Install our intercept CA into Waydroid's SYSTEM trust store.
#
# Waydroid runs as root, so (unlike redroid) the system store CAN be remounted
# writable. The cert goes in under BOTH the old and new subject hashes: the
# redroid run proved a cert filed under only one name is silently ignored.
#
# Usage:  bash setup_ca_waydroid.sh <outdir>
set -uo pipefail

OUT="${1:?outdir required}"
mkdir -p "$OUT"

openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
  -keyout "$OUT/ca.key" -out "$OUT/ca.crt" \
  -subj "/CN=kgs-intercept-ca" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
HOLD=$(openssl x509 -in "$OUT/ca.crt" -noout -subject_hash_old)
HNEW=$(openssl x509 -in "$OUT/ca.crt" -noout -subject_hash)
echo "ca-waydroid: old=$HOLD new=$HNEW"
echo "$HOLD $HNEW" > "$OUT/ca.hashes"

sudo waydroid shell mkdir -p /data/local/tmp/cacerts
sudo cp "$OUT/ca.crt" /var/lib/waydroid/data/local/tmp/cacerts/ca.crt
sudo waydroid shell sh -c "mount -o remount,rw /system 2>&1 || true; cp /data/local/tmp/cacerts/ca.crt /system/etc/security/cacerts/$HOLD.0 && cp /data/local/tmp/cacerts/ca.crt /system/etc/security/cacerts/$HNEW.0 && ls -la /system/etc/security/cacerts/$HOLD.0 /system/etc/security/cacerts/$HNEW.0 && echo CA-WAYDROID-INSTALLED"
