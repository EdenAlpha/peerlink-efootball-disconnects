#!/usr/bin/env bash
# Install our intercept CA into the ANDROID EMULATOR's SYSTEM trust store.
#
# On the emulator (unlike redroid) /system can be remounted via adb root, so
# the system store is writable. Filed under BOTH subject hashes - the redroid
# run proved a cert filed under only one name is silently ignored.
#
# Usage:  bash setup_ca_mac.sh <outdir>
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
echo "ca-mac: old=$HOLD new=$HNEW"
echo "$HOLD $HNEW" > "$OUT/ca.hashes"

adb root >/dev/null 2>&1 || true
sleep 2
adb remount >/dev/null 2>&1 || true
sleep 1
adb push "$OUT/ca.crt" /data/local/tmp/ca.crt 2>&1 | tail -1
adb shell sh -c "cp /data/local/tmp/ca.crt /system/etc/security/cacerts/$HOLD.0 && cp /data/local/tmp/ca.crt /system/etc/security/cacerts/$HNEW.0 && chmod 644 /system/etc/security/cacerts/$HOLD.0 /system/etc/security/cacerts/$HNEW.0 && ls -la /system/etc/security/cacerts/$HOLD.0 /system/etc/security/cacerts/$HNEW.0 && echo CA-MAC-INSTALLED" 2>&1 | tail -5
