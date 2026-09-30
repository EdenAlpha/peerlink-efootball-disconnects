#!/usr/bin/env bash
# Route the ANDROID EMULATOR's port 443 to our transparent proxy (mitmdump on
# 8080) on the macOS host, using pf (macOS's packet filter).
#
# On redroid this was an in-container iptables DNAT. On macOS the emulator is a
# QEMU process on the host, so the redirect is done with pf's rdr rule on the
# loopback/emulator traffic. If pf is unavailable or denied, we print it and
# continue - the session still drives the phone, only the plaintext capture is
# lost (screenshots still work).
#
# Usage:  bash pf_redirect_mac.sh
set -uo pipefail

PROXY_PORT=8080

echo "pf-mac: redirecting tcp/443 -> 127.0.0.1:$PROXY_PORT"

# anchor file: rdr rules for traffic the emulator generates
ANCHOR=/etc/pf.anchors/kgs
RULES="rdr pass on lo0 inet proto tcp from any to any port 443 -> 127.0.0.1 $PROXY_PORT"

# macOS pf needs root; the runner has sudo
if ! sudo mkdir -p /etc/pf.anchors 2>/dev/null; then
  echo "pf-mac: cannot write anchors (no sudo?) - redirect skipped"
  exit 1
fi
echo "$RULES" | sudo tee "$ANCHOR" >/dev/null

# include the anchor in pf.conf (idempotent)
if ! grep -q "kgs" /etc/pf.conf 2>/dev/null; then
  echo "anchor \"kgs\"" | sudo tee -a /etc/pf.conf >/dev/null
  echo "load anchor \"kgs\" from \"$ANCHOR\"" | sudo tee -a /etc/pf.conf >/dev/null
fi

if sudo pfctl -f /etc/pf.conf 2>&1 && sudo pfctl -e 2>&1; then
  echo "pf-mac: enabled"
  sudo pfctl -s nat 2>&1 | head -8
  echo "pf-mac: OK"
else
  echo "pf-mac: FAILED to enable (macOS SIP may block rdr on lo0)"
  exit 1
fi
