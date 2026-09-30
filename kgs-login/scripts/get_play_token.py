"""Get a real Google Play AAS token from the burner account, then hand it to
apkeep so it can download eFootball DIRECTLY from Google Play, headless.

Why this exists: the game's remaining ~2 GB is Play Asset Delivery, and the
only two things that have ever satisfied it are a real Play Store on a device
Play recognises. apkeep -d google-play speaks to real Play (verified: it gets
Google's own responses) but demands a login; gpsoauth exchanges email+password
for the AAS token apkeep needs. That is the same sign-in the Play app performs
on a phone, done without one.

A number-match prompt ("tap 14") may fire on the account owner's phone during
the exchange. That is expected: it is the intended approval, and it is the same
prompt the user has already approved once for this burner account.

CREDENTIALS: read from the environment, never hardcoded. A previous revision
had the password written in this file, and a `git add -A` published it to a
public repository; the history was rewritten to purge it and the file now
refuses to run without the environment. The values live in the repo secrets
PEERLINK_GMAIL / PEERLINK_GPASS.

Usage (on a runner or any box with python3):
    PEERLINK_GMAIL=... PEERLINK_GPASS=... python3 get_play_token.py
then
    apkeep -a jp.konami.pesam -d google-play --aas-token "$(cat /tmp/aas_token.txt)" OUT
"""
import os
import subprocess
import sys

try:
    import gpsoauth
except ImportError:
    print("installing gpsoauth")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "--quiet", "gpsoauth"])
    import gpsoauth

EMAIL = os.environ.get("PEERLINK_GMAIL", "")
PASS = os.environ.get("PEERLINK_GPASS", "")
# A stable device id, 16 hex. gpsoauth requires one; this is not a secret and
# is not tied to any real hardware.
ANDROID_ID = os.environ.get("PEERLINK_ANDROID_ID", "3fd6a4b2c9e1f807")

if not EMAIL or not PASS:
    print("set PEERLINK_GMAIL and PEERLINK_GPASS in the environment first")
    sys.exit(1)

print("=== step 1: exchange email+password for a Google master token ===")
try:
    r = gpsoauth.perform_master_login(EMAIL, PASS, ANDROID_ID)
    print("response keys:", list(r.keys()))
    if "Token" not in r:
        print("no Token in response:", r)
        print("NeedsBrowser / Error=BadAuthentication means Google wants the")
        print("number-match approval on the account owner's phone.")
        sys.exit(1)
    master = r["Token"]
    print("MASTER TOKEN acquired (len %d)" % len(master))
except Exception as e:
    print("master login failed:", type(e).__name__, e)
    sys.exit(1)

print("=== step 2: exchange master token for an AAS token ===")
try:
    r2 = gpsoauth.exchange_token(EMAIL, master, ANDROID_ID, "com.android.vending")
    print("response keys:", list(r2.keys()))
    aas = r2.get("Auth") or r2.get("Token")
    if not aas:
        print("no AAS token:", r2)
        sys.exit(1)
    print("AAS TOKEN acquired (len %d)" % len(aas))
    with open("/tmp/aas_token.txt", "w") as f:
        f.write(aas)
    print("saved to /tmp/aas_token.txt (chmod it before sharing the box)")
except Exception as e:
    print("exchange failed:", type(e).__name__, e)
    sys.exit(1)
