# eFootball target specification

## Identity

- **App:** eFootball™, KONAMI
- **Package:** `jp.konami.pesam`
- **Version to analyze:** latest available — at time of writing **11.0.1,
  build 311000101** (released 20 Aug 2026). If the store shows a newer
  version, analyze the newest and record its version/build in your report.
- **Source:** Google Play Store preferred; fallback APKMirror:
  `https://www.apkmirror.com/apk/konami/pes2017-pro-evolution-soccer/`
  (11.0.1 page lists arm64-v8a variants for Android 7.0+ and 10+).

## Size — read before downloading

- Store listing requires **≈ 3 GB free space** for full install.
- The small (~20–65 MB) download is only the base + splits; the game pulls
  down the bulk (native libs, assets) in-game.
- Full APKs of recent versions run **~800 MB up to ~3 GB**.
- **Your analysis is not complete until you have the native libraries.**
  Confirm all of the following before writing the verdict:
  1. `lib/arm64-v8a/` contains the game's `.so` files (network/match engine
     lives here, not in the Java/Kotlin layer).
  2. Total unpacked size is on the order of gigabytes, not megabytes.
  3. You can point to the networking code: search the `.so` files for
     `turn.konami.com`, `konami`, STUN/TURN/DTLS symbols, and timeout/error
     strings (see hunt list below).

## What to hunt inside the app

1. **Disconnect/timeout rules:** integer constants near 30/45/60/75/90/120/135
   seconds in match-network code; strings like "communication error",
   "connection lost", "failed to connect", "room", "reconnect", "timeout";
   the state machine that goes gameplay → loading → lobby.
2. **Server conversation mid-match:** HTTPS/QUIC endpoints called during
   gameplay (heartbeat, keepalive, result upload); intervals, timeouts, and
   failure behavior. Our `passthrough_capture.csv` shows the real
   counterparts — match domains/ports against the code.
3. **STUN/ICE handling:** how binding responses are validated; whether the
   reflexive address is reported to / checked by the server; any rejection of
   RFC1918 (10.x/192.168.x) or unexpected candidates.
4. **Relay policy:** references to `turn.konami.com`; relay-only vs
   peer-to-peer selection logic; what happens when media arrives on an
   unexpected path.
5. **Environment checks:** VPN interface detection (`tun`, `ppp`,
   `VpnService`), root/emulator/tamper checks anywhere near network setup.
6. **Logging:** log tags the game emits around disconnects — these same tags
   may appear in our `match_log.txt` context (logcat) if the game logs to
   logcat; check.

## Notes

- Do not redistribute the APK (KONAMI property). Analysis notes, string
  lists, offsets, and your written verdict belong in this repo; the binary
  itself does not.
- Our captured session ran against the then-current version (Sept 2026).
  If the newest version's network code differs from what our captures show,
  say so explicitly — the captures are ground truth for the killings, the
  newest binary is ground truth for the rules.
