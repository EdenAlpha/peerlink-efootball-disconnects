# PeerLink × eFootball disconnect investigation

## Mission (read this first)

Two phones play an eFootball **friend match** against each other while both run
PeerLink (this repo's `peerlink-code/` folder). Mid-match, **both phones freeze
at the same second**, the game shows a loading screen, and both get kicked back
to the Match Room lobby. This happened **3 times in one session**, then a later
match on the same build ran 10 clean minutes to full time.

Months of packet-level forensics (see `FINDINGS_SO_FAR.md`) have **exonerated
PeerLink's packet path**: the tunnel carries every packet, nothing is lost,
nothing is rebound, no timer in our code can freeze both phones symmetrically.
The remaining suspect is **the game itself**: something in eFootball's
connection rules — its conversation with the Konami server, its timeouts, its
validation of the network it sees — is deciding to kill the match.

**Your job: download the eFootball app, dig deep into it (APK + native
libraries + network behavior), and write the "constitution of the connection":**
what the game allows, what it forbids, and exactly which rule our setup is
tripping.

## What to download

- **App:** eFootball™ by KONAMI, package `jp.konami.pesam`
- **Version:** latest — at time of writing **11.0.1 (build 311000101)**,
  released 20 Aug 2026. If a newer version exists, use the newest, but note
  the version number in your report.
- **Where:** Google Play Store, or APKMirror
  (`apkmirror.com/apk/konami/pes2017-pro-evolution-soccer/`).
- **Size warning:** the store listing says ~3 GB free space is needed. The
  APKMirror "bundle" (~60 MB base + splits) downloads the rest in-game; full
  APKs run **~800 MB–3 GB**. Do NOT use a 20 MB stub and assume you have the
  whole game — the native match/network libraries download as extra data.
  Verify you have the native `.so` files (see `EFOOTBALL_TARGET.md`) before
  concluding anything.

## The setup you must understand

```
Phone A "Elijah" (hotspot owner, 10.57.220.34, interface ap0)
   ├── runs eFootball + PeerLink
   ├── shares a WiFi hotspot; Phone B joins it
   └── talks to Konami servers over mobile data (passthrough, untouched)

Phone B "Tiamant" (hotspot client, 10.57.220.5, interface wlan0)
   ├── runs eFootball + PeerLink
   └── talks to Konami servers over the hotspot's mobile data (passthrough)

Game traffic phone↔phone goes through PeerLink's encrypted tunnel.
Internet traffic game↔Konami goes around it (passthrough, recorded).
```

How the two phones found each other: normal eFootball friend-match flow
(Match Room, Room 1489-3073 in the captures). PeerLink does not touch
matchmaking — it only carries the peer-to-peer packets after the match starts.

Read `PEERLINK_ARCHITECTURE.md` for exactly what PeerLink does to packets
(especially **fabricated STUN responses** — prime suspect #1, see below).

## Prime suspects (game-side hypotheses to prove or kill)

1. **Fabricated-IP detection.** PeerLink answers the game's STUN binding
   requests with locally-made responses (see `StunFabricator.kt`), so the game
   believes its public address is something on our tunnel. If the game (or the
   Konami server) cross-checks this address against the address the server
   actually sees, the mismatch could look like spoofing/tampering → the server
   orders a disconnect. *Look for: server address validation, mismatch errors,
   "illegal" / tamper strings, attestation calls.*
2. **Server heartbeat during the match.** The game talks to Konami servers
   even mid-match (room keepalive, result reporting). If a heartbeat fails or
   times out — e.g. because the phone's route changed under the hotspot — the
   game may abort the match. *Look for: HTTPS/QUIC heartbeat intervals,
   timeout constants, retry counts, and what happens on heartbeat failure.*
3. **P2P timeout rules.** How many seconds of missing/delayed peer packets
   before the game freezes, shows loading, and quits to lobby? Our stalls last
   45–78 s. *Look for: timeout constants (search for 30/45/60/90/120/135 s),
   "communication error" / reconnection dialogs, freeze-then-lobby state
   machine.*
4. **Relay/TURN expectations.** The game uses `turn.konami.com`. PeerLink
   deliberately never blocks it. But if the game *expects* media via relay and
   instead sees direct-looking LAN traffic (10.57.220.x), it may distrust the
   path. *Look for: ICE candidate filtering, relay-only enforcement, LAN
   candidate rejection.*
5. **VPN/tunnel detection.** PeerLink is a VPN app. Some games refuse to run
   matches over VPN interfaces or treat them as cheating tools. *Look for: VPN
   interface checks (`tun0`, `ppp`, `VpnService`), emulator/root/VPN strings
   near network code.*
6. **NAT-type / port symmetry checks.** Both phones sit behind unusual NAT
   (hotspot + VPN). If the game grades the NAT and rejects symmetric/unknown
   types mid-match, that is our killer. *Look for: NAT classification code.*

## Evidence you must explain

In `captures/match-2026-09-26/` (exports from both phones, same session):

- 3 stalls at ≈ **02:34:48, 02:37:15, 02:45:53** (45–78 s each), both phones
  in the same second. Game packet rate collapses 27→0 pps; STUN and tunnel
  keepalives continue underneath; then both phones show loading screens and
  land in the lobby.
- Full-byte internet-side traffic (`passthrough_capture.csv`) — every packet
  the game exchanged with Konami servers around the stalls. **The
  game↔server conversation at the moment of death is in here.**
- Kernel-timestamped per-packet trace (`udp_trace.csv`) — proves peer packets
  flowed until the game itself stopped sending.
- Screenshots (`score_shots/`) incl. lobby + loading screens during stalls.

Your report must map each stall to a trigger: quote the exact packet(s),
timeout, or server message that precede it, and cite the game code/string that
gives that trigger its meaning.

## Deliverable

A `VERDICT.md` in this repo answering, with evidence quotes:

1. Which exact game/server rule kills our matches (string, constant, or
   packet sequence — not a guess).
2. What in PeerLink's setup trips that rule.
3. The smallest change (game-side impossible; so: network-setup-side or
   PeerLink-side) that would stop tripping it.
4. Anything you disproved along the way.

## Ground rules

- The captures contain real IP addresses (phone LAN + carrier IPs). They are
  here for forensics, not for sharing elsewhere.
- PeerLink is open source (MIT-style, this repo). eFootball is KONAMI's
  property — analyze, don't redistribute the APK.
