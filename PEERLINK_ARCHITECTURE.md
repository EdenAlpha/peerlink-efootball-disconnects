# What PeerLink does (for the investigating AI)

PeerLink source snapshot: `peerlink-code/`, commit `1ac227c` (main branch,
Sept 2026). Android app (Kotlin) + native core (C++, `app/src/main/jni/`).

## One-sentence version

PeerLink is a VPN app that carries game packets between two nearby phones over
an encrypted tunnel, while letting each phone's internet traffic (to Konami
servers etc.) pass through untouched.

## How it is built

| Piece | File(s) | Role |
|---|---|---|
| VPN entry point | `service/PeerLinkVpnService.kt` | Android VpnService. Reads packets from the TUN device, hands game packets to the tunnel, passes internet packets back out. Holds partial wake lock + low-latency WiFi lock. |
| Tunnel engine (Kotlin side) | `tunnel/TunnelEngine.kt` | Routing rules: what counts as game traffic, what is passthrough, guard rules that drop stray packets. |
| Native backend | `jni/peerlink_backend.cpp` (~3,900 lines) | The real datapath: peer socket TX/RX, keepalives, TUN inject queue, per-packet trace writer, drop counters. TX thread runs at urgent-display priority. |
| **STUN fabricator** | `tunnel/StunFabricator.kt` | **Answers the game's STUN binding requests locally** so the game learns a peer address on our tunnel instead of doing real NAT discovery. Prime suspect #1 — see README. |
| Passthrough bridge | `tunnel/PassthroughBridgeEngine.kt`, `PassthroughRecorder.kt` | Forwards + records non-game traffic (game↔Konami server) byte-for-byte. This recorder produced `passthrough_capture.csv`. |
| Match automation | `service/MatchAutomationEngine.kt` | Watches the match (screenshots, score OCR, timers). Constants: `DISCONNECT_CONFIRM_MS=135000`, `SUSTAINED_ZERO_PPS_MS=90000` — our *detectors*, not causes. |
| Path monitor | `PeerLinkVpnService.kt` `refreshGameplayPath` / `rebindPeerSocket` (~lines 743–901) | Checks the peer path every 10 s. Logs prove it fired **zero times mid-match** in the captured session. |
| Jitter buffer | `tunnel/JitterBuffer.kt` | Exists in code but was **not active** in the captured session (delivery ran in blocking mode). |
| Whistle / UI / pairing | `service/*`, `ui/*`, `network/*`, `godmode/*` | Sound effects, screens, hotspot pairing, discovery. Audited; none touch the mid-match socket. |

## What PeerLink does to a game packet (phone A → phone B)

1. Game sends UDP → TUN device → `PeerLinkVpnService` reads it.
2. Native backend classifies it as game traffic (UDP ports the game uses
   toward the peer's tunnel address).
3. Packet is wrapped with a small tunnel diagnostic header (sequence number,
   sender id, send timestamp) and encrypted/sent over the peer UDP socket
   (WiFi: hotspot owner ↔ client, port negotiated at pairing).
4. Phone B's native backend unwraps it, records trace stamps, and writes it
   into B's TUN device → B's game receives it, believing it came from the peer
   directly.

## What PeerLink does to STUN (important)

When the game sends a STUN binding request (to discover its public address or
to check the peer path), `StunFabricator` crafts a binding **response locally**
with the tunnel's addresses, instead of letting it reach a real STUN server.
From the game's viewpoint, NAT discovery succeeds and the peer is reachable.
From the Konami server's viewpoint, this client never performed (or completed)
real reflexive discovery — a possible mismatch the server may punish.

Separately, PeerLink also sends its own real STUN probes on its own sockets
for path maintenance; these are unrelated to the game's STUN.

## What PeerLink deliberately does NOT do

- Never blocks DNS, QUIC/443, DTLS to `turn.konami.com`, or any keepalive.
  Blocked-packet counters exist in code and read **zero** for all of these in
  the captured session (`RelayBlocked=BypassBlocked=TurnRelayBlocked=0`).
- Never rebinds the peer socket mid-match (proven zero by logs).
- Never modifies game payload bytes (headers added outside the payload).
- Never touches matchmaking/lobby/room signalling — only the peer path.

## Timers that exist (all ruled out as stall causes)

- 10 s gameplay-path monitor (would log + rebind; zero occurrences mid-match).
- Keepalive loop (seconds-scale; STUN/keepalives flowed *through* the stalls).
- `DISCONNECT_CONFIRM_MS=135000` / `SUSTAINED_ZERO_PPS_MS=90000` are our own
  *stall detectors* (they observe and log; they send nothing).
- Native code audit found no backoff/timer above a few seconds anywhere on the
  datapath. Nothing in this codebase can pause both phones for 45–78 s.

## Build / versions

- Snapshot commit `1ac227c` ("Whistle: fix no_system_context …"), HEAD of
  `main` at github.com/EdenAlpha/Peerlink-app, Sept 2026.
- The captured match ran on the parent build `4940264` (only whistle/logging
  differs; datapath identical).
- Full change history: `peerlink-code/PEERLINK_CHANGES.md`.
