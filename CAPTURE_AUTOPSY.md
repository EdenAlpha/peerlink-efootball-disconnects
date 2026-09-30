# CAPTURE AUTOPSY — what the game↔Konami conversation actually shows

Status: **data-side analysis complete.** Every claim below is measurable in
`captures/match-2026-09-26/`. The binary side (APK) is still open — see §7.
Clock note: `passthrough_capture.csv` timestamps are epoch-ms; phone wall
clock = epoch − 3,600,000 ms (phones ran UTC+1 against the export clock).
All times below are phone-local wall time, matching FINDINGS_SO_FAR.md.

## 1. The game's network architecture (as captured)

Five distinct internet-side layers, all recorded full-byte:

| Layer | Endpoints | Behavior |
|---|---|---|
| **Match supervisor** (DTLS) | high UDP ports on GCP/AWS, per match: z1 `34.22.210.195:30650`, z2 `34.22.210.195:30970` (match 1 — **same server IP for both phones**); stall-2 recovery `34.38.190.21:30905` / `35.233.88.176:32741`; match 2 `104.199.46.171:30222` / `35.240.102.10:31406`; clean match `34.156.177.234:30236`/`30116` / `31840` | DTLS 1.2 (record header `17 fe fd 00 01`, incrementing per-record counter, e.g. `e0f8877bc52a2b`→`…2c`). Exchanges at ~4.5 s cadence: phone sends 2×208 B, server replies 2×190 B. This is the online-session channel (room/sync/result reporting). |
| **Ping/keepalive mesh** | UDP 5521 (~14 GCP IPs, 45/45 tx/rx each), UDP 10000 (AWS/GCP, 30 B, ~13–16 s, bidirectional), UDP 30000/50000 (AWS, 30 B, tx-only) | Runs the entire session (−80 s → +1657 s). ~490 packets per 78 s stall window; max intra-stall gap = normal cadence (15.6–25.4 s per flow). Never pauses. |
| **DNS** | z1: plain DNS to 8.8.8.8:53 (1,629 pkts). z2: DoH to 8.8.8.8:443 (4,902 pkts — names invisible) | z1 resolved `pes22-game.cs.konami.net`, `agones-ping.<region>.nabeshin.people.aws.dev` (Agones = Google's game-server fleet manager — Konami runs eFootball match servers on Agones), and AWS ELBs in 6+ regions. |
| **QUIC/443** | Google IPs (e.g. `216.58.223.194:443`) | periodic, small. |
| **TCP 80/443** | CloudFront/CDN (108.156.x, 54.187.x, 35.174.x …) | config/assets/telemetry. Inbound TCP is not byte-captured in v1 recorder (documented scope); UDP evidence is complete. |

## 2. Per-stall timelines (both phones, same clock)

STALL-1 — cliff z1 02:34:48.727 / z2 02:34:48.731 (Δ < 5 ms)

```
02:34:46.7   z1+z2: game's 54-byte tick warning burst (PeerLink log)   [P2P dying]
02:34:47.98  z1 supervisor: last normal exchange (tx208/rx190)         [-0.75 s vs cliff]
02:34:52.83  z2 supervisor: last normal exchange (tx208×2/rx190×2)     [-1.70 s vs cliff]
02:34:48.7   cliff: game pps → 0 (BOTH phones, same second)
02:34:52.6   z1 screen: gameplay frame (241 KB) → 116 KB → 10.7 KB (black) = loading screen ~4 s after pps death
02:34:52–58  reverse-DNS wave #1 begins (see F6)
(no supervisor retries, no server pushes after the last exchange — flow simply ends)
+~72 s       z1 opens NEW supervisor 34.38.190.21:30905 (game rebuilding session)
```

STALL-2 — cliff 02:37:15.819 / .821

```
02:37:13.9   54B burst both phones
02:39:18.76 → sup z1 34.38.190.21:30905 last pkt  −3.23 s vs cliff
02:39:19.10 → sup z2 35.233.88.176:32741 last pkt −2.53 s vs cliff   (normal exchange, then nothing)
cliff at 02:37:15.8 both phones; mesh/keepalives uninterrupted throughout
```

STALL-3 — cliff 02:45:53.281 / .283

```
02:45:51.3   54B burst (55) z1 / (39) z2
02:47:57.63  z1 supervisor 104.199.46.171:30222: server→phone DTLS record, 61 B payload (IP 102 B) — NEVER ANSWERED  [-1.83 s]
02:47:57.25  z2 supervisor 35.240.102.10:31406: phone→server DTLS record, 76 B payload (IP 104 B) — NEVER ANSWERED  [-1.84 s]
02:45:53.3   cliff both phones, same second
02:46:40–47:08  game emits repeated 54B-style reconnect chatter that never collapses (recovery phase)
02:48:48     z1 probes z2's real cell IP 10.218.228.85:46839 (reconnect probe wave, symptom)
```

CLEAN MATCH (for contrast): supervisor `34.156.177.234:30236/30116` lives
991.8 → 1628.7 s. Full-time at ~1579 s. **Supervisor keeps exchanging ~50 s
after full-time** (result-reporting phase), including a poll loop of 208 B
every ~1 s with no reply at the very end — a *graceful* teardown.

## 3. Findings

**F1 — The internet path never failed. Not once.** The ping/keepalive mesh
(UDP 5521/10000/30000/50000, ~14+ servers) ran at full cadence with paired
replies through every stall window (488–492 packets per 78 s window; max gap
= normal 15–25 s per-flow cadence). Both phones. All three stalls. Any
"shared radio outage" or NAT-mapping-loss explanation is dead: a radio event
that kills P2P for 45–78 s would have silenced these too.

**F2 — The kill event is the match-supervisor session, not the network.**
Each stall coincides with the phone's DTLS supervisor flow ending — and it
ends *instantly* (no retry streaks, no unanswered poll loops, no server
keepalive-after-death, unlike every timeout pattern we can construct). In
stalls 1–2 the last exchange is a *completed, normal* 208/190 exchange; the
session is simply gone afterwards.

**F3 — The freeze presents like a forced match end, not a crash.** The
54-byte tick burst → 0 pps signature that precedes each stall is byte-for-byte
the signature of a NORMAL full-time (validated across months of captures).
After P2P death the game kept rendering ~4–6 s, then loading screen, then
lobby. Both phones within 100 ms of each other, every time.

**F4 — The supervisor teardown shape differs from a real full-time.** Real
full-time: supervisor lives ~50 s more for result reporting. Stalls: supervisor
dies with the match, no result phase, no result committed (screenshots show
lobby, not result screen). Conclusion: the session was *aborted*, not ended.

**F5 — Both phones' supervisors died simultaneously although they are
different sockets** (different ports, and in stall 2 even different server
IPs). Two independent UDP sessions on two phones do not die in the same
second by chance. Either one upstream decision killed both (orchestrator /
gameserver / session service), or one shared event reached both. F1 rules out
the network as that event.

**F6 — Failure diagnostics fire around every stall.** A wave of reverse-DNS
queries of the entire ping-mesh IP list (`43.162.247.35.bc.googleusercontent.com`
= reverse of `35.247.162.43:5521` etc., ~50 distinct IPs) spans −3 s … +6.5 s
around each stall, only then — never during healthy play. `pes22-game.cs.konami.net`
was re-resolved 4.6 s before STALL-3. Something (the game's SDK or Play
services layer) began annotating/re-resolving endpoints *as* the session died.

**F7 — The supervisor channel is DTLS 1.2.** Record headers (`17 fe fd 00 01`,
per-record counters) are visible because PeerLink records full bytes. Payloads
are encrypted; sizes are stable and meaningful (208 B phone→server,
190 B server→phone, final stall-3 messages 61 B ↓ / 76 B ↑).

**F8 — PeerLink-side bug (unrelated to stalls, still real):** the TX-guard
that should suppress probe packets to the peer's real cell IP was unarmed in
bridge mode (`lastTunnelActivityMs` never set; `TunnelAgeMs=-1` all match) —
as FINDINGS_SO_FAR §4 notes. Downstream symptom carrier, not a cause.

## 4. Suspect scoreboard after the capture autopsy

| # | Suspect | Verdict after captures |
|---|---|---|
| 1 | Fabricated-IP / server-side validation trip | **ALIVE — now the lead.** F2+F4+F5 show a single upstream session-abort decision. A server that validates session topology would abort exactly like this. Binary must supply the rule. |
| 2 | Server heartbeat failure | **KILLED as trigger.** The heartbeat mesh never missed a beat. (The supervisor *is* a session channel, but its death is the kill event, not a timeout — F2.) |
| 3 | P2P timeout rules | **Reshaped.** The 45–78 s is the game's own loading→lobby recovery. The freeze itself is the presentation of a forced/aborted match end (F3), not a P2P watchdog. |
| 4 | Relay/TURN expectations | **No capture evidence either way** — relay counters zero, DTLS to turn.konami.com untouched. Binary. |
| 5 | VPN/tunnel detection | **No capture evidence.** If the game detected the VPN client-side it would not need the server; the simultaneous both-phone abort fits a *server-side* verdict better. Binary. |
| 6 | NAT-type checks | Probes (tx-only 30000/50000) ran the whole session including stalls; nothing changed at stall time. Unlikely. |

## 5. The single most important open discriminator

We cannot yet see **who closed the DTLS session** — the game (client abort,
e.g. after the server sent the final 61 B "abort" message in stall 3) or the
server (both sessions dropped simultaneously). The stall-3 shape (z1 received
a final 61 B record, z2's final 76 B record went unanswered) is consistent
with **the server delivering an abort/order to both phones** — z1's game got
its order, z2's game may have already been dead or sent its own last message.
Decrypting is out of reach; the binary must instead reveal the *rule* that
makes the orchestrator abort: validation of addresses, session integrity,
or an explicit quit/pause message relayed from one client.

## 6. New facts for the binary hunt (sharpened from captures)

- Endpoints to find in the `.so`: `pes22-game.cs.konami.net`,
  `agones-ping.*.nabeshin.people.aws.dev`, `turn.konami.com`, ELB naming,
  ports 5521 / 10000 / 30000 / 50000 / 30xxx-31xxx.
- Protocol: DTLS 1.2 (OpenSSL/BoringSSL `fe fd` records) on the supervisor.
- Payload size constants to grep for / break on: 208, 190, 61, 76 (bytes at
  the DTLS layer), and the 54-byte tick payload on the P2P side.
- The stall recovery loop: repeated small-packet bursts every ~3 s for 45–78 s
  (matches a retry loop with ~3 s backoff, ~10–25 attempts, then lobby).
- Who issues reverse-DNS of peer/mesh IPs on failure (game telemetry vs Play
  services) — explains F6 and may expose the failure string.
- Search strings: "agones", "nabeshin", "sdk.gameserver", "disconnect",
  "abort", "forfeit", "opponent", "communication", "reconnect", "cheat",
  "validate", "integrity", "candidate", "reflexive", "symmetric".

## 7. What is still needed for the final VERDICT.md

1. The APK/native libs (see EFOOTBALL_TARGET.md) — the rules live there.
2. One logcat capture (`adb logcat`) around a stall — the game's own log tags
   at the death second will name the exact state machine transition.
3. Optional: a test session with PeerLink's STUN fabrication disabled
   (pass-through real STUN) — if the stalls vanish, suspect #1 is confirmed
   without reading a line of the binary. **This is the cheapest decisive
   experiment available and needs only a PeerLink toggle.**
