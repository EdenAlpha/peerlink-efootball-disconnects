# Findings so far (what months of forensics already proved)

Session: 26 Sept 2026, ~02:24–02:58 phone-local time. Two phones, PeerLink
build `4940264`. Evidence: `captures/match-2026-09-26/`.

- `z1-tiamant-client/` — Phone B "Tiamant", hotspot client, 10.57.220.5
  (wlan0). 192 screenshots.
- `z2-elijah-hotspot-owner/` — Phone A "Elijah", hotspot owner,
  10.57.220.34 (ap0). 192 screenshots.

Each folder: `manifest.txt`, `match_log.txt` (full session log),
`passthrough_capture.csv` (full-byte internet-side traffic + event markers),
`udp_trace.csv` (kernel-timestamped per-packet ring, last ~216 s),
`score_shots/` (screenshots).

## The three disconnects (the thing to explain)

| # | Stall start | Length | Signature |
|---|---|---|---|
| 1 | ≈ 02:34:48 | ~75 s | Game pps 27→0 both phones, same second |
| 2 | ≈ 02:37:15 | ~78 s | Same |
| 3 | ≈ 02:45:53 | ~47 s | Same; after 6 stall-free minutes |

During every stall: the game's 54-byte warning burst fires first, then
screenshots stop mattering — z1 shows Match Room lobby (Room 1489-3073) then a
loading-tip screen; z2 shows black loading screens. STUN, bridge keepalives
and tunnel keepalives continue underneath the whole time. After stall 3 the
phones re-match and play a clean 10-minute match to FULL_TIME on the same
build.

Paired `0pps_cliff` detector events: 6, spaced ~21 s apart (detector artifact
of the two phones polling, not a cause).

## Exonerated (do not re-investigate without new evidence)

1. **Packet path / loss.** Trace sequence numbers: zero gaps, zero reorders
   across ~11,000 packets per phone. Tunnel carried 76,131 packets in the
   session.
2. **PeerLink code freezing.** Kotlin WiFi/connection files + full native
   backend audited: no timer/backoff above seconds on the datapath; only
   mid-match socket toucher is the 10 s path monitor, and logs show **zero**
   rebinds mid-match on both phones.
3. **Screenshots/capture cost.** Capture bursts fire AFTER the game's warning
   burst in all 3 stalls; ~20 captures total, only 3 followed by stalls; zero
   captures 02:31–02:33, 02:39–02:44, 02:48–02:55. PRIME polling: 470
   polls, zero errors, steady ~4 s cadence through healthy and stall periods.
4. **Wrong-IP leak as cause.** 16 probe packets (11 sent + 5 replies) from z1
   to z2's real cell IP `10.218.228.85:46839` (76 B). Bursts land 45–78 s
   AFTER each stall starts (02:30:00 kickoff, 02:36:03, 02:38:33, 02:46:40)
   and never during healthy play → **symptom** (game re-probing after the
   stall), not trigger. (Side note: our TX-guard rule that should have
   stopped them was found unarmed — `lastTunnelActivityMs` never set in
   bridge mode, `TunnelAgeMs=-1` all match. A PeerLink bug, but downstream of
   the stalls, not their cause.)
5. **Blocking Konami traffic.** Counters all zero: `RelayBlocked=
   BypassBlocked=TurnRelayBlocked=TurnIps=0`. DTLS to `turn.konami.com`, DNS,
   QUIC/443 all untouched.

## Narrowed to (where the game-side investigation takes over)

- Both phones stall in the **same second** → a shared trigger: either the
  shared WiFi radio, or **the game's own sync/pause routine deciding to quit**
  (e.g. on a server message, a failed heartbeat, or a validation trip).
- The 16 post-stall probes to the real cell IP show the game, once stalled,
  distrusts the path it was given — consistent with the game noticing its
  network reality differs from what it was told (cf. fabricated STUN).
- Later clean 10-minute match proves the setup *can* work — the killer is
  conditional, not structural. Find the condition.

## Jitter side-finding (context, not the disconnect)

Same traces show 60–177 ms delivery clumps (~118 in ~3.5 min, asymmetric
toward the client) plus ~13/131 pipeline-made 60–90 ms gaps from reader-thread
wake latency. Markers verified against source (`peerlink_backend.cpp`):
kernel arrival = real OS socket timestamp, TUN-write = handoff to game, same
clock. Radio-side clumping dominates; VPN layer contributes ~10%.

## Exact anchors for cross-referencing

- Tunnel packet counter freezes at 76,131 by 02:56:46.
- Match-room lobby screenshot: z1 `shot_0460`; loading-tip: z1 `shot_0493`;
  z2 loading screens: `shot_0006`, `shot_0010`.
- Trace header gives `gameplayStartNs`, per-packet kernel/user/enqueue/write
  stamps; `passthrough_capture.csv` carries hex payloads of all
  game↔internet traffic with event markers — **start the server-side autopsy
  there.**
