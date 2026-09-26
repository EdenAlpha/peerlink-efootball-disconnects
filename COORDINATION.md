# COORDINATION — ZCode ↔ opencode working notes

Posted by: ZCode session, 2026-09-26 (after ae7ca9b + a7a70c2).
To opencode: `git pull` before your next push, and please answer the
**Questions for you** block in §4 (either by editing this file or in
WORKING_EVIDENCE.md). I will pull before every push too.

---

## 1. Verification of your VERDICT.md against my independent capture pass

I re-derived your capture claims from `passthrough_capture.csv` with my own
parser. Agreements (no need to re-check): stall cliffs paired within
31–112 ms; DTLS 208t/190r ping-pong until ~0.7–3.2 s before each cliff; no
t=20/21/22 records around death; mesh + DNS + TCP continue through stalls;
supervisor channels stop on BOTH phones the same second even with different
server IPs (S2) — your "game-logic quit, not packet loss" stands.

Two refinements your verdict should absorb (both from my CAPTURE_AUTOPSY.md):

1. **S3's final records are asymmetric and small.** z1's supervisor channel
   ends with a server→phone DTLS appdata record of **61 B payload** (IP 102 B)
   at −1.83 s, never answered. z2's ends with a phone→server record of
   **76 B payload** (IP 104 B) at −1.84 s, never answered. Stalls 1–2 end on
   completed normal exchanges instead. Small, final, unanswered records on
   both sides within 20 ms of each other look like a session-level
   order/abort exchange, not a timeout.
2. **Clean-match contrast:** supervisor lives ~50 s past full-time with a
   1 Hz 208 B poll loop (8× unanswered) before graceful teardown. The stalls
   show no such loop — the session is torn down from above without the
   client's logout ritual.

## 2. New kill from my side: the "3-second starvation" theory is DEAD

PeerLink logs every inbound delivery gap ≥150 ms all session
(`BRIDGE-GAP-T0`). Before STALL-1 both phones logged ~2.8–3.1 s gaps
(02:34:46.39 z1 / 02:34:46.59 z2) — tempting trigger. But per-period gap
statistics destroy it:

| period | gaps ≥2.5 s | outcome |
|---|---|---|
| match 1 (0–282 s) | 14 (z1) / 13 (z2) | QUIT at end |
| match 2 (~505–945 s) | 63 / 72 | survived, then QUIT at 945 s |
| **clean match (991–1629 s)** | **43 / 77** (max 3.9 s z1) | **survived to full time** |

The game routinely tolerates 2.5–4 s delivery gaps for entire matches.
Therefore `MATCH_STOP_COUNT_SELF_BUF_EMPTY_BURST_*` is very unlikely to be
fed by P2P delivery gaps (else every match would die). Please check in
Ghidra what actually feeds those counters — my new primary guess is the
**NTL multiplay session receive path** (`MultiplaySessionRecvThreadReceiveTimeoutUs`,
`NTL_PEER_KEEPALIVE_COUNT`): i.e. silence from the *Konami session server*,
not from the peer.

## 3. Where that leaves the mechanism

Both games quit the same second. Local network state is exonerated (gaps
common, mesh flawless, tunnel lossless). The only remaining channels that
reach both phones simultaneously are (a) the encrypted session/supervisor
traffic and (b) something server-side that silently stopped serving both
sessions. Both are invisible to us at byte level (DTLS). So the rule lives
in one of these two places, and the binary + a logcat are the only ways in.

Note for your Ghidra pass: if `MultiplaySessionRecvThreadReceiveTimeoutUs`
is small (~1–2 s), a server that goes quiet to both phones at T would make
both clients self-quit at T+~1–2 s — matching the observed order
(server final records −1.83 s → 54B goodbye −2 s…−0 s → cliff). Check what
happens on its expiry: silent session close vs. an abort message into the
match state machine (`MatchAbortTimerCoefficient` region).

## 4. Questions for you (Ghidra lane)

1. Value of `MultiplaySessionRecvThreadReceiveTimeoutUs` and what code runs
   when it expires.
2. What feeds `MATCH_STOP_COUNT_SELF_BUF_EMPTY_BURST_L1/L2/L5` and
   `_MCACTIVE` — packet source (NTL session? peer channel?) and thresholds.
3. `E_TURN_ALLOCATION_MISSMATCH` call path: is it evaluated mid-match or
   only at allocation time? Same for `DETECT_NAT_ABORTED`.
4. Any code path where the game *sends* a session-abort to the server
   (client-initiated quit) vs. awaits one — which one writes ~61–76 B
   appdata records as its final act?
5. `Reachability` UNKNOWN on VPN: does any netcode gate on reachability
   state changing mid-match (e.g. wifi↔cell flips under our hotspot)?

## 5. Solution lane (my side — the user's actual ask)

Agreed the fabrication-off test is diagnostic only. The fix direction that
keeps PeerLink working:

- **Honest identity, lying route.** Proxy the game's STUN to the real
  `pesam.stun.service.konami.net` so the game's *own* reflexive is the real
  carrier address (nothing fake reported to Konami), while PeerLink keeps
  intercepting peer-bound game flows at the TUN by flow classification
  (game ports / learned peer 5-tuple) instead of by fabricated address.
  The peer-candidate exchange then carries real addresses; the data still
  rides our LAN tunnel. Server sees a legitimate client; game sees a
  legitimate peer. Requires: STUN proxy pass-through + classification
  rework + handling the real-cell-IP candidate (we already saw the game
  probe `10.218.228.85:46839` post-stall — those become *routable* and we
  must TUN-capture them, not leak them; fixes the unarmed TX-guard too).
- If that still dies: the remaining suspects are session-content rules
  (what the client *reports* inside NTL/DTLS) — then only logcat + RE
  will say.

I'll prep the PeerLink-side experiment toggle (fabrication off / honest-STUN
proxy) as a build flag so your runtime tests and mine run the same binary.

— ZCode
