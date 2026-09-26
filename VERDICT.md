# VERDICT — PeerLink × eFootball disconnects (evidence-only, 2026-09-26)

Target: `jp.konami.pesam` 11.0.1 (311000101), `lib/arm64-v8a/libUE4.so` 160,822,968B.
Captures: `captures/match-2026-09-26/` z1 (13,188 rows) + z2 (16,511 rows).

## 1. Which exact rule kills our matches

**Signature (quoted packets, all 3 stalls):**

- `match_log` both phones same second: `02:34:46.717 54B burst (20) -> Path A capture` then `02:34:48.727 Path A cliff confirmed (pps=0)`; S2 `02:37:13.901 (52)` -> `02:37:15.918`; S3 `02:45:51.387 (55)` -> `02:45:53.393`. Z1-Z2 cliff delta 31/99/112ms. `0pps_cliff` events `1790386488724 / 1790386635917 / 1790387153392`.
- Game P2P 27→0 (detector `GAMEPLAY_PPS_MIN..MAX`, `MatchAutomationEngine.kt:312`). The 54B burst is the game's own dying tick: uniform ~54B, 45 in ~1.1s field traces, threshold `PATH_A_MIN_BURST=6` (`MatchAutomationEngine.kt:36-43,98-101`).
- Game↔Konami DTLS (parsed records, all type 23 appdata, ver `fefd`=DTLS1.2, epoch 0001): e.g. S1 z1 `1790386487485 t 208B` / `1790386487970 r 190B`, then silence 750ms before cliff. Last 8 pre-stall are all `t=23`, zero `t=21` alert / `t=22` handshake / `t=20` CCS. Both phones stop DTLS to *different* servers same second (S2 z1 `34.38.190.21:30905`, z2 `35.233.88.176:32741`; S3 z1 `104.199.46.171:30222`, z2 `35.240.102.10:31406`). No server kill command on the wire.
- During 21s: zero game DTLS, only DNS `8.8.8.8:53`, TCP 443 (`54.187.87.37`, `32.184.206.158`, `44.255.249.99`, `108.156.x.x`), QUIC `8.8.8.8:443` (z2), len-30 `:5521` probes. STUN keepalives continue (`02:34:49.412 STUN[T7:Signal]`). Internet works, game stops. Screenshot `z2/.../shot_0006_OTHER.jpg` = black + eFootball logo (loading).

**Game strings giving this trigger meaning (libUE4.so file offsets):**

- `E_TURN_ALLOCATION_MISSMATCH` @10251944 (note upstream misspelling). TURN allocation path exists: `ALLOCATE_SUCCESS_RESPONSE`, `REFRESH_REQUEST`, `CHANNEL_BIND_REQUEST`, `SendStunMsg ... tid ... act` @10953544, `ERR_FAILED_STUNCHECK` (lobby create/join) @10213270, `CHECK_STUN_RTT_TIMEOUT/COMPLETE`.
- Match-stop counters: `MATCH_STOP_COUNT_SELF_BUF_EMPTY_BURST_L1/L2/L5`, `MATCH_STOP_COUNT_BUF_EMPTY_BURST_L1-L5` (+`_MCACTIVE`), `MATCH_STOP_MAX_ROLLING_COUNT_BUF_EMPTY_IV2_MCACTIVE` (27 hits) + `MatchAbortTimerCoefficient`, `LoadTimeoutMs`.
- NTL (Konami's own traversal, `cobra/NatTraversal/NTL/ntl/NtlHelper.cpp`): `CMD_GET_TURN_SERVER_LIST` → `CMD_SEND_TURN_ADDRESS_DATA` / `CMD_WATCH_TURN_ADDRESS_DATA` / `CMD_GET_TURN_ADDRESS_DATA`; `START_UDP_HOLE_PUNCHING_{PROGRESS,COMPLETE,ERROR,ABORTED}` + `ADVICE_CANCEL_HAIRPIN/CANCEL_LOCAL`; `ALLOC_TURN_PORT_{COMPLETE,ERROR,ABORTED,QUOTA_ERROR,AUTH_ERROR,ALLOCATION_MISSMATCH_ERROR}`; strategies `...P2pFullMeshWithTurn` vs `...P2pFullMeshTurnOnly`; `natType` reporting (`${"natType":0x%08x}`, `NATTYPE_PEER`, `TurnInitializedNatType`); `reflexive_address`/`reflexive_port`/`PEER_REFLEXIVE`/`RP_REFLEXIVE_ADDRESS` handling; `is_cheat_user`/`is_cheat` + `OnlineModeTaskCheckCheat.cpp`; `DETECT_NAT_ABORTED`; `FakeKeepAlive` warning. No ICE (`candidate` hits all ARKit FP, `ICE` all `ostringstream` FP) — NTL replaces ICE here.
- Reconnect/keepalive names: `TurnNetworkIoReconnectServerTimeWaitMs` @10251029, `TurnReconnectWaitTimeMs` @10487790, `NtlReconnectWaitTimeMs` @12200932, `NTL_PEER_KEEPALIVE_COUNT` @12121675, `KeepAliveTimerUs` @12120984, `MultiplaySessionRecvThreadReceiveTimeoutUs` @10251231, `LinkTimeoutUs`, `PingIntervalUs`, `EstablishedConnectionTimeoutUs`.
- Exact millisecond values are NOT in cleartext (hashed `FName` config, no Rd-matched ADRP+ADD xref; 0 stored VA pointers). They require Ghidra on the enum-indexed table around `0x75505a8` (error-code registration, `w2=0x17`, counters 1..9 to `[x8,#0x38c+]`) — listed as next step, not guessed here.

**Rule in one sentence:** the game's P2P sync (27pps) emits its own 54B goodbye then stops, and its DTLS appdata to Konami stops with no alert, on both phones the same second, while the OS network stays up — i.e. **game-logic quit, not packet loss**. The binary owns a TURN-allocation-mismatch error and buffer-empty match-stop counters that are the only coded quit paths fitting this signature; their numeric thresholds are still open (see §4).

## 2. What in PeerLink's setup trips that rule

- `tunnel/StunFabricator.kt:50-67` answers game STUN Binding Request (`0x0001`, magic `0x2112A442`) locally for 4 verified clusters, returns `cachedMyFabricatedIp:fabricatedPort` (`TunnelEngine.kt:2436-2444`, defaults `AppState.kt:96-101` `my=197.210.53.1 peer=197.210.53.2`, `FABRICATED_PUBLIC_IP_BASE=197.210.53`). Well-formed (`SOFTWARE TurnServer 0.7.2+03`, `FINGERPRINT`, `RESPONSE-ORIGIN 0x802B`, `0xF000` echo). From the game's view NAT succeeds and peer is public 197.x, not LAN 10.x.
- From the server's view this client never did real reflexive discovery to `pesam.stun.service.konami.net` (`35.76.243.83`, DNS-learned `match_log 02:28:41.431`, IPv6 `2406:da14:...`). The game reports/learns 197.x while its real path is `10.57.220.5/34` + carrier. Post-stall 16 probes (11 sent +5 replies) to real cell `10.218.228.85:46839`, landing 45–78s AFTER each stall, show the game once stalled distrusts the given path — consistent with noticing reality ≠ told address (cf. `E_TURN_ALLOCATION_MISSMATCH`).
- `turn.konami.com`: 0 hits in libUE4.so and 0 hits in all 37 APK splits (raw bytes). TURN address is dynamic via `ntl.service.konami.net` (z1 DNS x8 → 5x A incl `35.174.175.11`, seen TCP 443/80; `NTL_PEER_KEEPALIVE_COUNT`, `NtlReconnectWaitTimeMs`). PeerLink never blocks it (`RelayBlocked=BypassBlocked=TurnRelayBlocked=TurnIps=0`, DTLS/DNS/QUIC untouched, zero rebinds mid-match). So the mismatch surface is the fabricated reflexive, not blocked TURN.

## 3. Smallest change that would stop tripping it (diagnostic ≠ fix)

Game-side impossible. The §7.3 toggle (`fabricationEnabled=false`, branch `test/no-stun-fabrication`) is DIAGNOSTIC ONLY: with fabrication off the game sends P2P to real peer LAN (`10.57.220.x`), which misses `PacketParser.kt:218-226` RULE 1 (tunnels only `dest == peerFabricatedIp` 197.x) and falls to RULE 3 PASSTHROUGH — direct WiFi, tunnel blind, automation dead. A clean match on toggle proves suspect #1 but is not shippable. The shippable fix keeps the tunnel AND drops the lie:

**Honest-STUN + LAN-retarget (real fix):**
1. STUN passthrough (toggle false): game learns real srflx via `35.76.243.83:3478`, reports honest `reflexive_address` + `natType` (`${"natType":0x%08x}`, `NATTYPE_PEER`) to NTL/session service. No `ALLOC_TURN_PORT_ALLOCATION_MISSMATCH_ERROR` / `E_TURN_ALLOCATION_MISSMATCH` surface.
2. Retarget `PacketParser` RULE 1 to also tunnel game UDP toward peer LAN (`AppState.peerIp`, e.g. `10.57.220.34`), scoped to learned game ports (kickoff 24–27pps flow) so ordinary LAN stays passthrough. Game believes peer is real host candidate (reachable same-subnet), NTL hole-punch to host succeeds *through the tunnel* (same addresses either way, PeerLink keeps pps/score visibility + QoS). srflx punch to carrier CGNAT fails as before — NTL picks host path, same as today, minus the lie.
3. Fallback if NTL still demands relay: strategies exist (`OnlineSystemMultiplaySessionStrategyP2pFullMeshWithTurn` vs `...TurnOnly`); honest srflx lets a real TURN allocation (`CMD_GET_TURN_SERVER_LIST` → `CMD_SEND_TURN_ADDRESS_DATA`) succeed instead of mismatching.

Do NOT tune jitter/pipeline first: radio clumps 60–177ms + 60–90ms pipeline gaps (FINDINGS) are 2 orders below 45–78s stalls and cannot explain same-second 54B goodbyes on both phones.

## 4. Disproved along the way (with quotes)

- Packet loss/path: `udp_trace` seq zero gaps/reorders ~11k pkts/phone; tunnel 76,131 pkts; keepalives flow through stalls. Not loss.
- PeerLink timers: keepalive `TunnelEngine.kt:327 100ms`, native `peerlink_backend.cpp:52-54 1s/0.5s/0.75s`; diag thresholds log-only `447-452`; sleeps `100ms×20 (disabled)`, `50ms` retry, TURN-resolver `10s` DNS-only. Nothing pauses 45–78s symmetrically. `DISCONNECT_CONFIRM_MS=135000` / `SUSTAINED_ZERO_PPS_MS=90000` are detectors (`resolveSustainedDisconnect 1160-1199`: log+vibrate only).
- Screenshots/capture cost: bursts AFTER 54B all 3 stalls; 0 captures 02:31–33 etc.; PRIME 470 polls 0 errors.
- Wrong-IP leak as cause: 16 probes land 45–78s AFTER stalls, never during healthy play → symptom. TX-guard unarmed (`TunnelAgeMs=-1` bridge) is downstream bug, not cause.
- Blocked Konami traffic: `RelayBlocked=BypassBlocked=TurnRelayBlocked=TurnIps=0`; DTLS/DNS/QUIC untouched.
- VPN detection in native: `tun0` 0, `VpnService` 0, `magisk`/`emulator`/`qemu`/`RootBeer` 0; only `isDeviceRooted` x1 + SafetyNet x2 (stock UE4). No VPN-specific checks found. Java dex has no game netcode (only Firebase heartbeat).
- Server heartbeat transport: TCP 443 ACKs (576/40) + QUIC + DNS continue through stalls; DTLS appdata stops with no alert — transport alive, app quit.

## Open (not in verdict, next work)

- Numeric thresholds for `TurnReconnectWaitTimeMs` / `NTL_PEER_KEEPALIVE_COUNT` / `MATCH_STOP_COUNT_*` / `MatchAbortTimerCoefficient` via Ghidra on `0x75505a8` table + enum-indexed string table (no direct VA pointers found; needs headless analyze).
- NTL API TURN delivery (TLS — needs runtime MITM/hook, not static).
- One-match test with fabrication OFF (logs + captures same format) to confirm stalls stop.
