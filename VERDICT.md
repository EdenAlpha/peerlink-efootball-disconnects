# VERDICT — PeerLink × eFootball disconnects (evidence-only, 2026-09-26)

Target: `jp.konami.pesam` 11.0.1 (311000101), `lib/arm64-v8a/libUE4.so` 160,822,968B.
Captures: `captures/match-2026-09-26/` z1 (13,188 rows) + z2 (16,511 rows).

## 1. Which exact rule kills our matches

**Signature (quoted packets, all 3 stalls):**

- `match_log` both phones same second: `02:34:46.717 54B burst (20) -> Path A capture` then `02:34:48.727 Path A cliff confirmed (pps=0)`; S2 `02:37:13.901 (52)` -> `02:37:15.918`; S3 `02:45:51.387 (55)` -> `02:45:53.393`. Z1-Z2 cliff delta 31/99/112ms. `0pps_cliff` events `1790386488724 / 1790386635917 / 1790387153392`.
- Game P2P 27→0 (detector `GAMEPLAY_PPS_MIN..MAX`, `MatchAutomationEngine.kt:312`). The 54B burst is the game's own dying tick: uniform ~54B, 45 in ~1.1s field traces, threshold `PATH_A_MIN_BURST=6` (`MatchAutomationEngine.kt:36-43,98-101`).
- Game↔Konami DTLS (parsed records, all type 23 appdata, ver `fefd`=DTLS1.2, epoch 0001): e.g. S1 z1 `1790386487485 t 208B` / `1790386487970 r 190B`, then silence 750ms before cliff. Last 8 pre-stall are all `t=23`, zero `t=21` alert / `t=22` handshake / `t=20` CCS. Both phones stop DTLS to *different* servers same second (S2 z1 `34.38.190.21:30905`, z2 `35.233.88.176:32741`; S3 z1 `104.199.46.171:30222`, z2 `35.240.102.10:31406`). No server kill command on the wire.
- During 21s: zero game DTLS, only DNS `8.8.8.8:53`, TCP 443 (`54.187.87.37`, `32.184.206.158`, `44.255.249.99`, `108.156.x.x`), QUIC `8.8.8.8:443` (z2), len-30 `:5521` probes. STUN keepalives continue (`02:34:49.412 STUN[T7:Signal]`). Internet works, game stops. Screenshot `z2/.../shot_0006_OTHER.jpg` = black + eFootball logo (loading).
- S3 finals are asymmetric and small (COORDINATION §1): z1 server→phone DTLS payload 61 B (IP 102) at −1.83 s unanswered; z2 phone→server UDP payload 76 B (IP 104, DTLS 63) at −1.84 s unanswered, within ~20 ms — session-level abort/order exchange, not timeout. S1–S2 end on completed normal exchanges instead. Clean-match contrast: supervisor lives ~50 s past full-time with 1 Hz 208 B polls (8× unanswered) — stalls show no logout ritual, torn down from above.

**Game strings giving this trigger meaning (libUE4.so file offsets):**

- `E_TURN_ALLOCATION_MISSMATCH` @10251944 (note upstream misspelling). TURN allocation path exists: `ALLOCATE_SUCCESS_RESPONSE`, `REFRESH_REQUEST`, `CHANNEL_BIND_REQUEST`, `SendStunMsg ... tid ... act` @10953544, `ERR_FAILED_STUNCHECK` (lobby create/join) @10213270, `CHECK_STUN_RTT_TIMEOUT/COMPLETE`.
- Match-stop counters: `MATCH_STOP_COUNT_SELF_BUF_EMPTY_BURST_L1/L2/L5`, `MATCH_STOP_COUNT_BUF_EMPTY_BURST_L1-L5` (+`_MCACTIVE`), `MATCH_STOP_MAX_ROLLING_COUNT_BUF_EMPTY_IV2_MCACTIVE` (27 hits) + `MatchAbortTimerCoefficient`, `LoadTimeoutMs`.
- NTL (Konami's own traversal, `cobra/NatTraversal/NTL/ntl/NtlHelper.cpp`): `CMD_GET_TURN_SERVER_LIST` → `CMD_SEND_TURN_ADDRESS_DATA` / `CMD_WATCH_TURN_ADDRESS_DATA` / `CMD_GET_TURN_ADDRESS_DATA`; `START_UDP_HOLE_PUNCHING_{PROGRESS,COMPLETE,ERROR,ABORTED}` + `ADVICE_CANCEL_HAIRPIN/CANCEL_LOCAL`; `ALLOC_TURN_PORT_{COMPLETE,ERROR,ABORTED,QUOTA_ERROR,AUTH_ERROR,ALLOCATION_MISSMATCH_ERROR}`; strategies `...P2pFullMeshWithTurn` vs `...P2pFullMeshTurnOnly`; `natType` reporting (`${"natType":0x%08x}`, `NATTYPE_PEER`, `TurnInitializedNatType`); `reflexive_address`/`reflexive_port`/`PEER_REFLEXIVE`/`RP_REFLEXIVE_ADDRESS` handling; `is_cheat_user`/`is_cheat` + `OnlineModeTaskCheckCheat.cpp`; `DETECT_NAT_ABORTED`; `FakeKeepAlive` warning. No ICE (`candidate` hits all ARKit FP, `ICE` all `ostringstream` FP) — NTL replaces ICE here.
- Reconnect/keepalive names: `TurnNetworkIoReconnectServerTimeWaitMs` @10251029, `TurnReconnectWaitTimeMs` @10487790, `NtlReconnectWaitTimeMs` @12200932, `NTL_PEER_KEEPALIVE_COUNT` @12121675, `KeepAliveTimerUs` @12120984, `MultiplaySessionRecvThreadReceiveTimeoutUs` @10251231, `LinkTimeoutUs`, `PingIntervalUs`, `EstablishedConnectionTimeoutUs`.
- `BRIDGE-GAP-T0` (`TunnelEngine.kt:2177-2187`, gate `GAP_THRESHOLD_MS=150` at `:447`, rename `:1107-1108`) cannot be read as "the game was silent for N ms". It reports ~300 gaps of 154–2975 ms *inside the very window where `udp_trace` shows tun traffic continuous to within 61 ms* (10,922 packets, max dir=out gap 70 ms), and its logged lengths (`208`,`40`,`576`,`362`,`84`) never appear in the gameplay stream at all. Every one carries `seq=0 missing=0 qTun=0`. Contradiction is unresolved in captures; treat its `gapMs` as invalid for watchdog analysis until the ring is re-taken (§5).

**Rule in one sentence:** the game's P2P sync (27pps) emits its own 54B goodbye then stops, and its DTLS appdata to Konami stops with no alert, on both phones the same second, while the OS network stays up — i.e. **game-logic quit, not packet loss**.

### 1b. The rule, decoded from `libUE4.so` (capstone, no Ghidra needed)

Source path string at file offset `0xae2b65`:
`G:\PES22HC\Dev-600Series\Source\Shared\pes\Game\Match\Online\MatchOnlineWatchDog.cpp`

The rule is in the function at `0x6f906ec`, which references that path with
`mov w1, #0x55` (decimal 85) at `0x6f907fc` — **line 85**:

| instruction | meaning |
|---|---|
| `bl 0x68c5efc` | `now` (microsecond clock) |
| `ldr x8, [x19,#0x10]` then `blr` vtable `[0x48]` | `last = last_activity()` |
| `0x6f90794: cmn w9, #1` / `b.eq` | **`threshold == -1` → rule disabled** (returns false) |
| `0x6f907a0: subs x8, x21, x8` | `elapsed = now - last` |
| `0x6f907a8: cmp x8, x9` / `b.lo` | **fire only if `elapsed >= threshold`** |
| `0x6f907fc: mov w1, #0x55` | log `MatchOnlineWatchDog.cpp:85` |
| `0x6f90840: bl 0x6f8ee24` | the abort/act-on action |
| `0x6f90ac4: str wzr, [x19]` (kind 20) | **`threshold == 0` → fires immediately** |

`threshold` is in **microseconds** and is built as `config_ms * 1000` — `mul w8, w8, w9` with `w9 = 1000`
at `0x6f90a68` and `0x6f90ba4`.

**The millisecond values (answers §4 Q1).** They are *not* hashed FNames and need no Ghidra: the
constructor `0x7d36874` of the config object `X` (1968 B, `0x7b0`, held at `S+0x10`, `S` from `0x7d2bf4c`)
fills the block with four `ldr q` immediates from `.rodata`, then four 16-byte stores:

```
ldr q0, [0x7300150]  str q0, [x19, #0x6f0]     ldr q1, [0x7340740]  str q1, [x19, #0x700]
ldr q2, [0x7399e0]   str q2, [x19, #0x710]     ldr q0, [0x73b760]  str q0, [x19, #0x720]
```

Read as little-endian `u32[4]`, these are round numbers in **milliseconds**:

| `X+` | value (ms) | consumed by | `×1000` (µs) |
|---|---|---|---|
| `0x708` | **120** | kind 24 (`ldr w8,[x0,#0x18]`) | 120000 |
| `0x70c` | **180** | kind 15 (`ldr w8,[x0,#0x1c]`) | 180000 |
| `0x710` / `0x714` | **10 / 300** | kind 30, side-selected (`add x8,x0,#0x20`/`#0x24`) | 10000 / 300000 |
| `0x718` / `0x71c` | **10 / 30** | kind 30, `vtable[0x160](x,6)` (`#0x28`/`#0x2c`) | 10000 / 30000 |
| `0x720` / `0x724` | **60 / 90** | kind 27 (`#0x30`/`#0x34`) | 60000 / 90000 |
| `0x728` / `0x72c` | **60 / 180** | kind 25 (`#0x38`/`#0x3c`) | 60000 / 180000 |
| — | **0** | kind 20, hardcoded `str wzr,[x19]` | 0 |
| `0x6f0`–`0x704` | 30, 30, 45, 60, 40, 180 | sibling timeouts (incl. the `0x995c8e8/0x995c8ec` globals written by `0x7a6cabc`) | |

**So: the watchdog thresholds are 0 / 10 / 30 / 60 / 90 / 120 / 180 / 300 ms. 300 ms is the largest
value that exists in the binary; `-1` disables.**

**These are the authoritative values — nothing overrides them.** The block accessor `0x7d376b0`
(`add x0,x0,#0x6f0; ret`, no `-1` defaulting, unlike the neighbouring `+0x610/+0x614/+0x618` fields)
has 12 call sites in 5 functions, all pure loads; and a full-binary scan of every non-SP
`str/stp` into `[reg, #0x6f0..#0x734)` found 24 candidates within ±4000 B of an `X`-getter, of which
all inspected (`0x76b0480`, `0x7ad5790`, `0x7ad5d98`, `0x79ecbe0…`) belong to *other* objects
(a `std::list` head, a bool field, a global at `0xa4a7708`). No server-side or runtime write reaches the block.

**Cross-check against healthy play** (`udp_trace.csv`, tun level, n=10,922 over 3.6 min):

| direction | p50 | p95 | p99 | max | gaps >300 ms |
|---|---|---|---|---|---|
| inbound (`dir=in`) | **37 ms** | 51 | 68 | **176 ms** | **0** |
| outbound (`dir=out`) | 37 ms | 42 | 52 | 70 ms | 0 |
| either direction | 19 ms | — | 39 | 64 ms | 0 |

The 180 ms and 300 ms slots sit **just above the healthy worst case (176 ms)** — they are sized so a
good link never trips them and a real stall always does. This is what makes the §4 Q3 "false positive"
test answerable: if transmission is active inside 180–300 ms, these two thresholds cannot have fired.

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
- P2P-gap starvation as cause: DEAD per COORDINATION §2 — clean match survived 43/77 × ≥2.5 s gaps (max 3.9 s); `MATCH_STOP_*` not fed by delivery gaps.
- Blocked Konami traffic: `RelayBlocked=BypassBlocked=TurnRelayBlocked=TurnIps=0`; DTLS/DNS/QUIC untouched.
- VPN detection in native: `tun0` 0, `VpnService` 0, `magisk`/`emulator`/`qemu`/`RootBeer` 0; only `isDeviceRooted` x1 + SafetyNet x2 (stock UE4). No VPN-specific checks found. Java dex has no game netcode (only Firebase heartbeat).
- Server heartbeat transport: TCP 443 ACKs (576/40) + QUIC + DNS continue through stalls; DTLS appdata stops with no alert — transport alive, app quit.
- **"The ms values need Ghidra" — disproved.** They are plain `u32` constants in `.rodata` loaded by four `ldr q` in the `X` constructor `0x7d36874`; extracted in one script (`efootball-apk/read_defaults.py`) with capstone + the ELF program headers. No headless analysis, no `0x75505a8` enum table.
- **"`BRIDGE-GAP-T0 gapMs` = how long the game was silent" — disproved.** `TunnelEngine.kt:2177-2187` gates it at `GAP_THRESHOLD_MS=150`, but in the window where `udp_trace` shows 10,922 tun packets with a **maximum** dir=out gap of 70 ms, it still reports ~300 gaps of 154–2975 ms, all `missing=0 qTun=0`, and its dominant lengths (`208` ×561, `40` ×337, `576` ×115, `362` ×93) are essentially absent from the gameplay stream (`udp_trace dir=out` top lens are 100/91/103/105/134). Every earlier "silence at quit" bracket derived from it is therefore void.
- **"`kUdpTraceCapacity=32768` is enough for end-of-match analysis" — disproved.** The session wrote **228,393** events (`capturedEvents=32768 overwritten=195625`), so only the last ~4.8 min (02:53:40–02:57:17) survived. All three stall windows (02:34:48 / 02:37:15 / 02:45:53) were overwritten — which is exactly the data needed to compare `now - last_activity` against the 180/300 ms slots.

## 5. Capture defect fixed (prerequisite for the next verdict)

`app/src/main/jni/peerlink_backend.cpp:78` — `kUdpTraceCapacity` raised **32768 → 262144**, with the
measurement written into the comment. `UdpTraceEvent` is ~104 B (`UdpTraceData` 88 B + `atomic<uint64_t>` +
`atomic_flag`), so the ring goes ~3.4 MiB → ~27 MiB resident and the CSV export goes to ~45 MB for a full
session. At ~6,800 events/min a 262,144-event ring covers ~39 min, i.e. a whole match plus menus.

Why this size and not 131072: stall 1 (02:34:48) sits ~23 min before session end, and 131072 events only
reach back ~19 min. This is the single change that turns "threshold unknown, capture destroyed" into a
direct `now - last_activity` measurement against the 10/30/60/90/120/180/300 ms table.

## Open (not in verdict, next work)

- Measure `now - last_activity` at a real stall from a full-length `udp_trace` (needs §5 build on both phones), then state which of the 7 slots fired and whether it was a true positive.
- Identify what `vtable[0x48]` (`last_activity`) actually samples — if it is the 37 ms inbound stream, an 180/300 ms fire means a genuine ≥180 ms inbound hole that the old ring erased.
- Resolve the `BRIDGE-GAP-T0` vs `udp_trace` contradiction (deferred/batched log timestamps via `kMaxDeferredFileLogs=65536` vs unretained tun reads).
- NTL API TURN delivery (TLS — needs runtime MITM/hook, not static).
- One-match test with fabrication OFF (logs + captures same format) to confirm stalls stop.
