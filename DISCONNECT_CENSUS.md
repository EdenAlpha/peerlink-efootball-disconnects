# eFootball P2P Disconnect Census (forensic, liveness-graded)

Date: 2026-09-27
Target: `libUE4.so` 160,822,968 B (arm64-v8a), 404,160 extracted strings
Repo: `EdenAlpha/peerlink-efootball-disconnects`

---

## 0. Why this document exists

A raw string dump of a 160 MB library is worthless as evidence: the linker keeps
orphan `.rodata` from unused translation units, and this binary also ships gRPC,
PhysX, ICU and Epic's stock Unreal code. Anything can *look* like a disconnect
rule just by being present.

So every entry below is graded by **liveness**, not presence.

### Method

New tool: `efootball-apk/liveness.py`. For a candidate string it reports:

| field | meaning |
|---|---|
| `code=N` | N distinct `adrp`+`add` / `adrp`+`ldr` sequences in executable code that materialise exactly that address |
| `ptrs=N` | absolute 8/4-byte pointers to it **outside unwind sections** |
| `sec` | which section holds it |
| verdict | `REFERENCED` / `TABLE_ONLY` / `DYNAMIC_EXPORT` / `UNREFERENCED` |

Index size: **909,974 ADRP sites** across all executable segments.

Control: `MatchOnlineWatchDog.cpp` (offset 11414373) → `code=1, xref 0x6f907f4`,
which is the exact instruction already proven to be the watchdog's fire path by
independent disassembly. The tool agrees with ground truth.

### Three bugs I found and fixed in my own tool

Recording these because they would have produced a *wrong* legacy list:

1. **`.eh_frame` false positives.** Unwind encodings reproduce arbitrary 8/4-byte
   patterns, so `ENetworkFailure::OutdatedClient` appeared "pointed to" at
   `0x215f5a6` — inside `.eh_frame`, not a real pointer. Pointer scanning now
   excludes `.eh_frame*`, `.gcc_except_table`, `.comment`.
2. **`.dynstr` false negatives.** `Java_jp_konami_AndroidUtil_OnPauseCallback`
   (offset 1193261) scored `code=0` and would have been called dead — but it sits
   in **`.dynstr`** and is an *exported JNI symbol*, referenced by the dynamic
   loader, never by `adrp`. Strings in loader-managed sections now classify as
   `DYNAMIC_EXPORT`.
3. **Over-eager loop termination.** The forward scan `break`ed on *any*
   instruction that wasn't `add`/`ldr`. A single `mov` between `adrp` and `add`
   would hide a real reference and mislabel live code as legacy. It now only
   breaks on a new `ADRP` or on a call/branch (where the base register may be
   clobbered).

After all three fixes: the 5 controls stayed `REFERENCED`, all 20 legacy
candidates stayed `UNREFERENCED`. Verdicts are stable.

### Honest limitation

`REFERENCED` proves the string is bound into compiled, linked code.
It does **not** prove that path is *reachable at runtime* — a referenced function
can still be unreachable from any live entry point. `UNREFERENCED` is the
stronger claim (dead by construction); `REFERENCED` means "not dead by linking".

---

## 1. LIVE — the game's own disconnect reason strings

All in `Source\Shared\pes\Game\Online\OnlineMode\Task\Match\OnlineModeTaskMatchSession.cpp`.
This function writes a reason string into `obj+0x200` and a code into `obj+0x78`.

| code | reason string | source line | verdict |
|---|---|---|---|
| 8 | `Error SetConfig()` | 283 | REFERENCED `0x7a5600c` |
| 3 | `Revison check TIMEOUT` *(sic)* | 468 | REFERENCED `0x7a56220` |
| 8 | `MultiplaySession daemon is NULL` | 387 | REFERENCED `0x7a56408` |
| 8 | `MultiplaySession backend is NULL` | 395 | REFERENCED `0x7a56558` |
| — | `UNKNOWN` | 488 | REFERENCED `0x7a56860` |
| — | `Revision error [ … ]` | 473 | REFERENCED `0x7a5690c` |
| — | `DATAPACK error` | 479 | REFERENCED `0x7a569f8` |
| **3** | **`Other user disconnected`** | **483** | **REFERENCED `0x7a56aa8`** |

`Other user disconnected` (the only player-facing one here) does:

```
0x7a56a90  mov  w8, #3
0x7a56a94  add  x0, x21, #0x200
0x7a56a98  adrp x1, "Other user disconnected"
0x7a56aa0  mov  w2, #0x17              ; 23 = strlen
0x7a56aa4  str  w8, [x21, #0x78]       ; state := 3
0x7a56aa8  bl   #0x2f15088             ; set reason
```

logged at line 483 of that file. **This is server-delivered**: it is set in the
session *task*, i.e. Konami's server tells your client that the opponent's
session ended. Your client did not detect this itself.

---

## 2. LIVE — Konami's own abnormal-end report schema

The client reports an abnormal match end to `CmdGetVscomGameResult.php`. The
payload builder (around `0x7698694`) enumerates **exactly which causes KONAMI
recognises** — this is the closest thing in the binary to an authoritative list:

| field | xrefs | verdict |
|---|---|---|
| `game_id` | `0x7698694` | REFERENCED |
| `abnormalend_reason` | 6 × incl. `0x76986d4` | REFERENCED |
| `is_problem` | 4 × incl. `0x7698710` | REFERENCED |
| `is_stun_keep_alive_failed` | 4 × incl. `0x7698758` | REFERENCED |
| **`is_network_blocked_disconn`** | 4 × incl. `0x7698794` | REFERENCED |
| **`is_background_timeout`** | 4 × incl. `0x76987d0` | REFERENCED |
| **`is_background_at_match`** | 4 × incl. `0x769880c` | REFERENCED |
| `user_network_status` | 4 × incl. `0x769882c` | REFERENCED |
| `error_code` | `0x76988d8` | REFERENCED |
| `intentional_give_up` | 2 × `0x7699cd4`, `0x76a2364` | REFERENCED |

Every one has 4 code references at a consistent 4-site pattern
(`0x7698…`, `0x769b…`, `0x76d4…`, `0x76d6…`) = two serialisers + two readers.

**Reading:** the game distinguishes *network blocked*, *app backgrounded*,
*STUN keepalive failed*, and *player quit on purpose* as separate reported
causes. Note `is_stun_keep_alive_failed` exists at all — the game explicitly
tracks whether its STUN keepalive failed.

---

## 3. LIVE — session timeouts, all config-driven

Parsed by function `0x7d3f938`, which reads a JSON node literally named
**`"timeout_settings"`** (via `obj+0x98`). Values are stored at `obj+0x50..0x8c`.

| key | stored at | phase |
|---|---|---|
| `wait_game_result_timeout_sec` | `+0x50` | — |
| `get_game_result_timeout_sec` | `+0x54`* | — |
| `add_point_timout_sec` *(sic)* | `+0x54` | — |
| `load_timeout_sec` | `+0x64` | — |
| `align_progress_ready_timeout_sec` | `+0x60` | — |
| `align_progress_abormal_end_timout_sec` *(sic)* | `+0x5c` | — |
| `out_of_play_timeout_sec` | `+0x68` | — |
| `match_sync_failed_timeout_sec` | `+0x6c` | — |
| `match_session_not_connected_timeout_sec` | `+0x70` / `+0x74` | `in_play` / `out_of_play` |
| `match_session_disconneted_timeout_sec` *(sic)* | `+0x78` / `+0x7c` | `in_play` / `out_of_play` |
| `match_not_run_timeout_sec` | `+0x80` / `+0x84` | `in_play` / `out_of_play` |
| `match_command_lack_mobile_timeout_sec` | `+0x88` / `+0x8c` | `in_play` / `out_of_play` |

Also REFERENCED, in the network-timing table at `0x7c05bec`:
`NetworkIoConnectionTimeoutUs`, `TurnReconnectWaitTimeMs`,
`NtlReconnectWaitTimeMs`, `NameResolverTimeoutMs`;
and `BackgroundTimeoutMs` at `0x7c0833c` (next to `NetworkQualityTestAlwaysEnable`).

**Critical:** these values are **not compiled into the binary.** Only one JSON
default blob exists in `.rodata` (offset 12514942, 313 bytes) and it does *not*
contain any of these keys. So their real numbers come from a delivered config
payload — you cannot read them off the `.so`; you must capture the config
response.

The 180 ms watchdog thresholds are the exception: those *are* compiled in
(`X+0x6f0..0x72c = 30,30,45,60,40,180,120,180,10,300,10,30,60,90,60,180` ms).

---

## 4. LIVE — the 180 ms match watchdog (unchanged, restated)

`Source\Shared\pes\Game\Match\Online\MatchOnlineWatchDog.cpp`
Path string offset 11414373 → `code=1, xref 0x6f907f4`.

Rule: `elapsed = now − [this+0x10]`; fires when `elapsed >= threshold`;
`threshold_us = config_ms × 1000`; `-1` disables, `0` fires immediately.
Threshold resolution order recovers 7 branches, mainline **180 ms**.

Healthy-play baseline (n=10,922, 3.6 min): inbound p50 37 ms, **max 176 ms**,
zero gaps >300 ms → 4 ms of headroom under the trip point.

---

## 5. LIVE — causes that stop a match from *starting*

These abort setup, not an in-progress match.

| string | offset | verdict | xref |
|---|---|---|---|
| `JOINROOM_ERR_FAILED_CONNECT_RELAY_TIMEOUT` | 10900815 | REFERENCED | `0x3324b60`, `0x7a1a41c` |
| `START_UDP_HOLE_PUNCHING_ERROR` | 12671767 | REFERENCED | `0x7d16158` |
| `START_UDP_HOLE_PUNCHING_ABORTED` | 11188643 | REFERENCED | `0x7d16164` |
| `START_UDP_HOLE_PUNCHING_ADVICE_CANCEL_HAIRPIN` | 11811726 | REFERENCED | `0x7d1617c` |
| `START_UDP_HOLE_PUNCHING_ADVICE_CANCEL_LOCAL` | 11108525 | REFERENCED | `0x7d16188` |
| `STOP_UDP_HOLE_PUNCHING_ABORTED` | 12121372 | REFERENCED | `0x7d15f34` |
| `STOP_UDP_HOLE_PUNCHING_ERROR` | 10794723 | REFERENCED | `0x7d161b8` |
| `KEEP_UDP_HOLE_PUNCHING_ERROR` | 11267132 | REFERENCED | `0x7d161e8` |

`ADVICE_CANCEL_HAIRPIN` is notable: Konami's own punch-through refuses a
hairpinned path — relevant when two peers sit behind the same NAT.

Related and REFERENCED: `ELobbyJoinRoomError::ERR_FAILED_CONNECT_RELAY_TIMEOUT`
(10834384) — relay (TURN) connect timeout at join time.

---

## 6. LIVE — give-up / forfeit

| string | offset | verdict | xref |
|---|---|---|---|
| `intentional_give_up` | 10639744 | REFERENCED | `0x7699cd4` |
| `NORMAL_GIVEUP` | 10791629 | REFERENCED | `0x7552808` |
| `is_enable_giveup` | 12668139 | REFERENCED | `0x74ef200`, `0x74ef218`, `0x74f0d2c` |
| `match_forfeited` | 12524240 | REFERENCED | `0x802dff8` |
| `giveup_msec` | 11733278 | REFERENCED | `0x7d3f244` |
| `STRANGE_MATCH_END` | 10408111 | REFERENCED | `0x76ca310` |
| `user canceled` | 12211234 | REFERENCED | `0x80019e0` |
| `CS_GIVE_UP_QUICKLY_LEVEL` | 10952971 | REFERENCED | 12 sites |
| `P2P_ADHOC_*_GIVE_UP_QUICKLY_LEVEL` | various | REFERENCED | 9–12 sites each |

`P2P_ADHOC_*` (LAN / BLE / BTC / WiFiDirect) is KONAMI's **ad-hoc local-play**
transport. It is *referenced*, so not dead — but it belongs to the local-play
path, not online matchmaking. Treat as irrelevant to your case, not as legacy.

---

## 7. LIVE but only TELEMETRY — measures disconnects, does not cause them

These are metric names emitted with values read from counters
(`x19+0xa5e/0xa6a/0xa70`, `ldrh`), in an upload routine around `0x7d4c780`:

`NTL_PEER_CLOSE_COUNT`, `NTL_PEER_KEEPALIVE_COUNT`, `NETWORK_UP_COUNT`,
`NTL_PEER_STATUS`.

**Do not mistake these for triggers.** They are consequences.

---

## 8. LIVE but WRONG SUBSYSTEM — not the gameplay path

`keepalive watchdog timeout` / `"%s: Keepalive watchdog fired. Closing transport."`

Origin proven at `0x7e2bf74`:

```
"G:\PES22HC\Dev-600Series\Source\Shared\basic\ext\grpc\grpc\
 src\core\ext\transport\chttp2\transport\chttp2_tran…"
line 2882
```

This is **gRPC's chttp2 transport keepalive** — the channel carrying server
*commands* (`CMD_ADD_SCORE`, `CMD_ADD_FOUL`, …), not the P2P UDP gameplay
stream. KONAMI merely vendors gRPC under their own source-tree prefix, which is
why it looks like first-party code.

---

## 9. DEAD / LEGACY — proven `UNREFERENCED`

Zero `adrp` code references **and** zero non-unwind absolute pointers, after all
three tool fixes.

### 9a. Epic's stock Unreal network-failure enum — entirely unused

| string | offset |
|---|---|
| `ENetworkFailure` | 11937801 |
| `ENetworkFailure::Type` | 12334348 |
| `ENetworkFailure::ConnectionLost` | 10847475 |
| `ENetworkFailure::ConnectionTimeout` | 10462531 |
| `ENetworkFailure::OutdatedClient` | 10224712 |
| `ENetworkFailure::OutdatedServer` | 10462566 |
| `ENetworkFailure::PendingConnectionFailure` | 10224744 |
| `ENetworkFailure::FailureReceived` | 10303624 |
| `ENetworkFailure::NetDriverCreateFailure` | 11160782 |
| `ENetworkFailure::NetGuidMismatch` | 12014838 |
| `ENetworkFailure::NetChecksumMismatch` | 12487978 |

**Conclusion:** eFootball does **not** use Unreal's generic
`ConnectionLost`/`ConnectionTimeout` machinery. Anyone reasoning from UE4
docs about "connection lost" is reasoning about dead code here.

### 9b. Forfeit / give-up naming — dead family

| string | offset |
|---|---|
| `FORFEITED_GAME` | 10712702 |
| `ForfeitedReason` | 11741929 |
| `CheckIsForfeitedGame` | 12679914 |
| `ERR_GIVE_UP` | 11187650 |
| `IsGiveUp` | 12551573 |
| `IsGiveUpMatchEnd` | 12319477 |
| `IsAnnounceGiveUpWinner` | 11146098 |
| `ECmnPauseIconType::ABANDON` | 10523102 |

Note the asymmetry: the *naming/checking* functions are dead while
`match_forfeited` and `intentional_give_up` are live — an older forfeiture
implementation was replaced.

### 9c. Dead but third-party anyway (never eFootball logic)

`EVipEndReason::NetworkDisconnect` (10519671) — dead.
gRPC strings (`grpc.keepalive_time_ms`, `HTTP2: abandon stream id`),
PhysX (`PxPvd::connect`, `_ZN5physx…`), ICU (`icu_64`, `DecimalFormat`),
XR (`DisconnectRemoteXRDevice`). All library internals.

---

## 10. Not in `libUE4.so` at all — the Java layer

`jp.konami.android.common.GetWifiManager` registers
`NetworkRequest.Builder().addTransportType(1)` and only ever reads
`hasTransport()` — **never** `NET_CAPABILITY_VALIDATED` or
`NET_CAPABILITY_INTERNET`. `Reachability.canUseWiFi/canUseEthernet` likewise
check transport type only.

`jp.konami.peerlink` (BLE / BluetoothClassic / NSD / WifiDirect) is KONAMI's
**local-play** discovery, unrelated to online matchmaking.

**Consequence:** "Wi-Fi present but no internet" is indistinguishable from
"Wi-Fi working" to the game's Java code. It cannot be the thing that notices
you went offline.

---

## 11. Summary — what actually ends an eFootball P2P match

**Proven live and plausibly involved in a mid-match disconnect:**

1. **180 ms inactivity watchdog** — `MatchOnlineWatchDog.cpp`. Fires on silence,
   not on network state. Mainline 180 ms vs 176 ms observed healthy max.
2. **Server-declared session end** — `OnlineModeTaskMatchSession.cpp:483`
   `Other user disconnected`. Delivered by Konami's server, not detected locally.
3. **`timeout_settings` session timeouts** — `match_session_disconneted_timeout_sec`
   and siblings, split `in_play` / `out_of_play`. Values come from a delivered
   config, not the binary.
4. **Reported causes** — `is_network_blocked_disconn`, `is_background_timeout`,
   `is_background_at_match`, `is_stun_keep_alive_failed`, `intentional_give_up`.

**Proven live but cannot cause *this* failure:** telemetry counters (§7),
gRPC command-channel keepalive (§8), hole-punch/relay errors (§5, setup only).

**Proven legacy — do not reason from:** the entire `ENetworkFailure::*` enum,
`EVipEndReason::NetworkDisconnect`, the `FORFEITED_GAME` / `IsGiveUp*` family (§9).

**Still unproven:** *which* of items 1–3 actually fires during the 02:34:48 /
02:37:15 / 02:45:53 stalls. The ms-resolution ring that would show it was
overwritten (`overwritten=195625`); `kUdpTraceCapacity` has since been raised
32768 → 262144 in `Peerlink-app@4fd7840`. Confirmation still requires one
instrumented match: `adb logcat | grep -E "MatchOnlineWatchDog|AbnormalEnd"`.
