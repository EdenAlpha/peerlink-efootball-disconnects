# eFootball post-room-creation flow — complete spec (from decomp, nothing omitted)

Source: fulldump2 decomp dumps (old binary, real C bodies) + 11.1.0 killrule decomp.
Every function referenced below is extracted in `flow_decomp.txt` / `flow_decomp2.txt`
(+ `ghidra_sgr\full1110\killrule_out.txt` for 11.1.0 bodies).

## 0. The authoritative order (Konami's own LATENCY registry)

`FUN_07e5bc34` registers telemetry keys in **execution order** — this is the
canonical game flow, verbatim (fulldump2 line 1616875+):

```
MODE_MATCHING:
  1  CMD_START_MATCHING
  2  PROCESS  CMD_GET_MATCHING_RESULT
  3  POLLING  CMD_GET_MATCHING_RESULT
  4  CMD_GET_SERVER_ENV
MODE_SESSION:
  5  PROCESS  CMD_GET_GAME_SESSION
  6  POLLING  CMD_GET_GAME_SESSION
  7  CMD_GET_TURN_SERVER_LIST            <-- WE NEVER SEND THIS
MODE_CONNECT:
  8  WAIT_SOCKET
  9  CONNECT_SESSION                     (P2P-SDK session + TURN connect)
 10  MODE_MULTIPLAY
 11  WAIT_CONNECT_SESSION_CONTROLLER
 12  REVISION_CHECK
 13  QUALITY_TEST                        (relay quality measure)
MODE_ANNTENA:
 14  WAIT_QUALITY_CHECK
 15  CMD_SET_GAME_SESSION_CHECK_RES
 16  PROCESS  CMD_GET_GAME_SESSION_CHECK_RES
 17  POLLING  CMD_GET_GAME_SESSION_CHECK_RES
 18  USER_DATA_SYNC
 19  CMD_GET_GAMEID
 20  DISP_MATCHING_RESULT
MODE_PRE_MENU:
 21  TEAM_DATA_SYNC
 22  CMD_START_GAME
 23  READY_ALL_PLAYER
SESSION_ESTABLISH:
 24  LATENCY_SESSION_ESTABLISH
 25  NTL_PUNCHING: PRE -> TIME -> PROCESS -> RETRY -> PROCESS_ON_SUCCESS
 26  NTL_STUNCHECK_PROCESS
 27  TURN: GET_TURN_ADDRESS (min/max/mean/variance)
 28  TURN: CONNECT_ANY -> RESOLVING_NAME -> CONNECT_UDP -> CONNECT_PEER
```

So the two halves are:
- **Gate (HTTP) pre-kickoff:** … GET_GAME_SESSION → **GET_TURN_SERVER_LIST** →
  (connect/TURN) → quality → SET/GET GAME_SESSION_CHECK_RES → USER_DATA_SYNC →
  GET_GAMEID → START_GAME → READY
- **Wire (UDP) post-kickoff:** session establish → NTL punching → STUN check →
  TURN address exchange (gate cmds GET/SEND/WATCH_TURN_ADDRESS_DATA) → TURN connect

The DISCONN_HB stamp appears immediately after START_GAME = the server expects
the relay half (items 24–28) and/or the pre-kickoff TURN fetch (item 7) which we
have never sent.

## 1. CMD_GET_TURN_SERVER_LIST (item 7)

- Request: **bare envelope — NO body keys.**
  Proof: 11.1.0 state machine `FUN_07f969c0` state 0 builds the command from the
  name string only (`FUN_07f86848(param_1, "CmdGetTurnServerList")`); state 1 waits
  for reply and compares `result == "NOERR"`; state 2 consumes reply.
  Old-binary twin: wrapper `FUN_07eaeaa8` = ctor `FUN_07eaf040` (request) +
  ctor `FUN_07eaf5c8` (reply), dispatched with no argument fill.
- Gate endpoint: `CmdGetTurnServerList.php` (11.1.0: `FUN_07f90c2c` / `FUN_07f906a4`).
- Reply body (parsers `FUN_07eaf14c`, `FUN_07eaf768`, 11.1.0 `FUN_07f906a4`):
```
result
turn_account_param          (string)
turn_time_limit             (int)
turn_server_list: [ { zone:int, address:string, port:int, tls_port:int } ]
turn_account: {
    id:     string
    pw:     string
    origin: string
    server_certificate:           string   (DTLS/TURN cert)
    server_certificate_data_size: int
}
```
- **State matters:** sent right after login (no room/session) →
  `ERR_INVALIDARG / GKZX-` (logged `work\turn_probe.log`). Must be sent
  immediately after a successful CMD_GET_GAME_SESSION.

## 2. CMD_GET_GAME_SESSION reply — ntl_address_list (punch targets)

Parser `FUN_07724da0`; entry parser `FUN_077240d4`:
```
result
gamerelay:            (sub-object, parser FUN_0759614c)
game_sycom:           string
ntl_address_list: [
   { user_id:int, xuid:string,
     address_ipv4: {host_address, host_port, reflexive_address, reflexive_port, nat_type},
     address_ipv6: {host_address, host_port, reflexive_address, reflexive_port, nat_type} }
]
ping:                 int      (DAT_00bb4c4f)
connecting_start_time: int
connecting_retry_time: int
```
Flat-kv twin parser `FUN_07724218` confirms entry keys `xuid`,
`address_ipv4`, `address_ipv6`, `user_id`.

## 3. CMD_SET_GAME_SESSION_CHECK_RES (item 15)

Request builder `FUN_078108fc` (full key list, in write order):
```
match_category, ping_level, is_good_reputation, retry_num
check_sum: { player_check_sum, team_entry_check_sum }
target_user_id:            [int, ...]        (one append per peer/target)
address_ipv4: { host_address, host_port, reflexive_address, reflexive_port, nat_type }
address_ipv6: { host_address, host_port, reflexive_address, reflexive_port, nat_type }
file_hash_list: [ ... ], file_hash_list_num
base_team_id, league_type, event_id, ch_mission
is_touch_control, team_power_limit, team_power
old_game_id
gamerelay_measure_result
is_low_image_quality_setting
model_name
```
Reply parsers: request/response pair `FUN_077e15d4` (req) / `FUN_077e3d44` (res),
wrapped by `FUN_077e0c7c`.

## 4. TURN address exchange (item 27, gate side)

All four follow the identical wrapper pattern (builder ctor + reply ctor):

| command | wrapper | request builder | reply parser | reply keys |
|---|---|---|---|---|
| CMD_GET_TURN_ADDRESS_DATA | `FUN_07ead038` | `FUN_07ead160` | `FUN_07ead464` | result, address, address_data_size |
| CMD_WATCH_TURN_ADDRESS_DATA | `FUN_07eadd8c` | `FUN_07eade70` | `FUN_07eae174` | result, address, address_data_size |
| CMD_SEND_TURN_ADDRESS_DATA | `FUN_07eb10e0` | `FUN_07eb12f0` | `FUN_07eb1908` | result |

- `address` is a **base64 blob** (encode `FUN_075e2df8`, decode `FUN_075e2e94`).
- CMD_SEND_TURN_ADDRESS_DATA request keys (`FUN_07eb12f0`):
  `target_user_id:int`, `address:string(base64)`, `address_data_size:int`.
- GET/WATCH take **no body keys** (only envelope); reply carries the peer blob.
- The blob content = NTL/STUN punch data — same family our `p2p_stun.py` speaks
  (RP_ method 0x20B, attr 0x9090).

## 5. Relay quality family (item 13/14)

| command | wrapper | req / res ctors |
|---|---|---|
| CMD_SET_LOCAL_GAMERELAY_LIST | `FUN_077e835c` | `FUN_077e8b08` / `FUN_077e98d4` |
| CMD_GET_GAMERELAY_QUALITYCHECK_LIST | `FUN_07729884` | `FUN_0772a380` / `FUN_0772a550` |
| CMD_SET_GAMERELAY_QUALITY | `FUN_077e4774` | `FUN_077e482c` / `FUN_077e5204` |

## 6. Phase / score / result (post-kickoff gate side)

- CMD_CHANGE_GAMEPHASE + CMD_ADD_SCORE: wrapper `FUN_07e36874`, driver
  `FUN_07e2b4e4` (singleton via `FUN_07e2bf1c`). Embedded server config JSON
  (inside `FUN_07e36874`):
```
{"default":{"onmode":{"get_game_result_error_sec":30,
  "game_result_timeout_sec":45,"at_match_polling_interval_msec":30000},
  "timeout":{"CMD_ADD_SCORE":30,"CMD_ADD_FOUL":30,"CMD_CHANGE_GAMEPHASE":30},
  "invitation_task":{"enable":true,"use_http_command":false},
  "connect_grpc_task":{"disable":true}}}
```
- CMD_GET_GAME_RESULT: ctor `FUN_07721a70`.

## 7. Drivers (who sequences it)

- `FUN_07ec7164` — P2P-SDK session machine, states 0–0xb; state 9 pulls the gate
  session via `FUN_07e5b638` (→ stats/session string `FUN_07e5bc34`) and feeds the
  SDK (`FUN_07ec91d8`, `FUN_08245274`); retries 5×5000 ms, fail → state 0xb.
- `FUN_07e442a8` → `FUN_07e46054` (session batch: quality pre + stats emit, run
  twice: arg 0 then 1).
- `FUN_07e2bf1c` → `FUN_07e2b4e4` (phase/score/relay manager singleton).
- TURN/relay wrappers are dispatched via vtable +0xf0 (function-pointer table),
  not direct calls — hence no plain CALL xrefs.

## 8. What our bot must add (gap list vs chain3.py)

1. ~~**CMD_GET_TURN_SERVER_LIST (bare) right after GET_GAME_SESSION**~~ — tried bare
   and 6 body variants (room_id list/obj/int, +sycom, is_lobby, ping) at the
   correct state (immediately after GET_GAME_SESSION, both identities):
   **all GKZX-**. `game_sycom: "P2P"` ⇒ likely relay-only (flow_map step 12),
   never sent in P2P matches. Not the wall for us.
2. Consume `turn_server_list` + `turn_account{id,pw}` — N/A for P2P.
3. ~~Address exchange~~ — **DONE & live-verified**: after START_GAME,
   `CMD_SEND_TURN_ADDRESS_DATA {target_user_id, address(base64),
   address_data_size}` NOERR both directions, then
   `CMD_WATCH_TURN_ADDRESS_DATA` returns `response_flg:1` + the peer's blob
   (`3.80.79.52:44000`, size 16). Blob content = free-form base64
   (`FUN_075e2df8` = generic base64 encode, `FUN_075e2e94` = generic decode).
4. Punch: NTL punching + STUN check over UDP (`p2p_stun.py` family).
5. Relay quality: `CMD_SET_LOCAL_GAMERELAY_LIST` / `CMD_SET_GAMERELAY_QUALITY`
   (game measures "GAMRERELAY_MEASUARE_RESULT_AT_MATCHING") and
   `CMD_GET_GAMERELAY_QUALITYCHECK_LIST`.
6. USER_DATA_SYNC + CMD_GET_GAMEID ordering around ANNTENA phase (chain3 already
   does GET_GAME_ID via `game_id_of`; verify placement matches items 18–19).

## 9. Live findings 2026-10-11 (the wire says)

- **T7 Signal keepalive solved** — the game's ~5 s liveness beat to
  `pesam.stun.service.konami.net:3478` (also answers from `35.76.243.83` and
  `54.64.79.140`) is a **plain STUN BINDING_REQUEST (0x0001) carrying attr
  `0x9090`** with the RP_P2P_HEADER (own user_id) inside. Verified: both IPs
  answer every beat; method `0x080B`+`0x9090` is NOT answered (that form is
  peer-punch only). Source: PeerLink `StunFabricator.kt` classifyRequest
  (T7 = binding + attr 0x9090/0x9091). Bot implementation:
  `work/stun_keepalive.py` (binds the advertised endpoint :44000, 5 s,
  180/180 replies through run chain3_full_20261011).
- **CMD_READY_FLAG / CMD_ALLREADY_FLAG** = READY_ALL_PLAYER, body `{flag:int}`
  (value loaded from client state; ready=1), BUT they are **not gate HTTP
  commands** — `gate_CMD_READY_FLAG.php` → HTTP 404 "Data must be padded…"
  (36-byte HTML). No `Cmd*Ready*.php` exists in 11.1.0. They travel in-band.
- **CMD_GET_SESSION_ID {game_id}** → NOERR, reply key
  `platform_session_id_info` (gate endpoint CmdGetSessionId.php). Session
  establish (item 24) now covered.
- **CMD_SEND_SESSION_ID** exists too (req keys: game_id, ps_session_id,
  xb_session_id, platform_session_id_info; endpoint CmdSendSessionId.php).
- **The DISCONN_HB stamp may be a standing default, not a verdict**:
  `gameend=INVALID abnormal=DISCONN_HB` appears at post-start even with T7
  keepalive + full TURN exchange + session id. It could simply persist until a
  result is filed. Decisive test = full chain (phases → scores → END →
  SET_GAME_RESULT battery) with all new steps in — run chain3_full_20261011.

## 10. Live findings 2026-10-11 later (the capture answers)

- **NTL service found in the z2 capture** (plaintext HTTP, never contacted by
  the bot until now): the phone POSTs to `ntl.service.konami.net`
  (35.174.175.11 / 34.193.147.150 :80):
  - `POST /ntl/api/GateInfo.php` body `req=<hex of
    {"titleCode":"PES2022","locale":"US","version":"6.0.1","extr":"",
    "apiLevel":"4"}>` -> reply `STATUS: 200 / API_STATUS: 1 / LOG_ACTIVE: 1 /
    SERVER_TIME: <unix> / PUT_LOG_URL: .../ReportLog.php`. Verified live
    2026-10-11 (raw socket, exact captured bytes).
  - `POST /ntl/api/PES2022/ReportLog.php` with urlencoded `type/prefix/ver/dat`
    where dat = hex of a `## NTLInfo / ## AppInfo` text log (libVer
    1.17.1-Android-15, ntl uid = 32-hex, opt=22011111). Types seen: pds/pde
    (p2p session open/close, bracket the punch phase) and uds/ude (udp
    session open/close, bracket the whole match, ~70-280 s apart).
  - UDP 2-byte probes to ~30 GCP IPs on :5521 at ~3.3 s cadence = hop-count /
    access-line test (HOP_COUNT_* / ACCESS_LINE_* latency names), not punch.
- **USER_DATA_SYNC / TEAM_DATA_SYNC confirmed non-gate**: chain3 run #4 --
  both `_DECODE_FAIL` HTTP 404 "Data must be padded..." (36-byte HTML); the
  11.1.0 php inventory has NO Cmd*Sync*.php. Builders stay in chain3 as
  documentation of the in-band bodies.
- **Mid-match CHECK_GAME_RESULT polling is NOT what keeps the window open**
  (superseded 2026-10-11 evening, see §11).  Earlier this read the mapstamp
  run as proof that polling prevented the walkover.  That inference was
  backwards: mapstamp polled early (t+2 s after each phase change), so it
  observed `gameend=INVALID` *before* the stamp landed, and it still got
  `ERR_INVALIDARG`/`GKZX-` on every SET.  Runs #5/#6/#7/#8 polled at a 30 s
  cadence starting at t+30 s and saw `DISCONN` on their first poll.  Polls
  cannot un-stamp; they only change which value you happen to observe.
- **Submit body gap found**: server template match_result (CHECK reply on an
  open match) = 5 keys {abnormalend_reason, game_res, gameend_reason,
  player_data, score_data}; our serializer body = 16 root keys with none of
  gameend_reason/game_res/score_data/player_data (the 11.1.0 serializer
  FUN_07895324 never emits them -- the server derives them). Echo-template
  submit variant added (photocopier): fill the server's own 5-key template
  and send it back. Run chain3_full5_20261011.log (--poll --realorder).
- gRPC channel is NOT the submit path: one-shot probes -- heartbeat
  dispatches CMD_HEARTBEAT_GRPC, SET_GAME_RESULT and GET_GAME_RESULT both get
  CMD_END_CONNECTION (server closes the stream on non-heartbeat commands).

## 11. Live findings 2026-10-11 night (the DISCONN_HB root cause)

### The gate was never the problem. `abnormal=DISCONN_HB` is stamped at
### START_GAME, from NAT proof that is self-contradictory.

**`gameend` is not the gate on SET_GAME_RESULT.** The mapstamp run is the
proof and it was misread for hours:

```
stampcheck post-start   -> NOERR gameend=INVALID abnormal=DISCONN_HB
stampcheck after END    -> NOERR gameend=INVALID abnormal=DISCONN_HB
set_result [owner NOERR] -> ['own:ERR_INVALIDARG']  (t+2.8s since END)
... every variant -> ERR_INVALIDARG / GKZX-
```

The window stayed `INVALID` (open) through END and the battery STILL failed.
So the "open window" theory is dead -- an open `gameend` does not let
SET_GAME_RESULT through.  Meanwhile `abnormal=DISCONN_HB` was already present
at the post-start check at t+2 s, i.e. before any heartbeat of ours could
have mattered.

**Why the server thinks the link is dead:** both PeerLink bots run on this ONE
VM behind ONE public IP, and both read the same `work/peer_endpoint.json`,
so both advertised the identical reflexive endpoint `3.80.79.52:44000`.
Two peers at the same ip:port is impossible NAT proof -- the server cannot
punch between a peer and itself, so it resolves the match dead on arrival.

Confirmed by the server's own echo in `CMD_GET_GAME_SESSION`:

```
ntl_address_list: [
  {user_id: A, address_ipv4: {host_address: 3.80.79.52, host_port: 44000,
                               reflexive_address: 3.80.79.52,
                               reflexive_port: 44000, nat_type: 1}},
  {user_id: B, address_ipv4: {host_address: 3.80.79.52, host_port: 44000, ...}}
]
```

Identical entries for both users. A real phone-vs-phone match has two
different endpoints.

### The fix

Each identity must bind its OWN local port and do its OWN STUN, because two
clients behind one NAT only get distinct public ports by using distinct
local ports.  This VM's NAT preserves the port (nat_type 1), so binding
44001 yields a real, distinct reflexive `3.80.79.52:44001`.

- `udp_punch.py` -- output file is now per-port: `:44000` writes
  `peer_endpoint.json`, `:44001` writes `peer_endpoint_bot.json`.
  Log likewise `peer_listen.log` / `peer_listen_44001.log`.
- `chain3.py` -- `endpoint_net()` is now `endpoint_net(tag)`; owner reads
  `peer_endpoint.json`, bot reads `peer_endpoint_bot.json`.
  `match_ready(g, rid, tag)` passes the tag through.
- The TURN address blob (`CMD_SEND_TURN_ADDRESS_DATA`) used to be built ONCE
  outside the loop, so both sides published the same address.  It is now
  built per identity inside the loop.

Verified live: owner `3.80.79.52:44000` (held by stun_session.py),
bot `3.80.79.52:44001` (held by udp_punch.py with PEER_PORT=44001).

### Dead ends closed today (do not re-open)

- **Antenna heartbeat as the liveness key.**  `CMD_GET/SET_GAME_SESSION_CHECK_RES`
  are the `LATENCY_MODE_ANNTENA_*` in-match poll.  Implemented and proven:
  they return `set=NOERR get=NOERR finished=YES` in-match for both bots, and
  firing one IMMEDIATELY after START_GAME changes nothing.  Accepted, but not
  the resolve key.  (Still required pre-match: it is what clears
  `ERR_DATABASE` by flipping `is_check_finished` to YES.)
- **`gameend` open/closed as the submit gate.**  See mapstamp above.
- **Mid-match `CHECK_GAME_RESULT` polling cadence.**  Does not affect the
  stamp; only changes which value is observed.
- **`CMD_GET_TURN_SERVER_LIST`.**  Still `ERR_INVALIDARG`/`GKZX-` with
  room_id, with game_id, and with game_id+room.  The room is
  `game_sycom: "P2P"` and `gamerelay: NotImplement`, so the TURN list path
  appears gated off for P2P rooms.  Reply serializer wants
  `turn_server_list` + `turn_account`.
- **`gamerelay_list` in the SESSION_CHECK_RES reply.**  Not there.  The
  xrefs are in the *request* builder (`CMD_SET_LOCAL_GAMERELAY_LIST`, which
  answers NOERR bare) -- the client PUSHES the list it measured, it is not
  handed one.
- **A second Konami config host for the relay address.**  SNI sweep of the
  z2 capture: every Konami hostname is `pes22-game.cs.konami.net` (the gate).
  The rest is applilink.jp, CloudFront, Firebase, Adjust.  No separate
  config service.
- **The capture's DTLS relay identity is `turn.konami.com`** (cert CN,
  subject Tokyo/Minato-ku/Konami, issuer "OpenSSL Generated Certificate",
  validity 2019-2021).  `turn.konami.com` does NOT resolve publicly, and the
  capture's four relay allocations (34.22.210.195:30970, 35.233.88.176:32741,
  35.240.102.10:31406, 34.156.177.234:31840) are dead -- they are per-session
  TURN allocations, confirmed by no DTLS reply from any of them and by the
  binary carrying RFC 5766 TURN vocabulary
  (`E_TURN_ALLOCATION_MISSMATCH`, `E_TURN_QUOTA_ERROR`, `E_TURN_AUTH_ERROR`,
  `E_TURN_NOT_AVAILABLE`).

### `link_type` in statistical_data must stay `""` -- `LINK_TYPE_PEERS`
### BREAKS the pre-match check (run #10, my mistake, reverted)

`LINK_TYPE_PEERS` (0xb71fee) is referenced from `FUN_07f3ba98` and
`FUN_07f26c50` -- the P2P-SDK enum region.  The gate's
`statistical_data.link_type` is built in `FUN_078a259c` / `FUN_078a4574`.
Same key name, different subsystem.  Sending it as the value cascades:

```
check_res [owner] -> ERR_INVALIDARG  GKZX-      (was NOERR with "")
check_state  -> NO (NOERR)                      (was YES)
start_game [owner 23] -> ERR_DATABASE  EVDU-    (was NOERR)
```

i.e. the pre-match session check never finishes, so START_GAME is refused.
Reverted to `""` in both sites (pre-match echo + antenna_beat); run #11
retests the endpoint fix with link_type isolated.

## 12. The complete LATENCY registry (all 31 entries, from FUN_07f3b638
##     / FUN_07f34644 string table) -- and the missing CONNECT layer

Extracted in full from 11.1.0.  Ordered, grouped by parent phase:

```
MATCHING         CMD_START_MATCHING
                 PROCESS/POLLING_CMD_GET_MATCHING_RESULT
                 CMD_GET_SERVER_ENV
SESSION          PROCESS/POLLING_CMD_GET_GAME_SESSION
                 CMD_GET_TURN_SERVER_LIST
CONNECT          WAIT_SOCKET
                 CONNECT_SESSION
                 WAIT_CONNECT_SESSION_CONTROLLER
                 REVISION_CHECK
                 QUALITY_TEST
                 MODE_MULTIPLAY
ANNTENA          WAIT_QUALITY_CHECK
                 CMD_SET_GAME_SESSION_CHECK_RES
                 PROCESS/POLLING_CMD_GET_GAME_SESSION_CHECK_RES
                 USER_DATA_SYNC
                 CMD_GET_GAMEID
                 DISP_MATCHING_RESULT
PRE_MENU         TEAM_DATA_SYNC
                 READY_ALL_PLAYER
                 CMD_START_GAME
MATCH_SETTEING_INIT -> WHOLE_CONNECTING -> (match) -> CONFIRMING_RESULT
```

**`CONNECT` contains no gate commands.**  Every entry is socket/session
work: wait for socket, connect session, wait for the session controller,
revision check, quality test, enter multiplayer.  This is the P2P/DTLS data
plane -- the `turn.konami.com` DTLS session seen in the z2 capture.

**This is the layer chain3.py never performs.**  The chain goes
SESSION (`CMD_GET_GAME_SESSION` + `CMD_GET_TURN_SERVER_LIST`) and then
jumps straight to ANNTENA (`CMD_SET_GAME_SESSION_CHECK_RES`) and PRE_MENU
(`TEAM_DATA_SYNC` -> `READY_ALL_PLAYER` -> `CMD_START_GAME`).  The whole
CONNECT phase is skipped, so no session is ever established -- which is
precisely what `abnormal=DISCONN_HB` stamped within 2 s of START_GAME means:
the server expected a session from the CONNECT phase and never saw one.

This also finally orders the phases correctly against the earlier note:
CONNECT comes BEFORE ANNTENA, not after.  ANNTENA (the session-check
"antenna") runs once the data plane is up, to report its quality -- not to
create it.

### What each dead end taught us (all verified live, all negative)

| test | result |
|---|---|
| antenna heartbeat in-match (`SET/GET_GAME_SESSION_CHECK_RES`) | `set=NOERR get=NOERR finished=YES`, stamp unchanged |
| antenna fired IMMEDIATELY after START_GAME (t+0) | `NOERR`, stamp unchanged |
| `gameend` open vs closed as the submit gate | mapstamp: `INVALID` (open) through END, battery STILL `GKZX-` |
| mid-match `CHECK_GAME_RESULT` poll cadence | does not affect the stamp |
| distinct endpoints 44000/44001 (was: both 44000) | server echo now shows both, stamp unchanged |
| BOTH clients send `CMD_START_GAME` (was: owner only) | `start_game [bot 23] -> NOERR`, stamp unchanged |
| `CMD_GET_TURN_SERVER_LIST` with room_id / game_id / both | `ERR_INVALIDARG`/`GKZX-` all three |
| `statistical_data.link_type = LINK_TYPE_PEERS` | BREAKS pre-match check -> `START_GAME` ERR_DATABASE. Reverted |

Every one of these is a gate-side signal.  The gate is not where the match
lives.  `DISCONN_HB` is about the data plane that CONNECT was supposed to
build.

---

## 13. `abnormalend_reason` is CLIENT-computed; `DISCONN_HB` is a server stamp

Disassembled the reason-code dispatcher (file `0x07611400..0x07612400`,
`disconn_enum.dis`). It is a bank of ~22 tiny enum->string converters, each
loading one literal. Full vocabulary, in the order the converters appear:

| converter addr | string |
|---|---|
| 0x076115d0 | `CHANGE_VSCOM` |
| 0x07611640 | **`DISCONN_HB`** |
| 0x076116a4 | `DISCONN_SLEEP` |
| 0x0761170c | `DISCONN_KILL` |
| 0x07611908 | `NORMAL_GIVEUP` |
| 0x07611a30 | `NO_OPERATION` |
| 0x07611a9c | `PES_CMD_SENDFAILED` |
| 0x07611b04 | `COMPE_TIMELIMIT` |
| 0x07611c38 | `SYNC_FAILED` |
| 0x07611d08 | `LOAD_TIMEOUT` |
| 0x07611d74 | `GAMERELAY` |
| 0x07611dd8 | `P2P_FAILED` |
| 0x07611e40 | `BUFFER_OVER` |
| 0x07611eac | `DEGRADE_SC` |
| 0x07611f14 | `DISCONN_SC` |
| 0x07611f7c | `CMD_SENDFAILED` |
| 0x07611fe4 | `OUTPLAY_LONG` |
| 0x0761217c | `READY_TIMEOUT` |
| 0x076121e4 | `DISCONN_P2P_NTL` |
| 0x0761224c | `DISCONN_P2P` |
| 0x076122b8 | `DEGRADE_P2P` |
| 0x076123f0 | `NORMAL_END` |

`DISCONN_HB` is returned by `FUN_07711608`; `DISCONN_SC` by `FUN_07711edc`;
`DISCONN_P2P_NTL` by `FUN_077121ac`; `DISCONN_P2P` by `FUN_07712214`.

**The chain always sends `abnormalend_reason="NOERR"`** (`chain3.py:1200`
and the `sgr_request` template at :353) yet reads back `DISCONN_HB` from
`CMD_CHECK_GAME_RESULT`. So the value we receive is NOT the one we sent --
the server overwrites it. That closes the "pick the right reason string"
line of attack: there is no string we can send that changes the stamp.

Note the vocabulary contains `P2P_FAILED` / `DISCONN_P2P` / `DISCONN_P2P_NTL`
/ `GAMERELAY` -- the client CAN report a P2P failure itself. It reports
`DISCONN_HB` (heartbeat) instead, which is what the server-side session
watchdog raises, not what a client-side P2P failure looks like.

## 14. `timeout_settings` -- the client's own death clock

`FUN_07f1f33c` (`disconn_timeout.dis`) walks the `timeout_settings` config
object. Keys, in order:

    timeout_settings
      align_progress_abormal_end_timout_sec
      align_progress_ready_timeout_sec
      add_point_timout_sec
      get_game_result_timeout_sec
      wait_game_result_timeout_sec
      load_timeout_sec
      out_of_play_timeout_sec
      match_sync_failed_timeout_sec
      match_session_not_connected_timeout_sec
      match_session_disconneted_timeout_sec
        in_play / out_of_play
      match_not_run_timeout_sec
        in_play / out_of_play
      match_command_lack_mobile_timeout_sec
        in_play / out_of_play

The two that bear on the wall:

- `match_session_not_connected_timeout_sec` -- how long the client tolerates
  a session that never connected.
- `match_session_disconneted_timeout_sec` -- split `in_play` / `out_of_play`.
  This is the config the `DISCONN_HB` name is derived from: a session that
  was connected and then stopped heartbeating.

Both are read from the embedded config blob, not hardcoded (the same blob
that carries `game_result_timeout_sec: 45` and the 30 s phase/score
timeouts already extracted).


## 15. NTL `GateInfo.php` was silently failing in EVERY prior run (one-letter bug)

`ntl_gateinfo()` had never once succeeded in any chain run this session. Every
appearance was `{'error': 'TimeoutError timed out'}` and the cause was filed as
"NTL handshake DNS-flaky from this VM". Both halves of that were wrong.

**Byte-diffed the capture against what we send** (`diff_gateinfo.py`, from the
plaintext HTTP in `passthrough_capture.csv`):

| | captured (real client) | what chain3 built |
|---|---|---|
| Content-Length | **166** | **164** |
| JSON key | **`extra`** | **`extr`** |

The 2-byte gap is exactly the missing `a`. NTL does not time out on the wrong
key -- it answers **HTTP 200** with its own body `STATUS: 400`. Because the
chain only printed `{'error': ...}` on an exception, a clean 400 reply looked
identical to a dead endpoint.

**Confirmed by the game itself, not just the capture.** `FUN_07eeb090` builds
the request from a format string:

    {"titleCode":"%s","locale":"%s","version":"%s","extra":"%s","apiLevel":"%d"}

with `apiLevel` an integer (`%d`, value 4), not a string. `extra` is right there
in the binary. `extr` existed nowhere.

**Other defects fixed at the same time:**
- The captured request carries **no `User-Agent` and no `Connection` header**.
  chain3 was sending `User-Agent: okhttp/4.12.0` (inherited from a note about a
  different NTL call). Harmless once the key was right; dropped to match bytes.
- `chain3.ntl_gateinfo()` did a single `urllib.urlopen` with **no retry**. Now
  retries 4x with backoff per host and falls back to the capture's own resolved
  IP `35.174.175.11`, because DNS-by-hostname really is slow on this VM -- that
  part of the old diagnosis was true, and it is what made the first attempts
  look like a timeout.

**Verified live:** `chain3.ntl_gateinfo()` ->

    {"STATUS": "200", "API_STATUS": "1", "LOG_ACTIVE": "1",
     "SERVER_TIME": "1791762840",
     "PUT_LOG_URL": "http://ntl.service.konami.net/ntl/api/PES2022/ReportLog.php"}

The docstring previously claimed "Verified live ... -> STATUS:200". It had never
been true. Removed the false claim.

### What GateInfo actually is, and what it points at

`FUN_07eeb090` parses exactly five keys: `STATUS`, `API_STATUS`, `LOG_ACTIVE`,
`SERVER_TIME`, `PUT_LOG_URL`. There is **no session handle, no token, no peer
address**. GateInfo is a *config fetch*, and its main output is the URL to POST
logs to.

`PUT_LOG_URL` is server-assigned, which is why `ReportLog.php` never appears in
the binary's string table -- only `GateInfo.php` does. So the real client's flow
is: `GateInfo` -> read `PUT_LOG_URL` -> `ReportLog`.

### The ReportLog stream the real client emits (decoded from the capture)

`decode_reportlog.py` decodes the `dat=` hex field of every `ReportLog.php` POST.
It is the **NTL P2P SDK's own session log**, and it is the ground truth for the
`CONNECT` phase that `chain3.py` skips entirely:

- type **`pds`** = P2P session open, **`pde`** = P2P session close
- type **`uds`** = UDP session open, **`ude`** = UDP session close

One `pds`/`pde` pair brackets the session; the `uds`/`ude` pairs recur through
the match. Body form: `type=<t>&prefix=<ts>_<n>_<...>&ver=4&dat=<hex>`.

Decoded `dat` contents from a real match:

    ## NTLInfo       {"libVer":"1.17.1-Android-13"}
    ## AppInfo       {"StunInfo":"pesam.stun.service.konami.net:3478"}
    ## NetworkInfo   {"hostAddress":"10.57.220.5:26031"}
                     {"reflexiveAddrStr":"197.210.53.1:26031"}
                     {"relayedAddress":"0.0.0.0:0"}
    ## EventHistory  CONNECT TARGET_STUN_SERVER via HOST_DIRECT ep PEER_STUN
                     CONNECT TARGET_PEER     via HOST_DIRECT ep PEER_REFLEXIVE
    ## PeerDump      peerId 0  status CONNECTED
    ## StunAgentDump MappingTestIA/II/III, FilteringTestI/II

**`relayedAddress: "0.0.0.0:0"`** -- the real match used **no TURN relay at
all**. Pure direct P2P, `HOST_DIRECT`, `PEER_REFLEXIVE`, `status CONNECTED`.
That independently confirms our room is the right kind: `game_sycom: "P2P"`,
`gamerelay: "NotImplement"` is not a misconfiguration.

The STUN ladder is RFC 5780 NAT-behaviour discovery against
`pesam.stun.service.konami.net:3478` (MappingTest x3, FilteringTest x2) -- the
same sequence `stun_session.py` emulates.

### Why this matters for the wall

`chain3.py` has **never** completed an NTL handshake, and has **never** sent a
single `ReportLog`. The real client reports `pds` (P2P session open) before the
match and `uds`/`ude` through it, to a different host (`ntl.service.konami.net`)
than the gate (`pes22-game.cs.konami.net`).

`abnormal=DISCONN_HB` reads as "the session never existed". A client that never
announced `pds` is indistinguishable, from the server's side, from a session
that never existed. This is the first hypothesis for the wall that is *not* a
gate body-field guess -- it is a leg of the protocol we were simply not speaking.

### `report_log()` implemented -- the NTL leg chain3 never spoke

`chain3.py` now has `report_log(log_url, rtype)` and calls it at the three
points the capture shows the real client logging:

| when | type | meaning |
|---|---|---|
| right after `GateInfo` (post `START_GAME`) | `pds` | P2P session **open** |
| every 30 s poll during the match | `uds` | UDP session **open** |
| at teardown (after the last poll) | `ude`, then `pde` | UDP close, then P2P session **close** |

Body form, byte-for-byte from the capture:

    type=<t>&prefix=<epoch>_<seq>_<8hex>_<4hex>_<n>&ver=4&dat=<hex>

`dat` is hex of the NTL SDK's own diagnostic log; the real one opens with
`## NTLInfo` + `${"libVer":"1.17.1-Android-13"}`.  Our first cut sends just
that header block -- enough to be a well-formed entry, without yet faking the
STUN/peer dumps we have no business inventing (the photocopier rule: do not
fabricate a region).

`prefix` is generated per-call from `os.getpid()` + epoch so repeated `uds`
entries do not collide.

Live-verified: `report_log(url, "pds")` -> `STATUS: 200`.

The URLs come from `log_urls[tag] = gi.get("PUT_LOG_URL")`, captured per
identity from its own `GateInfo` reply, so each identity logs to the URL the
server assigned it.

## 16. Run #15 -- NTL + ReportLog fully working, `DISCONN_HB` unchanged (clean negative)

`chain3.py --live --poll --antenna` with the newly-corrected NTL leg.

**Every new leg succeeded:**

    ntl_gateinfo [owner] -> {'STATUS': '200', 'API_STATUS': '1', 'LOG_ACTIVE': '1',
                             'PUT_LOG_URL': '.../PES2022/ReportLog.php'}
    report_log  [owner] pds -> {'STATUS': '200'}
    ntl_gateinfo [bot  ] -> {'STATUS': '200', ...}
    report_log  [bot  ] pds -> {'STATUS': '200'}

plus `uds` at every 30 s poll and `ude`/`pde` at teardown.  Both identities
handshaked and both announced the P2P session open AND close, for the first
time in any run.

**And it made no difference at all.**

    phase 1ST_15MIN  -> NOERR
      poll[own] 1ST_15MIN gameend=DISCONN abnormal=DISCONN_HB
      poll[bot] 1ST_15MIN gameend=DISCONN abnormal=DISCONN_HB
      ... identical at 1ST_30MIN, BREAK1 (x2), 2ND, 2ND_30MIN (x2) ...

The stamp is present at the FIRST poll, before any of the in-match traffic.
**Hypothesis closed:** `abnormal=DISCONN_HB` is not "the session never existed
from the server's view".  We announced the session, on the correct host, in the
correct format, with the correct body, and the server stamped DISCONN_HB
anyway.

This is the second clean negative of the night and it has the same shape as
run #14 (live UDP data plane, no change).  Both legs the real client speaks
that we were entirely absent from are now confirmed **not** to be the gate.

### New, decisive observation from the FULL check

The `--precheck` FULL response now exposes the adjudication:

    "match_result": {"gameend_reason": "DISCONN",
                     "abnormalend_reason": "DISCONN_HB",
                     "game_res": "LOSE",
                     "score_data": {"home_score": 0, "away_score": 3},
                     "side": "HOME", "team_id": 396, ...}

The server had **already ruled the match a 0-3 walkover against HOME** before
we submitted anything.  `game_res`/`score_data` are pre-filled by the server,
not echoed from our `CMD_SET_GAME_RESULT`.  So the submit is not being refused
because the body is malformed -- the match is already closed, and any SET into
a closed match returns `ERR_INVALIDARG`/`GKZX-` regardless of body.

`side: "HOME"` + `team_id: 396` for the owner is also new information about
what the server thinks our seat is.

### Standing conclusion

Two independent "missing protocol legs" hypotheses (UDP data plane, NTL
handshake + session log) are now measured and eliminated.  The remaining live
explanation is that the match is being **closed by the server** for a reason
recorded in `timeout_settings` -- most likely
`match_session_disconneted_timeout_sec{in_play,out_of_play}` or
`match_not_run_timeout_sec` -- and the task is to find what the server requires
to consider the session *connected* and *running*.

## 17. `CMD_READY_FLAG` -- a real gate command the chain has NEVER sent

Exhaustive `CMD_` diff (24 commands `chain3.py` sends vs. every `CMD_` literal
in `fulldump_out.txt`) surfaced three names the chain never speaks.  One is a
real gate command:

    STR 00c0add2 CMD_READY_FLAG |07ea1e64@FUN_07ea1dc8 |07ea17e8@FUN_07ea1778

Both references are in the **NTL/GateInfo region** (`FUN_07eeb090` parses the
`SERVER_TIME`/`LOG_ACTIVE`/`PUT_LOG_URL` reply a few KB away).

### Body

Decoded from `FUN_07ea1778` (Ghidra `0x07ea1778`):

    msgid  = CMD_READY_FLAG
    rqid   = <envelope>
    flag   = <u32 bitmask>   ; written at obj+0x150 from the w1 argument

`FUN_07ea1778` is the *builder*; `FUN_07ea1dc8` is a near-duplicate (reads
`flag` twice).  Each has **exactly one caller**, so the dispatch site is known
and unambiguous:

    0x07b1fe0c  bl  ->  0x07ea1778   (inside FUN_07b1fda8, size 228)
    0x07b20a40  bl  ->  0x07ea1dc8   (inside FUN_07b20a1c region)

### It is sent only when a bitmask CHANGES

`FUN_07b1fda8` is a change-detector, decoded instruction by instruction:

    tst      w8, w9
    cset     w11, ne            ; w11 = (mask & bits) != 0
    cmp      w11, w10
    b.eq     -> early_ret       ; NO SEND if unchanged
    orr      w10, w8, w9        ; set path
    bic      w8,  w8, w9        ; clear path
    tst      w2,  #1
    csel     w8, w10, w8, ne    ; pick set vs clear
    mov      w1,  wzr           ; <-- builder arg = 0
    str      w8,  [x0, #0x850]  ; stash new mask at +0x850
    bl       FUN_07ea1778       ; CMD_READY_FLAG  with flag=0

So the builder's `flag` argument is passed as `wzr` here; the meaningful
bitmask is the one stored at `+0x850`.  The second site passes `w21`, loaded
by `mov w21, w2` -- i.e. `flag` is a **value the caller supplies**, and both
callers derive it from a state bitmask.

### Where it comes from -- the `Task\Match\` map

`FUN_07b1fda8` has **11 callers**.  Resolving each to its enclosing `FUNC` and
then to the `__FILE__` literal in that function:

    07c25978 (764)          -> OnlineModeTaskSyncMatchSettings.cpp
    07c2c95c (492)          -> OnlineModeTaskSyncSideSelect.cpp
    07c3b73c (312)          -> OnlineModeTaskSyncTeamSelect.cpp
    07c3f108 (512)          -> OnlineModeTaskSyncMatchSettings.cpp
    07c4476c (468)          -> OnlineModeTaskSyncSideSelect.cpp
    07c4695c (476)          -> OnlineModeTaskSyncTeamSelect.cpp
    07c48d18 (1656)         -> OnlineModeTaskSyncUserData.cpp   (x2 callers)
    08237a2c / 08238424 / 08246684  (no enclosing FUNC -- tail/veneer region)

These are the **`OnlineModeTask\Match\` state tasks**, and the binary carries
its full source path.  The complete enumerated set:

    OnlineModeTaskAlignProgress          <- name == the timeout key
                                           `align_progress_abormal_end_timout_sec`
    OnlineModeTaskCheckCheat             <- anti-cheat, runs on a bot
    OnlineModeTaskCreatePlatformGameSession
    OnlineModeTaskMatchCommissioner      <- the match overseer
    OnlineModeTaskMatchSession
    OnlineModeTaskMultiplaySession
    OnlineModeTaskSelectableSettingsList
    OnlineModeTaskSyncManager
    OnlineModeTaskSyncMatchSettings
    OnlineModeTaskSyncSideSelect
    OnlineModeTaskSyncTeamData
    OnlineModeTaskSyncTeamSelect
    OnlineModeTaskSyncUserData
    OnlineModeTaskWatchGameResult

String addresses (Ghidra):
`bf7215` SyncManager, `c44773` MatchSession, `ccaeee` CheckCheat,
`cde146` MatchCommissioner, `d0414c` AlignProgress.

### Why this is the strongest lead so far

Every hypothesis tested tonight was a *missing leg we were absent from*
(UDP data plane, NTL handshake, ReportLog).  Those are now closed.  This is
different in kind: `CMD_READY_FLAG` is a command the server can be expected to
require as a **liveness precondition**, it is emitted by the match task layer,
and it is gated on *state change* -- which a polling bot that never changes
state would never trigger.  That is exactly the shape of a
`DISCONN_HB` ("stopped sending") failure.

Two things still to pin before a run: the correct `flag` bitmask, and which
phase it must be sent in.

## 18. Run #16 -- `CMD_READY_FLAG` is NOT a gate command (clean negative)

Wired `CMD_READY_FLAG` (found in §17) into `chain3.py --live --poll --antenna`,
sent for both identities right after `START_GAME` (the pre-verdict window) and
then rotated through masks 0/1/2/3 on every 30 s in-match beat.

**Every single send failed identically:**

    ready_flag[owner] flag=0 -> _DECODE_FAIL
      {"result": "_DECODE_FAIL", "_status": "Not Found",
       "_err": "Data must be padded to 16 byte boundary in CBC mode",
       "_len": 36}

`_status: Not Found` + the CBC padding message is the **transport-layer decode
error**, which in this codebase means *no gate endpoint exists* -- NOT a state
refusal.  Every real gate command returns `NOERR` or a *state* error
(`ERR_INVALIDARG` / `GKZX-`).  A 404 with a padding error means the request
never reached a command handler.

So there is **no `CmdReadyFlag.php`**.  The `flag` value was never the question
-- no mask would have worked.  (The `.php` suffix is what distinguishes a gate
command; chain3's 24 working commands all carry one.)

Polls were entirely unaffected:

    poll[own] 1ST_15MIN gameend=DISCONN abnormal=DISCONN_HB
    poll[bot] 1ST_15MIN gameend=DISCONN abnormal=DISCONN_HB
    ... (identical through BREAK1) ...

### Why this negative is still worth having

`CMD_READY_FLAG` looked, on paper, like the best lead of the night: a real
command name in the binary, two builders, a change-gated sender, and 11 callers
all in the `Task\Match\` sync layer.  Every structural signal said "in-match
liveness command".  It turned out to be an **internal, non-gate** signal.

The lesson that generalises: **a `CMD_*` name in the string table does not imply
a gate endpoint.**  The only reliable test is whether the server answers with a
state error (real command, wrong state) vs. the 404/padding decode error (no
endpoint at all).  Any future command candidate must pass that test before it
earns a full chain run.

### Side finding: the complete client-side error vocabulary

Discovered while chasing the `ERR_DEFCLIENTVER` seen in run #14.  `FUN_077039f8`
lazily builds one string per enum slot, in this exact order (each preceded by a
`tbz/tbnz w8,#0` cached-flag pair):

     0 ERR_CONNECT_SERVICE        10 ERR_SUSPEND
     1 ERR_TIMEOUT                11 ERR_ONLINE_PRIVILEGE
     2 ERR_LINKDOWN               12 ERR_SIGNEDOUT
     3 ERR_MEMORY                 13 ERR_OPTION_OUTOFRANGE
     4 ERR_ONLINE                 14 ERR_RESULT_OUTOFRANGE
     5 ERR_FILEIO                 15 ERR_GATEWAY_TIMEOUT
     6 ERR_FATAL                  16 ERR_INVALIDARG     <-- what every SET gets
     7 ERR_UNKNOWN               17 ERR_DEFCLIENTVER   <-- the 4x entry_side hit
     8 ERR_BAD_STATUS_CODE        18 ERR_NONSUPPORT
     9 ERR_SERVICE_UNAVAIL

Two consequences:
- **`ERR_INVALIDARG` (16) and `ERR_DEFCLIENTVER` (17) are adjacent** enum
  entries.  The four `ERR_DEFCLIENTVER` hits in run #14 were the *default
  client-version* slot, emitted from `FUN_077039f8`, which shares a block with
  `ERR_CONNECT_SERVICE` -- i.e. it belongs to the **CONNECT phase chain3 skips
  entirely**.  It is a version bookkeeping artifact, not a defect in our bodies.
- The adjacency means an off-by-one in whatever the server checks could surface
  either error, so the two should be reasoned about together, not separately.

## 19. The complete top-level phase registry, and what chain3 skips

`FUN_07f3b638` registers every top-level phase in enum order.  This is the
whole match lifecycle, and it is the map that shows the gaps:

    idx  LATENCY_MODE_*                          chain3 coverage
    ---  --------------------------------------  ------------------------
     0   MATCHING                                partial
     1   SESSION                                 yes
     2   CONNECT                                 ** NONE -- skipped **
     3   ANNTENA                                 yes
     4   PRE_MENU                                yes
     5   MATCH_SETTEING_INIT                     partial
     6   WHOLE_CONNECTING                        ** NONE **
     7   CONFIRMING_RESULT                       yes

CONNECT's sub-phases, in the same registry order (confirmed, correcting the
earlier prose ordering):

    WAIT_SOCKET -> CONNECT_SESSION -> MODE_MULTIPLAY
      -> WAIT_CONNECT_SESSION_CONTROLLER -> REVISION_CHECK -> QUALITY_TEST

The ANNTENA sub-phases (the block chain3 already exercises) are
`WAIT_QUALITY_CHECK -> CMD_SET_GAME_SESSION_CHECK_RES ->
 PROCESS_CMD_GET_GAME_SESSION_CHECK_RES ->
 POLLING_CMD_GET_GAME_SESSION_CHECK_RES -> USER_DATA_SYNC ->
 CMD_GET_GAMEID -> DISP_MATCHING_RESULT`.

The two unexercised phases are **CONNECT (idx 2)** and **WHOLE_CONNECTING
(idx 6)**.  `WHOLE_CONNECTING` is the interesting one: by name it spans the
entire connection window -- exactly where the server stamps `DISCONN_HB`.
This is now the single largest structural gap, and unlike the dead ends it is
a *phase the real client enters and we never do*.

### `CMD_REVISION_CHECK` -- rejected WITHOUT a chain run

Both builders (`FUN_07ea3d88`, `FUN_07ea25c8`) are the same
`NotImplement`-sentinel descriptor shape as `CMD_SET_GAME_RESULT`, which made
it look like a real gate command.

But the §18 test settles it for free: **there is no `CmdRevisionCheck.php`**
in the 337-endpoint `Cmd*.php` inventory (checked; only `CmdCheck*.php` names
exist, none for revision).  It is therefore another internal, non-gate command,
same as `CMD_READY_FLAG`.

Its `is_revision_check` body field is referenced exactly once, at
`FUN_07840324` -- an ordinary field, no gate coupling.

**This is the §18 rule paying off.**  Two candidates that looked structurally
identical to real commands (`CMD_READY_FLAG`, `CMD_REVISION_CHECK`) were both
eliminated by checking for a `.php` endpoint, at zero run cost.  Any future
candidate gets that check before it earns a 6-minute run.

### Net state after runs #15 and #16

Both were clean negatives on the two strongest structural hypotheses of the
night:

- #15: NTL handshake + full ReportLog session lifecycle (`pds`/`uds`/`ude`/`pde`)
  -- all `STATUS: 200`, `DISCONN_HB` unchanged.
- #16: `CMD_READY_FLAG` -- no gate endpoint, `DISCONN_HB` unchanged.

Every "missing protocol leg" theory is now measured and eliminated.  What
remains is the phase-registry gap above, which is a different kind of
hypothesis: not a body field or a missing message, but an entire phase the
real client enters (CONNECT / WHOLE_CONNECTING) that the chain never does.


---

## 20. `gate_map.py` -- the authoritative CMD_ -> endpoint map, and the
##     server's own config (`CMD_GET_SERVER_ENV`)

### 20.1 The map, and why it can be trusted

Every gate command's descriptor builder references **both** its `CMD_` name
and its `CmdXxx.php` route from the *same* function. Verified directly on
`CMD_SET_GAME_RESULT`: `FUN_078a0f7c` touches `CMD_SET_GAME_RESULT` and
`CmdSetGameResult.php`. Internal, non-gate signals reference the `CMD_` name
but **no** `.php` -- which is exactly what killed `CMD_READY_FLAG` in §18.

`work/gate_map.py` exploits this to settle "is it a gate command?" for **all**
names at once instead of one 6-minute chain run each. It groups the STR
xrefs by function (`fulldump_out.txt`) and reports a `CMD_` as a gate command
iff some single function names both it and a `.php`.

Result:

    CMD_ names in binary      : 358
    resolved as GATE commands : 337      <- exactly the 337 Cmd*.php routes
    chain3.py sent            : 23

The map **independently reproduces §18**: `CMD_READY_FLAG` appears under
"chain3 sends but NOT resolved to a .php" -- the same 404 the gate returned
in run #16. The other two unresolved were `CMD_TEAM_DATA_SYNC` /
`CMD_USER_DATA_SYNC`, which chain3 *does* send successfully via a dynamic
name, so those two are map false-negatives (co-reference heuristic), not
protocol facts.

**87 gate commands are never sent by chain3.** The match/session/connect
subset:

    CMD_ADD_FOUL                         -> CmdAddFoul.php
    CMD_CONNECT_GRPC                     -> CmdConnectGrpc.php        (stub)
    CMD_CREATEJOIN_ROOM                  -> CmdCreatejoinRoom.php
    CMD_GET_GAMERELAY_QUALITYCHECK_LIST  -> ...QualitycheckList.php
    CMD_GET_MATCHING_RESULT              -> CmdGetMatchingResult.php
    CMD_GET_REQUESTED_JOIN_ROOM_INFO     -> CmdGetRequestedJoinRoomInfo.php
    CMD_GET_ROOM_LIST                    -> CmdGetRoomList.php
    CMD_GET_SERVER_ENV                   -> CmdGetServerEnv.php
    CMD_GET_TURN_ADDRESS_DATA            -> CmdGetTurnAddressData.php
    CMD_GET_VSCOM_GAME_RESULT / _OPPONENT
    CMD_JOIN_GAME_MODE                   -> CmdJoinGameMode.php
    CMD_JOIN_ROOM / CMD_LEAVE_ROOM / CMD_RETURN_ROOM
    CMD_LEAVE_GAME_MODE                  -> CmdLeaveGameMode.php
    CMD_SEND_JOIN_ROOM_REQUEST           -> CmdSendJoinRoomRequest.php
    CMD_SEND_SESSION_ID                  -> CmdSendSessionId.php
    CMD_SET_GAMERELAY_QUALITY            -> CmdSetGamerelayQuality.php
    CMD_SET_MATCHING_OPTION              -> CmdSetMatchingOption.php
    CMD_SET_PLAYDATA_MATCH               -> CmdSetPlaydataMatch.php
    CMD_SET_ROOM_SETTINGS                -> CmdSetRoomSettings.php
    CMD_UNSET_ROOM_MATCH_READY           -> CmdUnsetRoomMatchReady.php

### 20.2 Bodies recovered for the above (subagent extraction, 11.1.0)

    CMD_GET_TURN_ADDRESS_DATA   request: (EMPTY)   response: address,
                                                    address_data_size
    CMD_GET_GAMERELAY_QUALITYCHECK_LIST  request: (EMPTY)
        response: quality_check_data_list{...}, quality_threshold_1,
                  quality_threshold_2, quality_list
    CMD_SET_GAMERELAY_QUALITY   request: quality_list[{region,quality,last_update}]
    CMD_GET_SERVER_ENV          request: lang,region,platform,client_version
                                  (all default absent)
    CMD_SEND_SESSION_ID         request: game_id,
                                  platform_session_id_info{ps_session_id,
                                                           xb_session_id}
    CMD_SET_PLAYDATA_MATCH      request: play_data, match_team_play_data
    CMD_GET_MATCHING_RESULT     request: room_id:{<key>: int64}
                                  response: matching_state, member,
                                            strike_arena_team
    CMD_SET_MATCHING_OPTION     request: ping_level, team_power_limit,
                                  control_style_filtering ("NO")
    CMD_JOIN_GAME_MODE          request: game_mode, client_version,
                                  livedata_version
                                  response: result.ping_level,
                                            result.team_power_limit
    CMD_ADD_FOUL                request: game_id, card_user_id, card_side,
                                  card_gameplayer_id{id,serial}, card_kind,
                                  injury_user_id, injury_side,
                                  injury_gameplayer_id{id,serial},
                                  gtimer, phase, match_minute
    CMD_JOIN_ROOM               mode, room_id{id}, event_id, password,
                                  is_need_password ("NO"),
                                  address_ipv4{host_address,host_port,
                                  reflexive_address,reflexive_port,nat_type}
    CMD_SET_ROOM_SETTINGS / CMD_UNSET_ROOM_MATCH_READY / CMD_LEAVE_ROOM /
    CMD_RETURN_ROOM / CMD_CREATEJOIN_ROOM -- see the subagent reports in this
    session; all follow the same ctor/builder/response-parser triple.

### 20.3 **RETRACTION: `CMD_JOIN_GAME_MODE` is NOT a NotImplement stub**

An earlier note (carried in §8 and in chain3's own comments) said
`FUN_0786da14` returns the literal `"NotImplement"`, making JOIN_GAME_MODE a
client-side stub. **That is wrong.** `FUN_0786da14` is the *void response
object's ctor*: it copies `CMD_JOIN_GAME_MODE` + `CmdJoinGameMode.php` into
the object and seeds two response string fields with the absent-sentinel.
It references the `.php` route. The real request builder is `FUN_0786d1f0`.

Generalised rule: **each command registers TWO ctors (request object +
response object); both reference the CMD name and the `.php`; the builders
and parsers are separate vtable methods.** So "the function I looked at just
stores NotImplement" is not evidence of a stub -- you must find the *builder*.

### 20.4 The server's own config, decoded

`CMD_GET_SERVER_ENV` returned `NOERR` for both identities. Two fields,
`proto_opt` and `onsys_opt`, are **base64-encoded JSON**. `work/decode_env.py`
decodes them (note: chain_run*.log is written by PowerShell `*>` as UTF-16 --
detect it, do not assume UTF-8).

`onsys_opt` (authoritative server-side config):

    default:
      onmode:
        quality_check_timeout_msec       = 30000
        get_game_result_error_sec       = 30
        game_result_timeout_sec         = 45
        at_match_polling_interval_msec  = 30000
        livedata_hash_calculation_mode  = 'async'
      timeout_settings:
        align_progress_ready_timeout_sec = 40
      timeout:                                  <- PER-COMMAND TABLE
        CMD_ADD_SCORE        = 30
        CMD_ADD_FOUL         = 30
        CMD_CHANGE_GAMEPHASE = 30
      invitation_task:
        enable             = True
        use_http_command   = False
      connect_grpc_task:
        disable            = True
      onmatch:
        set_concurrent_ad_requests = 2

`proto_opt`:

    CS.Network:
      CmpNetworkIoVersion                              = 0
      DcTestProbeDataLength                           = 2
      DcTestUdpPingRequestLength                      = 2
      DcTestForClientServerModeRecommendedRegionMode  = 2
      DcTestForClientServerModeRecommendedRegionThreshold = 10
    CS.MatchCommandBufferingControl:
      PredictKeepBufferSizeDeltaFromMatchStopCountEnable = False
    CS.Match / P2P.Match:
      NoMoveOperationTimeoutMs = 120000
    Device: 3 preset rows (EnableManufactureModelNamePresetType 0/1/2)

Three conclusions the config settles outright:

* **`connect_grpc_task.disable = True`** -- the server itself disables the
  gRPC connect task. The `CMD_CONNECT_GRPC` path is not merely a client stub;
  it is switched off server-side. (The gRPC *beats* chain3 sees are a separate
  antenna channel and keep working.)
* **`invitation_task.use_http_command = False`** -- invitations do not travel
  as gate HTTP commands at all.
* **`communication_antenna_status_info = {antenna_5_limit:30,
  antenna_4_limit:120, antenna_3_limit:171, antenna_2_limit:209}`** (the `_cs`
  variant is 15/50/110/200). These are antenna signal thresholds.

---

## 21. Runs #17 and #18 -- the 30 s table, and a closed timing hypothesis

### 21.1 Run #17 (`chain_run17.log`)

Four commands added; **all returned `NOERR` for both identities**:

    get_turn_addr[owner/bot]  -> NOERR
    server_env[owner/bot]     -> NOERR   (config in 20.4)
    send_session_id[owner/bot]-> NOERR
    playdata[own/bot] x7      -> NOERR

`DISCONN_HB` unchanged.

**Correction to this session's own earlier claims.** Only two of those four
were genuinely new. chain3 *already* implemented `CMD_GET_TURN_ADDRESS_DATA`
(`turn_addr [... GET_TURN_ADDRESS] -> NOERR`) and `CMD_SEND_SESSION_ID`
(`sess_id [...] -> NOERR`) under different helpers; they were absent from
`gate_map.py`'s "sent" set only because that set is parsed from literal
`envelope("...")` calls and these go through a different code path. The
"CONNECT-phase GET gap" and "SESSION-phase SEND gap" were therefore **not**
gaps. `CMD_GET_SERVER_ENV` and `CMD_SET_PLAYDATA_MATCH` were the real
additions.

### 21.2 Run #18 (`chain_run18.log`) -- the in-match command window

Run #17's timeline put the first in-match timeout-table command
(`CMD_CHANGE_GAMEPHASE`, 1ST_15MIN) at **t+61.1s**, exactly **30.5 s** after
`START_GAME` at t+30.6s -- with the server's `timeout` table saying
`CMD_CHANGE_GAMEPHASE = 30`. The gap was spent on NTL, ReportLog x2,
ready_flag, antenna and TURN setup. Hypothesis: the first table command must
land inside 30 s.

Fix: advance the phase **immediately** on START_GAME, ahead of all setup
traffic (`early_phase`), and run `--realorder` goals.

Result:

    early_phase 1ST_15MIN -> NOERR
    phase 1ST_15MIN  -> NOERR    goal 12' HOME -> NOERR
    phase 1ST_30MIN  -> NOERR    goal 34' HOME -> NOERR
    phase BREAK1     -> NOERR
    phase 2ND        -> NOERR    goal 61' AWAY -> NOERR
    phase 2ND_30MIN  -> NOERR
    phase END        -> NOERR

    poll[own|bot] every phase -> gameend=DISCONN abnormal=DISCONN_HB

**Clean negative.** Hypothesis closed.

### 21.3 Why it could not have worked (binary evidence)

A parallel extraction traced `FUN_07f1e778` = `GetTimeout(obj, key)`, which
reads `obj+0xb0["timeout"][key]` (thunk `FUN_07f16dac` -> `this+0x6a0`), and
returns 0 when the key is absent. It has **exactly four** call sites:

    077e23d4   key literal `CMD_GET_GAME_RESULT`
    077e3ac0   key literal `CMD_GET_GAME_SESSION`
    07cfd87c   key `SERVER_UNAVAIL`
    FUN_07d00d4c @ 07d00e68   dynamic per-command name (object+0x120),
                              cached at object+0x398

For the three in-match commands the value is written into the request record
at **request+0x158** as a seconds budget (ctor `FUN_07bd9078`, record 0x1f0
bytes, appended via `FUN_07bdf6c4`). Nothing compares it to a clock delta and
nothing multiplies it by 1000. It is a **per-request processing budget
(interpretation C)** -- how long to wait for that command's reply -- **not**
a first-delivery deadline (A) and not a staleness limit (B).

Decisively, the client *does* implement the (B) pattern explicitly, at the
`SERVER_UNAVAIL` site: `delta = now - [x19+0x180]; limit = timeout? timeout*1000 : 3000; if (delta >= limit) -> state 9`. The authors write (B) by hand when
they mean it. They did not here.

Source files observed: `OnlineSystemCommandObjectBase.cpp` (`FUN_07cfcb2c`),
`CommandObjectCmdChangeGamephase.cpp` (`FUN_0777ffc0`), and per-command ctors
`FUN_0776fa48` (CmdAddScore), `FUN_0776cc24` (CmdAddFoul),
`FUN_0777ffc0` (CmdChangeGamephase). No single function references all three
names; the shared plumbing is the name/enum table `_INIT_11523` (refs
07f0bf14 / 07f0bf4c / 07f0bf70).

### 21.4 Where this leaves `DISCONN_HB`

After runs #17 and #18 chain3 now sends **every in-match command the server's
own config names** -- `CMD_CHANGE_GAMEPHASE`, `CMD_ADD_SCORE` -- plus
`CMD_SET_PLAYDATA_MATCH`, and **all are accepted `NOERR` with real match
minutes and scorers**. `DISCONN_HB` is stamped regardless, at the first poll,
and the server has already adjudicated the match (`game_res: LOSE`,
`score_data: 0-3`) by then.

So `DISCONN_HB` is **not** a function of in-match command delivery, timing,
or content. It is decided before any of them matter. The only structural gap
still standing is the one named in §19: chain3 never enters **CONNECT** or
**WHOLE_CONNECTING**. Run #19 attacks `CONNECT/MODE_MULTIPLAY` via
`CMD_JOIN_GAME_MODE` -> `CMD_SET_MATCHING_OPTION` (the feed-forward pair from
20.2/20.3), since the JOIN reply supplies exactly the two fields the OPTION
command takes.



---

## 22. Run #19 -- `MODE_MULTIPLAY` refused (`GKZX-`), and what that proves

`CMD_JOIN_GAME_MODE` and `CMD_SET_MATCHING_OPTION` were wired just before
`START_GAME`:

    join_game_mode[owner] -> ERR_INVALIDARG  errcode=GKZX-
    join_game_mode[bot  ] -> ERR_INVALIDARG  errcode=GKZX-
    match_opt[owner] ping=0 tpl=0 -> ERR_INVALIDARG  errcode=GKZX-
    match_opt[bot  ] ping=0 tpl=0 -> ERR_INVALIDARG  errcode=GKZX-

    poll[own|bot] every phase -> gameend=DISCONN abnormal=DISCONN_HB

Every other command in the run was `NOERR` (early_phase, all six phases, all
three `--realorder` goals).

### 22.1 This is the §18 test passing, not failing

`GKZX-` is a **state** refusal. The failure that means "no such endpoint" is
the 404 + `"Data must be padded to 16 byte boundary in CBC mode"` + `_len: 36`
signature that `CMD_READY_FLAG` produced in §18. `CMD_JOIN_GAME_MODE` did not
produce that. **The endpoint exists and the command is real** -- confirming
the `gate_map.py` resolution of `CmdJoinGameMode.php` and the §20.3
retraction of the "stub" claim. The only error is *when* we sent it.

### 22.2 Why that placement was never going to work

`CMD_SET_MATCHING_OPTION`'s body is `ping_level`, `team_power_limit`,
`control_style_filtering` -- **matchmaking preferences**. You declare them so
the matcher can pair you fairly. A custom-room match (`CFG["mode"]="CUSTOM"`,
`LOBBY_ROOM_MATCH_1VS1`) never enters matchmaking: there is no matcher, so
there is no state in which those two commands are legal. `MODE_MULTIPLAY`
being a *sub-phase of CONNECT* is a registry fact, but for a custom room the
CONNECT work is the TURN/punch exchange (§4), not a mode-join.

Recorded so this placement is not retried. The commands themselves are real
and would apply to a ranked/anonymous match; they are out of scope for the
custom-room chain.

### 22.3 Consequence for the CONNECT gap

Run #19 therefore did **not** close the CONNECT gap -- it removed one of its
three candidate sub-phases. What remains untested inside CONNECT is the one
that is actually last and actually reachable:

    ... -> REVISION_CHECK -> QUALITY_TEST

`QUALITY_TEST` is the final CONNECT sub-phase, immediately upstream of
`WHOLE_CONNECTING`, and it is a GET/SET pair that chain3 has never sent:

    CMD_GET_GAMERELAY_QUALITYCHECK_LIST   request: (EMPTY)
        response: quality_check_data_list, quality_check_data_list_num,
                  quality_threshold_1, quality_threshold_2,
                  quality_list, quality_list_num
    CMD_SET_GAMERELAY_QUALITY             request: quality_list[
                                          {region, quality, last_update}]

Run #20 sends the pair, grading the report with the gate's OWN
`quality_threshold_1` / `quality_threshold_2` rather than invented values.

## 23. The real client, captured live 2026-10-12 -- ground truth replaces inference

Everything above §22 was derived from `libUE4.so` disassembly and probe runs.
On 2026-10-12 we captured a **genuine client** end-to-end (login -> friend
room create/join -> full match -> accepted result) through the MITM proxy and
decrypted it (`work/cap/flows-final.log`, 138 gate blocks; `dump_final.py`
parses it). This is the first time the actual wire order and bodies are known
rather than reconstructed. Key results:

### 23.1 The real room->result sequence (accepted, `result:NOERR`)

    CMD_CREATEJOIN_ROOM            -> room_id, NOERR   (NAT block: host/reflexive/nat_type)
    [~45x CMD_GET_ROOM_INFO poll]
    CMD_CHECK_MATCH_ENABLE         -> NOERR (manner A)
    CMD_SET_ROOM_MATCH_READY       -> NOERR (gamerelay_measure_result=COMPLETE + NAT block)
    CMD_GET_GAME_SESSION           -> gamerelay{name,region,ip_addr,port}, game_sycom
    CMD_GET/SET_GAME_SESSION_CHECK_RES (a few)
    CMD_GET_GAME_ID                -> game_id   (note: request room_id is `{}`, empty)
    CMD_CHANGE_GAMEPHASE
    CMD_START_GAME                 -> match_category=MYCLUB_LOBBY_ROOM_MATCH_1VS1
    [ingame: CHANGE_GAMEPHASE many, ADD_SCORE x2, ADD_FOUL x2]
    CMD_SET_GAME_RESULT            -> NOERR
    CMD_GET_GAME_RESULT            -> the stored result

Commands chain3 fires that the real client **never** sends in a custom-room
match (all binary-inferred, all absent here): `CMD_READY_FLAG`,
`CMD_GET_TURN_SERVER_LIST`, `CMD_GET/SEND/WATCH_TURN_ADDRESS_DATA`,
`CMD_JOIN_GAME_MODE`, `CMD_SET_MATCHING_OPTION`, `CMD_SEND_SESSION_ID`,
`CMD_SET_PLAYDATA_MATCH`, `CMD_USER_DATA_SYNC`, `CMD_TEAM_DATA_SYNC`,
`CMD_SET_ROOM_USER_ENTRY_SIDE`. (Caveat: gRPC-stream commands such as
`CMD_HEARTBEAT_GRPC` would not appear in an HTTP capture, so their absence
here is not proof they are unused.)

### 23.2 The three real/bot mismatches that were fixed

1. **`SET_GAME_RESULT` body** -- the old builder omitted keys whose source
   vector was empty, on the authority of a serializer disassembly. The live
   capture proves the opposite: the real client **sends them empty**:
   `achievement_progress_list: []`, `owngoal_user_list: []`,
   `tour_pvp_bonus_result_list: []`; plus `behind_flag: ["YES","NO"]` and
   `opp_gameplayer_id_list` (11 entries, opponent XI only). `error_code` is
   `"_0x0"` not `"0"`. `game_check_data` carries BOTH 23-entry parameter
   lists. `analyst` carries a real `match_json` string, empty
   `advice_info_list`, `is_invalid_advice:"YES"`. After the rebuild,
   `verify_sgr.py` confirms all three sections match the capture
   **key-for-key, same order**.
2. **`SET_ROOM_MATCH_READY`** -- real sends `is_single_matching:"NO"` +
   `gamerelay_measure_result:"COMPLETE"` (bot had `YES`/`MEASUREING`).
3. **`START_GAME`** -- real `match_category` is
   `"MYCLUB_LOBBY_ROOM_MATCH_1VS1"` (bot omitted the `MYCLUB_` prefix).

### 23.3 P2P vs relay -- what the capture does and does not settle

The gate assigned a relay endpoint (`gamerelay.name=pesms-hd-...`,
`region=europe-west9`, `ip_addr` -> Google Cloud `34.163.149.29:5735` /
`34.163.163.69:5736`). But `game-final.pcap` is **100% TCP (75,889 packets,
zero UDP)** because the recorder DNATed only `-p tcp --dport 443`. So the
gameplay path (P2P punch vs relay fallback) was never on the captured wire.
The three fixes in §23.2 all come from the TCP gate channel, which is fully
captured and carries **no transport field** -- so they hold regardless of
P2P/relay. The bots' own P2P setup (each advertises its STUN-punched endpoint
in `address_ipv4`) is untouched. If `DISCONN_HB` turns out to live in the
gameplay transport, this capture cannot show a working example (no UDP).

### 23.4 Run #21 (2026-10-12) -- the result wall BREAKS; the NAT wall remains

First live run with the §23.2 rebuilt body (`--live --poll --realorder`):

**`CMD_SET_GAME_RESULT` accepted for the first time.**
`set_result [own roomid] -> NOERR (t+30.0s)` and the battery's
`[owner NOERR] -> ['own:NOERR']`. The empty-lists / `_0x0` / both-check-lists /
real-`match_json` rebuild is correct. Every prior run since #1 got
ERR_INVALIDARG/GKZX- here; that wall is gone.

**But the match was already walked over.** The first in-match poll (1ST_15MIN)
read `gameend=DISCONN abnormal=DISCONN_HB`, and every poll after. The server's
stored verdict ignored the submitted 2-1 and stamped its own walkover
`game_res=LOSE score_data 0-3`. So the result is accepted as a *submission*
but the *outcome* was decided at START_GAME.

**Root cause is NAT proof, not the body.** The server's `ntl_address_list`
holds BOTH bots at `host_address 3.80.79.52` (ports 44000/44001) -- one IP,
two peers. That is impossible NAT proof, so the server stamps DISCONN_HB at
START_GAME (the §11 finding). Fixing the body cannot help until the two
identities present endpoints on SEPARATE IPs (separate VMs/regions) for the
hole-punch to be believable.

Side observations from #21: `CMD_GET_GAME_ID` with the real client's empty
`room_id: {}` was NOT what got game_id (the `map-int` form did); `READY_FLAG`,
`USER_DATA_SYNC`, `TEAM_DATA_SYNC` all return `_DECODE_FAIL` (404 HTML, not
encrypted gate replies -- they have no .php route and are noise to strip);
`SET_GAMERELAY_QUALITY` -> ERR_DATABASE `EVDU-`; `GET_TURN_SERVER_LIST` ->
ERR_INVALIDARG `GKZX-` in every body form.

**Net: ERR_INVALIDARG on the result is SOLVED. The remaining wall is
DISCONN_HB from single-IP NAT proof.**

### 23.5 Run #22 (2026-10-12) -- the NAT-shape hypothesis is TESTED and FAILS

Two changes were tested against run #21, same flags (`--live --poll
--realorder`):

1. **Noise-command strip** (§23.1's never-sent list: `GET_TURN_SERVER_LIST`,
   `USER_DATA_SYNC`, `TEAM_DATA_SYNC`, `READY_FLAG`, mid-room
   `SET_GAMERELAY_QUALITY`, `SEND/GET_SESSION_ID`, TURN-list probes).  Result:
   **the result path still returns `NOERR`** (`set_result [own roomid] ->
   NOERR`), and the stored `analyse_json` came back as a real 347-char string
   (our `match_json` was fully processed).  The strip is safe -- the lean
   capture-faithful flow submits a valid result.  KEEP IT.

2. **NAT-shape fix** (`endpoint_net` now advertises a PRIVATE loopback
   `host_address` 127.0.0.2/127.0.0.3 distinct from the public
   `reflexive_address`, matching the real client's local-vs-reflexive split).
   Result: **DISCONN_HB is STILL stamped at the first in-match poll.**  The
   shape fix does NOT help.

**Correction of the §23.4 root cause.**  Run #22 is decisive evidence that
`DISCONN_HB` is NOT caused by the address/NAT shape at all:

- After the fix, the two bots' advertised host addresses are 127.0.0.2:44000
  and 127.0.0.3:44001 -- two endpoints on the SAME machine, perfectly
  reachable over loopback, no NAT traversal needed between them.
- The TURN address exchange confirms the gate stored and returned exactly
  those: `WATCH_TURN_ADDRESS` -> `127.0.0.3:44001` (owner) and `127.0.0.2:44000`
  (bot), base64.  So the punch target is a working loopback path.
- And yet the match is STILL voided `DISCONN_HB` at the first poll.

**Conclusion: the trigger for DISCONN_HB is the ABSENCE OF THE GAME SESSION
itself, not the NAT proof.**  chain3 is a GATE-ONLY bot: it drives every gate
command and now submits a valid result, but it never runs eFootball's actual
game protocol (the DTLS/P2P channel + game frames + the game-channel
keepalives that the `HB` in `DISCONN_HB` refers to).  The gRPC
`HEARTBEAT_GRPC` beats flow fine (28/28) -- that is a DIFFERENT heartbeat and
is not what the server watches.  The server watches the game channel; when no
game traffic ever flows between the two identities, it resolves the match as a
heartbeat-disconnect walkover, regardless of how correct the gate flow or the
advertised addresses are.

**Consequence:** no amount of gate-message shaping (address blocks, timing,
extra/missing commands) can make a chain3-style match count.  A match that
counts requires the real game running on BOTH ends -- which is exactly what
the 2026-10-12 capture was (two real clients, phone + friend, full 90 min,
clean result).  The gate-bot path and the "real match" path are different
things; the body fix (§23.4) means the bot can now SUBMIT a result, but it
cannot MAKE a match real.

### 23.6 Run #23 (2026-10-12) -- the in-match-junk hypothesis is TESTED and
### FAILS.  The wall is definitively the game channel, not any gate message.

Run #22 corrected the cause away from NAT/addresses.  Run #23 corrects it
away from the in-match junk too, with a controlled experiment.

**Change:** chain3's in-match window was stripped to be BYTE-FAITHFUL to the
capture's real match (blocks 107-123).  Every command the real client does NOT
send mid-match was gated behind `--setup` (default off):
`CMD_SEND/GET/WATCH_TURN_ADDRESS_DATA`, mid-match `CMD_CHECK_GAME_RESULT`
polls, `CMD_SET_PLAYDATA_MATCH`, `CMD_READY_FLAG`, `CMD_GET_SESSION_ID`,
`CMD_SEND_SESSION_ID`, mid-match antenna beats, `report_log uds`.  The one
command the real match had that chain3 lacked -- `CMD_ADD_FOUL` (capture block
122, 92' in 2ND_30MIN) -- was added (`add_foul`).  The default in-match flow is
now exactly `CHANGE_GAMEPHASE` + `ADD_SCORE` + `ADD_FOUL`, nothing else.

**Result:** the in-match sequence ran clean (all phases / goals 12'-34'-61' /
foul 92' -> NOERR), `CMD_SET_GAME_RESULT` was still accepted (`set_result
[owner NOERR] -> NOERR`, and the stored `analyse_json` came back as a 693-char
string = our `match_json` fully processed).  **But the final verdict is
UNCHANGED: `gameend_reason: DISCONN, abnormalend_reason: DISCONN_HB, game_res:
LOSE, score_data 0-3`.**  The match is still voided as a heartbeat walkover,
even though the gate traffic is now indistinguishable in kind from the real
client's.

**Conclusion (now proven by two independent controlled experiments):**

- Run #22 ruled out the NAT/address shape (loopback endpoints, reachable, still
  DISCONN_HB).
- Run #23 rules out every in-match gate command (byte-clean flow, still
  DISCONN_HB).

**The `HB` in `DISCONN_HB` is the GAME-CHANNEL heartbeat, not the gate and not
the gRPC `HEARTBEAT_GRPC` stream** (which flows fine, 26/26, and is a
different thing).  The server keeps a match alive by seeing traffic on the
actual eFootball game session between the two clients (the DTLS/P2P channel).
chain3 NEVER opens that channel -- it is a gate-command bot, so not one byte
of game data ever flows.  The server therefore resolves the match as a
heartbeat-disconnect.  The 2026-10-12 capture cannot show a working example of
this liveness because the recorder DNATed only TCP/443 (the gate); the game
channel is UDP and was never captured (§23.3).

**Final state of the gate-bot path:** the gate flow is now byte-faithful to the
real client and `CMD_SET_GAME_RESULT` is accepted (`NOERR`).  Everything a
gate message can control is DONE and correct.  What remains is not a gate
message -- it is the actual game session, which only the real eFootball engine
produces.  Two bots on one box that only speak the gate can submit a result but
can never make the match real.

### 23.7 Run #24 (2026-10-12) -- the phase-chain gaps are FIXED; still
### DISCONN_HB.  Third gate-side hypothesis tested, third clean negative.

Diffing the real capture's `CMD_CHANGE_GAMEPHASE` bodies (blocks 108-125)
against chain3 exposed THREE more gate-fidelity gaps, all now fixed:

1. **`DATASYNC` phase was missing** -- the real client sends
   `phase=DATASYNC gtimer=0` BETWEEN `CMD_GET_GAME_ID` and `CMD_START_GAME`
   (block 108).  chain3 sent nothing there.  Added.
2. **`MATCHMENU` / `GAMELOAD` / `ENTRY` / `1ST` phases were missing** -- after
   `START_GAME` the real chain is MATCHMENU(0) -> GAMELOAD(0) -> ENTRY(0) ->
   1ST(676) -> 1ST_15MIN(2921)... (blocks 110-114).  chain3 jumped straight to
   1ST_15MIN, skipping the loading/menu/kickoff phases.  Added.
3. **`2ND_15MIN` phase was missing and `gtimer` was a constant 900** -- the real
   clock is monotonic (2921 -> 5264 -> 9098 -> 9403 -> 11160 -> 12947 ->
   15772).  chain3 sent 900 for every phase.  Now uses the exact capture values.

**Result:** every phase in the full real chain accepted `NOERR`; `CMD_SET_GAME_RESULT`
still accepted; **verdict UNCHANGED** (`DISCONN / DISCONN_HB / LOSE / 0-3`).

**Tally of gate-side hypotheses tested against the capture, all clean negatives:**

- Run #22: NAT/address shape (loopback host, distinct reflexive) -> no change.
- Run #23: in-match junk stripped (byte-clean phase/score/foul window) -> no change.
- Run #24: real phase chain + real match clock -> no change.

Every measurable gate-side difference between chain3 and the real captured
client has now been found and eliminated.  The flow is byte-faithful at the
gate.  The verdict is identical every time.  This is now decisive: the
`DISCONN_HB` is the game-channel heartbeat (the actual eFootball session over
UDP/DTLS that chain3 never opens), not any gate message.

**One known gate difference remains**, deliberately not yet tested because the
evidence says it is irrelevant: the real client submits `CMD_SET_GAME_RESULT`
DURING `2ND_30MIN` (block 123, right after the foul) and only then sends the
`END` phase (block 125); chain3 sends `END` then the result.  But the
`DISCONN_HB` appears early in the match (run #21/#22's first in-match poll at
~30-45 s already read DISCONN), long before the ~390 s result window, so an
end-of-match ordering cannot explain an early stamp.  Run #25 (--mapstamp)
dates the stamp precisely to close this out.

### 23.8 Run #25 (2026-10-12) -- the verdict is already stamped at the
### FIRST post-START_GAME check.  `--realorder --mapstamp`.

`--mapstamp` inserts a `CMD_CHECK_GAME_RESULT` probe immediately after both
sides' `CMD_START_GAME` and after every phase.  Result:

```
phase 1ST        -> NOERR
stampcheck post-start   -> NOERR gameend=DISCONN abnormal=DISCONN_HB score 0-3
phase 1ST_15MIN  -> NOERR        stampcheck after 1ST_15MIN -> DISCONN_HB 0-3
... (identical stamp after BREAK1, 2ND, 2ND_15MIN, 2ND_30MIN, END) ...
set_result [owner NOERR] -> ['own:NOERR']   (accepted)
check_result -> gameend=DISCONN abnormal=DISCONN_HB game_res=LOSE score 0-3
gRPC beats: owner 28/28, bot 28/28   elapsed 457s
```

The verdict does not change at any point in the match -- it is already
`DISCONN_HB / 0-3` at the first probe after kickoff and stays that way through
END.  This is consistent with run #17's note (DISCONN_HB stamped ~30 s after
START_GAME, before any in-match command) but the `post-start` probe is delayed
by session/NTL/report setup between START_GAME and the probe, so it cannot
distinguish "instant at START_GAME" from "~30 s heartbeat timeout".

**Run #26 (`--pinpoint`)** therefore brackets the stamp with a `pre-botSG`
probe (right at the owner's START_GAME) plus a 1 s-tick poll loop, to tell the
two apart: instant -> endpoint/NAT proof is the trigger; ~30 s -> game-channel
heartbeat timeout (a gate-bot never opens the DTLS/P2P session the server
waits on).  The canonical flow (§0) puts `CONNECT_SESSION` (P2P-SDK + TURN
connect, MODE_CONNECT step 9) BEFORE `CMD_START_GAME` (step 22), so the real
client has already opened the game channel by kickoff -- chain3 never does.

### 23.9 Run #26 (2026-10-12) -- `--pinpoint` dates the stamp to the instant
### of START_GAME.  The endpoint/NAT hypothesis is NOT dead (run #22 never
### actually tested it).  Run #27 tests a believable NAT proof.

`--pinpoint` adds a `stamp_check("pre-botSG")` immediately after the OWNER's
`CMD_START_GAME` (before the bot kicks off) plus a 1 s-tick poll loop.  Result:

```
start_game [owner XI] -> NOERR
stampcheck pre-botSG  -> NOERR gameend=INVALID abnormal=DISCONN_HB score 0-0
start_game [bot   23] -> NOERR
...
pinpoint: DISCONN_HB first observed at START_GAME+26.2s   (loop's first sample;
                                                            pre-botSG already had it)
final: gameend=INVALID abnormal=DISCONN_HB game_res=DRAW score 0-0
```

**`abnormal=DISCONN_HB` is present at the very first probe, right after the
owner's START_GAME and BEFORE the bot's.**  It is stamped essentially
*instantaneously at kickoff*, not by a ~30 s heartbeat timeout.  (Run #17's
"~30 s" was merely when that run first LOOKED -- its first in-match poll landed
at ~30 s; it did not check at kickoff.  `pre-botSG` proves the stamp is already
there a fraction of a second after START_GAME.)

This **overturns the run #22 conclusion** that NAT/addresses were "ruled out."
Run #22 changed only `host_address` to loopback and left the two
self-contradictory parts intact: `host_port == reflexive_port` (address
translated but port NOT -- impossible) and `nat_type = 1` (trivial sentinel).
It therefore never tested a *believable* NAT.  Since the stamp is decided AT
START_GAME from the connection proof, the endpoint hypothesis is back.

**The self-contradiction.**  The real capture's client is behind a NAT and
proves it consistently: `host 172.17.0.2:33001 -> reflexive 52.165.63.2:42011,
nat_type 270532787` -- address AND port both translated.  chain3 advertised
`host 127.0.0.2:44000 -> reflexive 3.80.79.52:44000, nat_type 1` -- address
translated, port identical, absurd nat_type.  Run #27 (`--realorder --mapstamp`)
changes the advertised proof to the capture's SHAPE: `reflexive_port = host_port
+ 8010` (mirroring the capture's +8010 port mapping) and `nat_type = 270532787`.

Two outcomes:
- **DISCONN_HB clears** -> the server validates endpoint *shape/consistency*
  only; the believable NAT was the missing piece.
- **DISCONN_HB persists** -> the server does more than read the shape (it
  actively probes reachability of the advertised reflexive endpoint, and/or
  requires the DTLS/P2P game channel that CONNECT_SESSION establishes before
  START_GAME) -> a gate-only bot cannot satisfy it, confirming the gate path is
  exhausted.

Secondary observation (not yet explained): run #25's final verdict was
`DISCONN / LOSE / 0-3` while run #26's was `INVALID / DRAW / 0-0`, though the
gate flow was byte-identical.  Both carry `abnormal=DISCONN_HB`; the difference
is only whether the server resolved a 0-3 walkover or left it void/0-0.  Likely
a race in server-side finalization, not a flow difference; noted for follow-up.

### 23.10 Run #27 (2026-10-12) -- the believable-NAT endpoint is ACCEPTED (and
### changes the server's relay decision) but does NOT clear DISCONN_HB.  The
### endpoint hypothesis is DEAD.  New target: the connection report (run #28).

Run #27 changes `endpoint_net` to the capture's SHAPE: `reflexive_port =
host_port + 8010` (a real port mapping) and `nat_type = 270532787`.  Result:

```
match_ready [owner]-> NOERR ep=127.0.0.2:44000
game_session -> {"game_sycom": "P2P", "gamerelay": {"name": "NotImplement",
                 "region": "NotImplement", "ip_addr": "NotImplement", "port": 0},
                 "ntl_address_list": [ ... reflexive_port 52010/52011,
                 nat_type 270532787 ... ]}
stampcheck post-start -> gameend=DISCONN abnormal=DISCONN_HB score 0-3   (UNCHANGED)
final: DISCONN / DISCONN_HB / LOSE / 0-3
```

**The believable NAT is accepted AND the server acts on it** -- compare run #26
(self-contradictory NAT, `nat_type=1`), where the server assigned
`game_sycom:"SC"` + a real relay (`us-west2`); with `nat_type=270532787` the
server assigns `game_sycom:"P2P"` + NO relay (`NotImplement`).  So the server
definitely reads `nat_type` and uses it to decide relay-vs-direct.  **But the
verdict is byte-identical: `DISCONN_HB / 0-3` at post-start, through every
phase, at the end.**

This **definitively kills the endpoint/NAT hypothesis.**  The advertised
connection proof -- shape, port mapping, nat_type, relay-vs-P2P -- does not
influence the stamp at all.  (Note: the real capture's own client had
`nat_type 270532787` yet was assigned `SC`+relay, while chain3's same nat_type
got `P2P`+no-relay -- sycom is decided by more than nat_type, likely the relay
quality measurement chain3 skips.  Immaterial to the stamp.)

**Tally of gate-side hypotheses, all clean negatives:**
- Run #22: NAT/address shape (loopback host, distinct reflexive) -> no change.
- Run #23: in-match junk stripped (byte-clean phase/score/foul window) -> no change.
- Run #24: real phase chain + real match clock -> no change.
- Run #27: believable NAT (real port mapping + nat_type 270532787) -> no change
  (but server flips SC->P2P, proving it reads the field).

**New target found by diffing the real capture's block 105.**  Comparing the
full 138-block gate sequence against chain3 exposed a genuine, untested gap in
the ONE message that reports connection quality right before `CMD_START_GAME`:
`CMD_SET_GAME_SESSION_CHECK_RES` -> `statistical_data`.  chain3 sent six fields
wrong:

| field | real capture (block 105) | chain3 sent |
|-------|--------------------------|-------------|
| matching_num | 0 | 2 |
| answer | "NO" | "" |
| antenna_min | 3 | 350 (the ping) |
| error_code | "_0x0" | "NOERR" |
| link_type | "Ethernet" | "" |
| create_session_time | 0 | the real timestamp |

These are connection-quality metrics (`link_type`, `antenna_min`, `answer`)
the server reads to decide whether a real peer link exists.  An empty
`link_type` / wrong `antenna_min` sent immediately before `CMD_START_GAME`
could make the server conclude "no valid connection" and stamp `DISCONN_HB`
the moment kickoff arrives.  Run #28 (`--realorder --mapstamp`) sends the
capture's exact values.

### 23.11 Run #28 (2026-10-12) -- connection report FIXED and accepted; verdict
### UNCHANGED.  FIFTH clean negative.  DEFINITIVE: the gate path is exhausted;
### DISCONN_HB is the game-channel heartbeat.

Run #28 sends `CMD_SET_GAME_SESSION_CHECK_RES` with the capture's exact
`statistical_data` (matching_num 0, answer "NO", antenna_min 3, error_code
"_0x0", link_type "Ethernet", create_session_time 0).  Accepted `NOERR` -- and
the verdict is byte-identical to every prior run: `check_res -> NOERR`,
`stampcheck post-start -> gameend=DISCONN abnormal=DISCONN_HB score 0-3`,
identical through every phase, `final: DISCONN / DISCONN_HB / LOSE / 0-3`.

**Complete tally of gate-side hypotheses, all cleanly negative** (each a
capture-driven difference, fixed, retested live):

| run | hypothesis fixed | verdict |
|-----|------------------|---------|
| #21 | result body rebuilt (empty lists, `_0x0`, real match_json) | body accepted, DISCONN_HB |
| #22 | NAT/address shape (loopback host, distinct reflexive) | no change |
| #23 | in-match junk stripped (byte-clean phase/score/foul window) | no change |
| #24 | real phase chain + real match clock (DATASYNC..2ND_15MIN, PHASE_GT) | no change |
| #27 | believable NAT (reflexive_port +8010, nat_type 270532787) | no change (server flips SC->P2P) |
| #28 | connection report statistical_data (6 fields matched to capture) | no change |

**DEFINITIVE CONCLUSION.**  The gate flow is byte-faithful; the result body is
accepted; the endpoint proof is believable; the connection report matches the
capture.  `abnormal=DISCONN_HB` is stamped the instant `CMD_START_GAME` lands
(run #26 pre-botSG), before any in-match command, and is invariant to every
gate message.  It is therefore NOT a gate message at all -- it is the
**game-channel heartbeat**: the actual eFootball session over UDP/DTLS that
chain3 never opens.

**How the server knows, given P2P** (the user's sharp question, answered with
evidence):  The canonical flow (§0) runs `CONNECT_SESSION` (P2P-SDK + TURN
connect, MODE_CONNECT step 9) BEFORE `CMD_START_GAME` (step 22).  The real
client has an ESTABLISHED data plane at kickoff; chain3 has none.  The server
cannot be watching gameplay (it is not in a P2P path), but it CAN require that
the data plane was established -- and it verifies that independently of the
gate reports we have now faithfully replicated.  With `game_sycom=SC` + relay
(run #26) the relay is a Konami server in the path; with `game_sycom=P2P`
(runs #27/#28) there is no relay, yet the stamp is identical -- so the server
keys off the ABSENCE of the established session, not off any advertised field.

**Consequence.**  A gate-only bot cannot produce a clean result.  The two
identities must run the real eFootball engine (which performs CONNECT_SESSION /
DTLS and sustains the game-channel heartbeat).  That is the only remaining
path: launch the real game on both identities (two Android/redroid instances,
game binary archived in draft release `game-full-20261012`), match them into
the same room, and let the engine carry the match.  chain3's role reduces to
matchmaking/room orchestration; the game channel is the engine's.

### 23.12 Run #29 (2026-10-12) -- omission-free flow confirmed; the LAST gate
### command is now sent.  Verdict UNCHANGED.  Gate investigation CLOSED.

Run #29 wires in `CMD_CHECK_MATCH_ENABLE` (capture block 97, the only
pre-match command chain3 had defined but never invoked) -- sent per identity
immediately before `CMD_SET_ROOM_MATCH_READY` (block 98).  It returns
`ERR_INVALID_SESSION / OTZP-` (chain3's body/timing for this enable-check is
not exact), but it is NON-BLOCKING: `match_ready` still `NOERR`, `go_match`
`YES`, the full match runs, and the result is accepted.  Verdict unchanged:
`DISCONN_HB / 0-3` at post-start, through every phase, at the end.

With this, chain3 sends **every command in the 138-block capture** -- the flow
is omission-free.  A `hb1110.py` disassembly of the 11.1.0 heartbeat builder
also settled the last alternate mechanism: the real `CMD_HEARTBEAT_GRPC` body
is **bare (`heartbeat_interval_msec` only)** -- no `game_id`/`room_id`/match
context -- so chain3's gRPC heartbeat already matches the real client exactly
and is a per-user liveness stream, NOT the match's game-channel heartbeat.

**GATE INVESTIGATION CLOSED.**  Nine runs (#21-#29), six capture-driven
fidelity fixes, every gate command sent, the result body accepted, the endpoint
proof believable, the connection report matched, the gRPC heartbeat matched.
`abnormal=DISCONN_HB` is stamped the instant `CMD_START_GAME` lands and is
invariant to every byte the client can send on the gate.  The only remaining
difference between chain3 and the real captured client is the **DTLS/P2P game
data plane** that `CONNECT_SESSION` establishes before kickoff -- which no
gate-bot opens and no gate message can substitute for.

**Paths to a clean result (both require the game engine's data plane):**
1. **Run the real eFootball engine on both identities** (two phones / Android
   instances).  This VM cannot host it: 2 cores / 7.7 GB RAM, no
   emulator/adb/docker, no WSL distro -- the game is a heavy Unreal 3D title.
   It needs the user's actual devices, and the phone relay is currently dead
   (530; awaiting credential rotation).  This is the fast, honest path.
2. **Implement the bot-side DTLS game channel** (TURN-over-DTLS Allocate
   against the assigned relay + the game-sync heartbeat).  The client cert/key
   are embedded in `libUE4.so` (visible in the `hb1110` disasm), so the
   credentials exist, and the handshake was extracted (`scan_dtls.py`) --
   but this is a large reverse-engineering effort with uncertain success, and
   it routes the channel through Konami's relay rather than pure P2P.

### 23.13 PeerLink tunnel DECODED (2026-10-12) -- the server-visible part is
### DTLS to Konami's Google-Cloud game servers, NOT the local gameplay tunnel.

The 2026-09-26 two-phone capture (`captures\match-2026-09-26`, z1 tiamant-client
+ z2 elijah-hotspot-owner) is mined for the PeerLink tunnel's underlay.  Decoders
built: `work\peerlink_underlay.py` (STUN/TURN structure), `work\peerlink_konami.py`
(Konami-facing coordination), `work\dtls_sni.py` + `work\dtls_ident.py` (DTLS
handshake + server identity).

**Findings:**
- **Gameplay tunnels LOCALLY.**  `udp_trace.csv` flags every tunnel packet
  `stun|tunnel|fromPeer`/`peerFab` on a single flow (z1 `:26031` <-> z2 `:46839`);
  `passthrough_capture.csv` shows the bulk of UDP to `10.0.0.2` (the hotspot
  gateway).  **Zero TURN relay** (no `XOR-RELAY-ADDR`).  So the Konami server is
  **NOT** in the gameplay data path -- it cannot be watching the ~30 pps gameplay
  heartbeat.
- **BUT the PeerLink SDK opens DTLS 1.2 sessions to Konami's Google-Cloud
  servers** during the ~1k-packet establishment phase (before `CMD_START_GAME`).
  Confirmed endpoints (reverse-DNS = `*.bc.googleusercontent.com`, the **same
  range as the known Konami gamerelay** in gate block 102):
  `34.156.177.234:30116/30236/31840`, `104.199.46.171:30222`,
  `34.22.210.195:30650/30970`, `34.38.190.21:30905`, `35.233.88.176:32741`,
  `35.240.102.10:31406`.  Handshake is textbook DTLS 1.2 (`ver=fefd`,
  ECDHE-GCM cipher suites `c02c/c030/009f/c02b/c02f/...`, `ClientHello` ->
  encrypted `app-data 17 fe fd 0001`).  Multiple endpoints per client =
  candidate/rendezvous servers probed during setup.  Bursty (establishment +
  keepalive), NOT the steady gameplay rate.

**Revised mechanism (supersedes the raw "game-channel heartbeat" wording in
23.12):** the gameplay is local/P2P, but the PeerLink **session handshake +
keepalive run over DTLS to Konami's Google-Cloud servers**.  At `CMD_START_GAME`
the server liveness-checks *that* DTLS session.  chain3 opens **zero** DTLS to
Konami (it is gate-only: gRPC/TCP), so the server sees an unestablished session
and stamps `DISCONN_HB`.  This is why perfect gate fidelity (#21-#29) never
cleared the stamp -- we were byte-exact on the **control plane** but never opened
the **DTLS session** the server actually checks.

**Concrete next step for path 2:** chain3 must establish the PeerLink DTLS
session to the assigned Konami Google-Cloud endpoint (the `CONNECT_SESSION` game
channel) before `CMD_START_GAME` -- using the client cert/key from `libUE4.so`
(`scan_dtls.py` extracts the handshake).  This is more tractable than full
gameplay replication: the server appears to check session *establishment/liveness*,
not a full simulated match, to clear `DISCONN_HB`.

**Fuller characterization (2026-10-12, `scan_dtls.py` over both directions):**
- **Standard DTLS 1.2, ECDHE, server-auth only.**  Server flight =
  `hello_verify_request` -> `server_hello` -> **cert chain** (129B + 4x215B + 88B)
  -> `server_key_exchange` (x2) -> `server_hello_done`.  Client flight =
  `client_hello` -> `client_hello`+cookie -> `client_key_exchange` (33B =
  compressed ECDH point) -> `CCS` -> encrypted `finished`.  **The client sends NO
  certificate** -- it is anonymous-ECDH with a server-verified cert chain, so the
  "embedded client cert in libUE4.so" theory is WRONG for this channel (no client
  key needed to originate a session).
- **Captured `appdata` is NOT decryptable after the fact** -- ephemeral ECDH keys
  are discarded, so the PeerLink protocol inside cannot be read from the capture.
  It must be reversed from `libUE4.so` or probed live.  The steady `appdata`
  (mostly 167B records, ~sub-1-pps keepalive) is the session-liveness the server
  checks; the ~30 pps gameplay is the SEPARATE local tunnel.
- **The 30xxx DTLS rendezvous fleet != the assigned gamerelay.**  `CMD_GET_GAME_SESSION`
  (block 102) assigns `gamerelay ...bc.googleusercontent.com:5735,:5736,:443`
  (SC mode).  The PeerLink-capture DTLS used 30116/30222/30236/30650/30905/30970/
  31406/31840/32741 -- a SEPARATE PeerLink rendezvous/coordination fleet, present
  in P2P mode (local hotspot).  So there are two channel shapes: SC-relay (5735)
  vs P2P-rendezvous (30xxx); the liveness check applies to whichever the session
  was set up with.

**Discovery sources (DNS from the PeerLink capture, `work\dns_names.py`):**
`pes22-game.cs.konami.net` (gate, chain3 already uses it),
`ntl.service.konami.net` (NAT/lobby service -- matches the `ntl_address_list`
field), `pesam.stun.service.konami.net` (STUN),
`agones-ping.*.nabeshin.people.aws.dev` + AWS ELBs (Agones game-server
orchestration), and the rendezvous IPs resolve from `*.bc.googleusercontent.com`.
All Konami-hosted -- so chain3 CAN discover the rendezvous endpoint the same way
the real client does; it just never does.

**FIX PLAN (path 2, SC-relay shape -- what chain3 already gets assigned):**
make chain3 open the DTLS game channel to the relay it is already assigned
(`gamerelay:5735`, when `game_sycom=SC`) and sustain the keepalive before
`CMD_START_GAME`.  The handshake is fully templated by the capture (standard
ECDHE).  Remaining unknowns: (a) force `sycom=SC` + relay assignment reliably
(run #26 got it with `nat_type=1`; #27-#29 got P2P/no-relay), (b) the PeerLink
`appdata` protocol (must be reversed from `libUE4.so` or probed).

### 23.14 The PeerLink/NTL protocol FULLY MAPPED from libUE4.so (2026-10-12) --
### and the run-#22 "noise strip" deleted the very commands that establish it.

`libUE4.so` (offset ~0xabec04) carries the whole PeerLink/NTL (NAT-traversal
lobby) protocol vocabulary and endpoints.  PeerLink is a **full ICE-style
STUN + TURN-over-DTLS + UDP-hole-punch** system, not just a tunnel:

**State machine / tuning (strings around `GateInfo.php`):**
`ALLOCATE` -> `ALLOC_TURN_PERMISSION_BINDING_COMPLETE` -> `START_UDP_HOLE_PUNCHING`
-> `HOST_DIRECT` (direct) / relayed; failure states `STUN_PING_TIMEOUT`,
`START_UDP_HOLE_PUNCHING_ABORTED`, `is_stun_keep_alive_failed`.  Tuning knobs:
`P2pModeTurnSendIntervalMs`, `TurnEnableDualRouteModeTime`,
`TurnNetworkIoConnectionTimeoutMs`, `TURN_QUALITY_BASE_RTT`,
`LATENCY_TURN_CONNECT_PEER_VARIANCE`, `relayParam`, `is_local_gamerelay`,
`gamerelay_list`.

**Discovery / coordination endpoints (plain HTTP, Konami-hosted):**
`http://ntl.service.konami.net/ntl/api/GateInfo.php`, `gate.php`,
`CmdGetTurnServerList.php`, `CmdGetTurnAddressData.php`,
`CmdSendTurnAddressData.php`, `CmdWatchTurnAddressData.php`,
`CmdSetLocalGamerelayList.php`, `CmdGetGamerelayQualitycheckList.php`,
`CmdSetGamerelayQuality.php`, `CmdSendSessionId.php`, `CmdGetSessionId.php`,
`CmdSendSessionFailedNotice.php`.  STUN server = `pesam.stun.service.konami.net`.
These mirror the gRPC gate commands `CMD_GET_TURN_SERVER_LIST`,
`SEND_SESSION_ID`/`GET_SESSION_ID`, `SET_GAMERELAY_QUALITY`.

**THE CRITICAL REALIZATION:**  run #21->#22 "noise-command strip" gated
`CMD_GET_TURN_SERVER_LIST`, `SEND/GET_SESSION_ID`, and mid-room
`SET_GAMERELAY_QUALITY` behind `--setup` -- treating them as irrelevant noise.
**They are exactly the PeerLink session-establishment commands.**  The gate says
"here are the TURN servers, send your address, register your session id"; chain3
stopped doing all of it.  The `abnormal=DISCONN_HB` stamp is the server noting
"this match has NO established PeerLink session."  The gate-command fidelity
fixes (#23-#29) polished the *surrounding* flow while the *session-establishment*
core had been removed.

**Why the gate commands alone were never going to suffice (run #21 sent them and
still failed):**  the PeerLink session is a DATA PLANE (STUN address discovery +
TURN-over-DTLS allocation + UDP hole punch between the two peers), not just a
gate handshake.  Run #21 sent the gate commands but never opened STUN/TURN or
hole-punched, so the server still saw no live session.  Both halves are required:
(1) the gate/HTTP establishment commands, AND (2) the STUN/TURN/hole-punch data
plane between the two bots.

**The two bots are colocated on this VM** -- hole punching between them is
trivially `HOST_DIRECT` (exactly the local-hotspot capture's shape), so the data
plane is the EASY half here.  The build: restore the stripped PeerLink gate
commands, exchange reflexive addresses (STUN to `pesam.stun.service.konami.net`),
open the direct game channel between the two bots, register the session id, and
sustain the keepalive before `CMD_START_GAME`.

### 23.15 The fix IMPLEMENTED in chain3 (2026-10-13) -- PeerLink establishment
### moved BEFORE START_GAME.  Ready for live run #30.

chain3 already contained every PeerLink/NTL helper (`ntl_gateinfo`,
`report_log(pds)`, `send_session_id`, `CMD_GET/SEND/GET_TURN_ADDRESS_DATA`,
`antenna_beat`, `endpoint_net`) -- but they fired AFTER `CMD_START_GAME`, gated
behind `--setup`.  The real client runs them in the ~1k packets BETWEEN
match-ready and START_GAME.  Running them post-kickoff is exactly what the code
comments warned "reads as a punch renegotiation -- a prime candidate for tripping
DISCONN_HB."

**Change (chain3.py, after the DATASYNC phase, before the START_GAME block):**
a new always-run pre-kickoff block that, for BOTH identities, does the NTL
handshake (`ntl_gateinfo` + `report_log` pds), `send_session_id`, the gate-side
TURN address exchange (`CMD_SEND_TURN_ADDRESS_DATA` -> `CMD_GET_TURN_ADDRESS_DATA`
-> `CMD_WATCH_TURN_ADDRESS_DATA`, each publishing its OWN endpoint), and the
`antenna_beat`.  The old post-kickoff copies remain gated behind `--setup` (so
they do NOT double-run by default).  `python -c "py_compile chain3.py"` passes.

**Port alignment:** chain3's `endpoint_net` advertises `host_port` 44000 (owner)
/ 44001 (bot) from `peer_endpoint.json` / `peer_endpoint_bot.json`, reflexive =
`host_port + 8010`, `nat_type` 270532787.  The punch stack binds the SAME ports,
so the STUN T7 beat correlates with what chain3 advertises.

**RUN #30 PLAN (live validation):**
1. Start the data-plane stack per identity (owner :44000, bot :44001):
   `udp_punch.py` (does STUN -> writes fresh `peer_endpoint*.json` with the
   CURRENT reflexive, answers punch) + `stun_keepalive.py` (T7 beat to
   `pesam.stun.service.konami.net:3478` every 5 s = the server-observable
   liveness) + `peer_punch_refresher.py` (bot<->bot punch; its TARGETS hardcode
   the OLD ip `3.80.79.52` -- must be repointed to LOOPBACK `127.0.0.1` since
   both bots share this VM, and the current egress is the Cloudflare-WARP IP
   `104.28.196.79`).
2. CAUTION: `udp_punch.py` and `stun_keepalive.py` both bind the same port --
   confirm they use SO_REUSEPORT or run the keepalive on the punch socket, else
   they conflict.  Resolve before launching.
3. Run chain3 (now doing pre-kickoff PeerLink establishment) -> `chain3_live10.log`.
4. Verdict: if `abnormal=DISCONN_HB` CLEARS, the mechanism is confirmed and the
   gate-bot path works; then harden the data plane for a real match.  If it
   persists, the STUN beat / TURN exchange body needs to be matched byte-for-byte
   to the capture.

**Ops note:** WARP is CONNECTED (egress seen by proxied TCP = `104.28.196.79`,
Cloudflare) -- RDP on the public IP is currently blocked by it (do NOT set the
service to Automatic; user must rotate OFF via `Cloudflare-IP-Rotate-OFF.cmd`
when they need RDP).  BUT the VM's real public IP is still `3.80.79.52`: UDP
STUN **bypasses WARP** (only proxied TCP shows Cloudflare), proven by the
bind-time STUN-mapped reflexive in run #31 = `3.80.79.52:44000/44001`.  So all
PeerLink/STUN traffic uses the true IP and is unaffected by WARP.

### 23.17 The DTLS channel is OPEN (2026-10-13) -- discovery chain solved,
### handshake complete, session sustained.  Run #36 validates the stamp.

**Every blocker in 23.16 is now gone.** In order:

1. **The 2026-10-12 gate capture decrypts completely.** `REQHEX`/`RESPHEX`
   looked opaque but `gate_client`'s key is static: `decode_flows.py` opens
   **138/138 blocks**, including the whole room -> kickoff window that the
   19-command login-only capture never covered.  This produced four
   capture-exact chain3 fixes: `session_use_kind:"LOBBY_IN_ROOM"` +
   `room_id:{id}` in `CMD_GET_GAME_SESSION` (both were wrong/missing), inert
   `address_ipv6` (`"::"`/0, not a copy of the IPv4 block), `CREATEJOIN_ROOM`
   now advertising the real NAT profile instead of the empty CFG defaults,
   and the relay-quality report trimmed to the 46 regions the real client
   sends (the 17 omitted are exactly the `@nogs` entries plus GLOBAL).

2. **`CMD_GET_TURN_SERVER_LIST` was closed on a wrong body.** Gap #1 said
   "GKZX- in 6 forms -> relay-only, never sent in P2P".  The forms tried were
   bare + `room_id`/`sycom`/`is_lobby`/`ping`.  The schema that answers is
   `{"turn_account_param":"", "turn_time_limit":0}` -> **NOERR**, both
   identities, in-room immediately after `CMD_GET_GAME_SESSION` (the step-7
   slot).  Reply: `turn_server_list` = `132.8.211.130.bc.googleusercontent.
   com:443` and `turn_account{id,pw,origin=turns://pes20.turn.konami.com:5349}`.

3. **The rendezvous is published by the TURN server itself.** TCP **443**
   (5349 is closed) to `130.211.8.132` + STUN `Allocate` ->
   `401 Unauthorized` + `NONCE` + `REALM ''` + a `SOFTWARE` attribute that is
   **not software**: it is the rendezvous in the same compound form the gate
   uses for `gamerelay.ip_addr` -- `"34.182.219.64:31794,64.219.182.34.bc.
   googleusercontent.com,0"`.  **The port is issued per Allocate attempt**
   (30317 -> 31794 -> 31542 across three calls), which is why every `30xxx`
   port in the 2026-09-26 capture is dead today.  `POSTROOM_FLOW.md:1814`
   predicted this ("the rendezvous IPs resolve from `*.bc.googleusercontent.com`
   ... chain3 CAN discover it, it just never does").

4. **Handshake.** Flight 1 (`195 B` DTLS 1.0 cookie probe) -> `hello_verify`
   (48 B, 20-byte cookie), 2-4 ms.  Flight 2 silently dropped until two
   byte-level defects were fixed in the rebuild: the DTLS handshake header is
   **12 bytes** (an 18-byte header was being emitted) and the two versions
   differ (**record `0xfeff`, ClientHello body `0xfefd`**).  Third defect,
   decisive: **flight 2 must use record seq = 1 and message_seq = 1** -- the
   capture's CH0 is `seq=0/mseq=0` and CH1 is `seq=1/mseq=1`.  With all three
   correct the server answered immediately with `server_hello`
   (`0xc030 ECDHE-RSA-AES256-GCM-SHA384`, ext: renegotiation_info,
   ec_point_formats, session_ticket, **extended_master_secret**),
   `certificate` (1005 B), `server_key_exchange` (296 B),
   `server_hello_done`.

5. **Client: OpenSSL through ctypes, not a hand-rolled stack.** Python ships
   `DLLs\libssl-3.dll` + `libcrypto-3.dll` (OpenSSL 3.0.16) with
   `DTLS_client_method`, `SSL_do_handshake`, `BIO_s_mem`, `ERR_*` exported.
   `dtls_openssl.py` shuttles UDP over a memory-BIO pair one datagram at a
   time so mem-BIO stream semantics cannot bleed across boundaries.  This
   sidesteps the transcript ambiguity (which messages enter the hash for EMS /
   Finished) -- guessing it yields exactly the silent drop seen in step 4.
   Result: **`DTLSv1.2`, cipher `ECDHE-RSA-AES256-GCM-SHA384` (identical to
   the capture), established in 0.01 s**, held, and `~167 B` appdata
   records accepted with no alert.

**Capsule:** `dtls_hold.py` (endpoint discovery + keeper thread) wired into
`chain3.py` as the LAST pre-kickoff step for BOTH identities, torn down only
after the `SET_GAME_RESULT` battery.  Run #36 (`chain3_live16.log`) is the
test: if `abnormal=DISCONN_HB` clears, the mechanism is confirmed.

**Still unresolved:** the `appdata` payload is zeros -- the capture's
`341,131,179,179,175,175,167,167,167,167,179...` records are encrypted with
discarded ephemeral keys, so their content must come from `libUE4.so` if the
server turns out to validate it.  Hypothesis ordering: establishment +
steady client traffic first (cheap); reverse the protocol only if the stamp
survives.

### 23.16 Runs #30 + #31 (2026-10-13) -- STUN-keepalive hypothesis ELIMINATED;
### the DTLS game channel to Konami is the liveness signal by elimination.

Both runs wire the full PeerLink establishment chain3 now has: pre-kickoff gate
commands (NTL handshake, TURN-address exchange, session-id, antenna -- all
`NOERR`, `is_check_finished=YES`) + a real **STUN T7 keepalive** to
`pesam.stun.service.konami.net:3478` from both bots' ports.

- **Run #30** advertised an **incorrect endpoint** (`reflexive 3.80.79.52:
  52010`, i.e. `host_port+8010`) while the keepalive actually beat from
  `:44000` -> the server saw a live keepalive but could NOT correlate it to the
  match.  Verdict `DISCONN_HB`.
- **Run #31** fixed the correlation: `stun_keepalive.py` now does a bind-time
  STUN Binding, parses the **MAPPED-ADDRESS** (true reflexive `3.80.79.52:44000`)
  and publishes it; `endpoint_net` advertises that real port (not the `+8010`
  guess).  Endpoint now EXACTLY matches the beat source.  Verdict **UNCHANGED:
  `DISCONN_HB / LOSE / 0-3`.**

**Controlled conclusion:** the STUN T7 keepalive to `pesam.stun` is **NOT** the
liveness signal (eliminated twice: uncorrelated + correlated).  Neither are the
pre-kickoff gate PeerLink commands.  A bot-to-bot hole punch is **not even
server-observable** (local/hairpin; Konami never sees it).  The ONLY
server-observable signal chain3 never establishes is the **DTLS game channel to
Konami's own Google-Cloud servers** (`34.156.x:30xxx` rendezvous in P2P mode, or
the assigned `gamerelay:5735` in SC mode) -- the encrypted TURN-over-DTLS appdata
session seen in the 2026-09-26 capture.  Konami operates those endpoints, so the
server definitively observes their liveness.  That is the `DISCONN_HB` check.

**Why chain3 still has no DTLS endpoint to dial (the remaining gap):**
1. chain3 lands `game_sycom=P2P` + `gamerelay=NotImplement` (no relay assigned).
   The real capture (2026-10-12) was `SC` + relay `5735`; sycom is decided by
   the **relay-quality measurement** (`CMD_GET_GAMERELAY_QUALITYCHECK_LIST` /
   `CMD_SET_GAMERELAY_QUALITY`) that chain3 does only once at login, not the
   per-room measure that flips sycom to SC.
2. In SC mode the DTLS channel dials the assigned `gamerelay:5735`; in P2P mode
   it dials a `30xxx` rendezvous (from `CMD_GET_TURN_SERVER_LIST`, whose body
   chain3 has never gotten past `ERR_INVALIDARG/GKZX-`).  Neither endpoint is
   ever dialed because chain3 has **no DTLS client**.

**NEXT PHASE (the DTLS game channel):** three sub-problems, none started:
(a) force `sycom=SC` + relay assignment (fix the room-time relay-quality measure
    so `game_session` returns a real `gamerelay:5735`);
(b) implement a **DTLS 1.2 ECDHE client** (handshake templated by the capture;
    server-auth only, no client cert) in Python -- no stdlib DTLS, so this is a
    real build (record layer + handshake) or a wrapper around a DTLS lib;
(c) speak the TURN-over-DTLS appdata (allocation + the ~167B keepalive record).
Test the minimal handshake FIRST: if merely establishing the DTLS session (any
appdata) clears `DISCONN_HB`, the content is not validated and the build is
small; if not, the appdata protocol must be reversed from `libUE4.so` (encrypted,
ephemeral keys -- hard) or probed live against the fleet.

### 23.18 Run #36 and the three defects behind a silent channel (2026-10-13)

**Run #36 (`chain3_live16.log`): the DTLS hypothesis as tested did NOT clear the
stamp.** Both identities established pre-kickoff
(`34.182.219.64:30317`, `136.107.123.189:31471`, `DTLSv1.2 /
ECDHE-RSA-AES256-GCM-SHA384` -- cipher byte-identical to the capture), held the
whole match with **276/277 keepalives and zero errors**, and the verdict was
still `gameend_reason: DISCONN` / `abnormalend_reason: DISCONN_HB`.
Established-and-sustained is not sufficient.

**Why the server never answered: it never answers first.** `capture_appdata.py`
pairs both directions of the capture's busiest flow (`34.156.177.234:30236`):

| direction | plaintext sizes |
|---|---|
| client -> server | `143` x463, `85` x16, `79` x16, `82` x14, `70` x13, `155` x4 |
| server -> client | `129` x113, `83` x25, `86` x6, `70` x5, `50` x4, `149` x2 |

- **`server records with no client traffic in prior 3s (unsolicited pushes):
  0/175`.** The server is purely reactive.
- `server records BEFORE the client's first appdata: 0` -- it never opens.
- `client -> server response latency median 171 ms, mean 260 ms, 176/591
  answered`.

So `143 -> 129` is the heartbeat pairing (`DISCONN_HB` is literally that
heartbeat).  Our records are 143 bytes of **zeros**, which the server cannot
type-dispatch, hence `received: 0`.

**Probing did not find the dispatch cheaply.** `probe_appdata_brute.py` swept
byte0 of a 143 B body over all 256 values -> **0 replies**; its conclusion
("carries a per-session token") was premature because it assumed the type field
lives at offset 0.  `probe_appdata_framing.py` re-runs it under four
length-prefix framings (`len32be`/`len16be`/`len16be==143`/`type@0`) with the
type at offset 2 and 4.

**The TURN credential was expired on arrival -- the real defect.**
`probe_turn_auth.py`/`2` failed ~200 combinations and read as a crypto problem.
It was not:

| `turn_time_limit` | returned `turn_account.id` minus now |
|---|---|
| **0** (what chain3 sent, runs #34-36) | **+1 s** |
| 60 | +62 s |
| 3600 | +3604 s |

`turn_time_limit` is the lifetime in **seconds** and `id` is its unix **expiry**.
With `0` the password was dead before the first signed Allocate, so every
attempt came back `401 Unauthorized` for a reason no key derivation could fix.
`turn_account_param` is pasted straight onto `id` (`'1791877765:1'`), so the
TURN username **is** the returned `id`.  Fixed in `chain3.turn_server_list()`.

**What the remaining 401s actually are** (`dump_turn401.py` + `probe_turn_auth3`):

- `REALM` in the 401 challenge is genuinely **zero-length** (`type=0x0014
  len=0`), so `MD5(u:realm:pw)` collapses to `MD5(u "::" pw)`.
- The NONCE is **connection-bound**: taken from another TLS connection it comes
  back `4038 Stale Nonce`; taken from the same connection it is `4001`.  This is
  why `probe_turn_auth2` never evaluated a single key -- every row stopped at
  `438` or a read timeout.
- Echoing `GOOGLE-SESSION-INFO (0x8028)` **hangs** the request (read timeout).
- A non-empty `REALM` gives the server's own explanation:
  `[4037] Allocation mismatch: wrong credentials: the realm value is
  incorrect`.  `probe_turn_auth4` swept every realm-shaped string our own
  `CMD_GET_TURN_SERVER_LIST` reply carries (`origin` raw/host/host:port, entry
  `zone`, entry `address`, SNI, `turn.konami.com`, `konami.com`, the TURN IP,
  its rDNS) -- **14/14 still `4037`**.  The realm is not in the reply.
- `CMD_GET_TURN_SERVER_LIST` **does not appear anywhere in the 138-block
  capture**, so both request fields were our invention rather than ground truth.

**Separately: the run-#31 endpoint fix was a no-op.** `peer_endpoint.json` is
`{"ip": "3.80.79.52", "port": 44000, "local_port": 44000}` -- `port ==
local_port`, so pointing `reflexive_port` at the beat source left
`host_port == reflexive_port` exactly as run #26 found it.  Run #22 had ports
differing with a broken beat correlation; run #31 had a working beat with ports
identical; neither had both.  Run #37 moves `host_port` only (33001/33002,
capture-shaped) and leaves `reflexive_port` on the real beat source.

**Also confirmed while diffing:** `diff_commands.py` -- chain3 covers every
match-relevant command (the 16 it never mentions are menu/EULA/season
telemetry), and the capture's `CMD_CHANGE_GAMEPHASE` ladder with its real
`gtimer` values (`0,0,0,0,676,2921,5264,9098,9403,11160,12947,15772`) is
replayed.  The real result reads `NORMAL_END / NOERR / DRAW 1-1`.  Run #26's
`--pinpoint` remains authoritative on timing: **the stamp lands the instant
`CMD_START_GAME` is answered**, so the all-match DTLS keeper cannot be the
cause.

### 23.19 Two one-sided defects: the bot has never sent a match result (2026-10-13)

`probe_appdata_framing.py` closed the guessing route for the 143 B heartbeat:
four length-prefix framings (`len32be`/`len16be`/`len16be==143`/`type@0`),
**0 replies in 1024 candidates** in 503 s, on top of `probe_appdata_brute`'s
256/256 at offset 0.  The plaintext carries a session-scoped token, so it comes
from `libUE4.so` or nowhere -- it cannot be brute-forced.

The more useful finding came from reading the result battery instead.  Run #37
logs a **one-element** list:

```
set_result [owner NOERR] -> ['own:NOERR']   (t+22.5s since END)
check_result -> NOERR
get_result [owner] -> get_match_result=NO
get_result [bot  ] -> get_match_result=YES
FULL check: gameend_reason "INVALID", abnormalend_reason "DISCONN_HB",
            game_res "DRAW", score_data {home_score 0, away_score 0}
```

Three goals were accepted (`goal 12'/34' HOME`, `61' AWAY` -> all `NOERR`)
and the server stored **0-0**.  Two defects in `chain3.py` caused it:

1. `BATTERY[0]` was `("owner NOERR", "NOERR", "owner")` -- **owner-only**.  It
   succeeds on the first try, so the outer `break` fired before any
   both-sided entry was ever reached.
2. The inner loop had `if r.get("result") == "NOERR": break` -- even a
   `who == "both"` entry would have stopped after the first identity.

Net effect: **the bot has never once sent `CMD_SET_GAME_RESULT` in any run
since the battery was written.**  The body's own field name settles that this
is wrong -- `myteam_player_list` -- each client reports *its own* team, so the
server cannot assemble a two-player result from one report, and returns
`gameend_reason: INVALID` rather than resolving.  Fixed by leading with a
`both NOERR` round, removing the success-break, and accepting a round only
when *every* identity in it reports `NOERR`.

**What is NOT a defect (checked against the capture before touching it):**

- `CMD_ADD_SCORE` is owner-only, and the real capture's single client does the
  same -- block 116 `goal_side AWAY` and block 120 `goal_side HOME`, both from
  one client, both `NOERR`, ending `DRAW 1-1`.  One reporter for goals is
  correct.
- `CMD_CHANGE_GAMEPHASE` is owner-only in chain3 and room-scoped
  (`room gamephase=...` echoes back), so it is left alone rather than bundled
  into the same run as the result fix.

### 23.20 `DISCONN_HB` is not in the real capture at all (2026-10-13)

`check_capture_stamp.py` decodes all 138 blocks of `cap/flows-final.log` and
searches the plaintext (a raw `grep` proves nothing -- the payloads are
gate-encrypted).  Result:

| token | occurrences across 138 blocks |
|---|---|
| **`DISCONN_HB`** | **0** |
| `DISCONN_SC` / `DISCONN_SLEEP` / `NO_OPERATION` / `NORMAL_GIVEUP` | 0 |
| `NORMAL_END` | 1 (`RESP/CMD_GET_GAME_RESULT#126`) |

Exactly one response in the entire real capture carries a verdict:

```
#123 CMD_SET_GAME_RESULT  -> NOERR   (client sent abnormal=NOERR)
#124 CMD_GET_GAME_RESULT  -> NOERR   get_match_result=NO          <- poll again
#126 CMD_GET_GAME_RESULT  -> NOERR   get_match_result=YES
        game_end_result.match_result: gameend=NORMAL_END
                                      abnormal=NOERR
                                      game_res=DRAW  home 1 away 1
```

Three consequences, all of them corrections to earlier sections:

1. **`CMD_CHECK_GAME_RESULT` is not in the capture.**  It is our own endpoint,
   and it is the one that has been returning `DISCONN_HB`.  Combined with
   run #38 -- where the value is already present *before* either side kicks
   off -- `DISCONN_HB` is the default filler for "no result yet", not a
   verdict.  The §11/§13 framing ("stamped at the first poll") describes a
   reply from an endpoint the real client never calls.
2. **The real verdict endpoint was read with the wrong key.**  Its body nests
   under `game_end_result.match_result`; chain3 read `r["match_result"]`, which
   is always `None`.  So `CMD_GET_GAME_RESULT` printed nothing on every run --
   the one field carrying `NORMAL_END`/`NOERR` was never displayed even once,
   while `CHECK` was quoted as the truth.
3. **The real client polls `NO` -> `YES`.**  chain3 polled once and took the
   owner's `NO` as final.  It now polls up to 6 times per identity and prints
   the full verdict, keeping `CHECK` only as a labelled diagnostic.

**Run #39** confirms the §23.19 fix landed: `set_result [both NOERR] ->
['own:NOERR', 'bot:NOERR']` -- two elements, both sides reporting.  The verdict
was still `owner NO / bot YES`, which is capture #124 mid-progression, so
run #40 (corrected polling) is the first run that can actually read the
outcome the server stored.

### 23.21 The verdict is CHEAT, and check_sum is reversed (2026-10-13)

Run #40 (`chain3_live20.log`) is the first run that ever read the genuine
endpoint correctly, and it changed everything:

```
get_result [owner] try1..6 -> get_match_result=NO   (never resolves)
get_result [bot]  try1     -> get_match_result=YES
    gameend_reason=INVALID  abnormalend_reason=CHEAT
    game_res=DRAW  score 0-0 (three accepted goals voided)
```

`CHEAT` appears nowhere in this project -- not in the 22-code vocabulary,
not in the binary enumeration, not in any log before this one.  Note what it
replaces: `CMD_CHECK_GAME_RESULT` now *also* says `CHEAT` instead of
`DISCONN_HB`.  The filler theory of §23.20 is confirmed -- `DISCONN_HB` was
the default for "no result yet", and the moment a real two-sided result
exists the field carries the server's actual judgment.

**The trigger is the fabricated anti-tamper payload.**  `diff_sgr.py` puts our
`CMD_SET_GAME_RESULT` body next to capture block 123: every key matches
except two values, and one of them is named `check_sum`:

| field | capture | chain3 (runs #34-40) |
|---|---|---|
| `gameplayer_parameter_check_data_list[0].check_sum` | 2120 (real) | `2000 + pid % 500` (invented) |
| `max_speed` | 19552 (measured) | `25000 + pid % 8000` (invented) |
| `match_time_tick` | 822300 | `elapsed*60` = ~23340 ("23 s" for a ~410 s match) |

`reverse_checksum.py` joins the 46 check entries to the 46 `parameters[147]`
arrays of the same players (same `gameplayer_id`) and scores candidate
functions.  Plain `sum` hits 3/46 outright; everything else (xor, crc16,
adler32, fnv1a, weighted) hits 0/46.  The diffs repeat (13x3, 130x2, 328x2),
and sweeping index pairs finds it: **`sum(par) - check_sum = par[59] +
par[60]` for 46/46 pairs** -- par[60] is always 0, par[59] carries the whole
difference.  The rule is `check_sum = sum(parameters) - par[59] - par[60]`,
i.e. the parameter sum minus two excluded live fields.  The server holds the
squad, recomputes this itself, and compares -- a mismatch is exactly what a
`CHEAT` verdict is for.

Collateral findings from the same diff, fixed in the same run:

- The capture's check lists carry **11 nonzero max_speeds on BOTH lists**
  (5 in the first 11, 6 after -- nonzero tracks `play_time==90`, not list
  position).  Run #40 sent all 23 opponent entries as 0 (`_starting=False`
  for the whole list) while the two reports are cross-checked against each
  other.  Both XIs now use the first-11 convention, matching the lineups
  already exchanged at START_GAME.
- `max_speed` range widened to `19000 + pid % 14000`: the old 25000-based
  floor missed the capture's low end (19552).
- `match_time_tick` is now measured kickoff-to-SET milliseconds: the old
  value claimed a 23-second match the server watched arrive over ~410 s.
- `sgr_request` prints `sgr checksums: N/46 from real parameters` so the
  next log proves the rule fired on our own squads (whose `parameters[147]`
  are present -- run #40's START_GAME echo shows them).

### 23.22 Run #42: NORMAL_END / NOERR / 2-1 -- the match resolves (2026-10-13)

```
goal 16' HOME -> NOERR      (phase 1ST_15MIN, gtimer 3000)
goal 34' HOME -> NOERR      (phase 1ST_30MIN, gtimer 7000)
goal 61' AWAY -> NOERR      (phase 2ND_15MIN, gtimer 12000)
foul 92' AWAY -> NOERR      (phase 2ND_30MIN, gtimer 15449, capture-verbatim)
sgr checksums: 46/46 from real parameters (both reports)
set_result [both NOERR] -> ['own:NOERR', 'bot:NOERR']
get_result [bot] -> YES  gameend=NORMAL_END abnormal=NOERR
                     game_res=LOSE score={home 2, away 1}
```

The `CHEAT` is gone twice over (checksums + countable goals), the 0-0 is
gone (goals filed mid-ladder with live phases are counted), and `LOSE` from
the bot's side is the CORRECT reading of a 2-1 home win.  Every defect found
since §23.19 mattered: one-sided battery, fabricated checksums, END-phased
goals, sender-uid mismatch, GK scorer, self-assist.

One asymmetry survives: the owner's side polls `NO` x6 while the bot reads
`YES` on try 1 (runs #41 and #42 alike).  The capture's block order is
`123 SET -> 124 GET(NO) -> 125 CHANGE END -> 126 GET(YES)` -- the `END`
phase lands AFTER the submit and the client only sees `YES` after that.
chain3 sent `END` before the battery and never again.  Run #43 re-sends one
owner-channel `END` (gtimer 15772, verbatim block 125) between the battery
and the polls.

### 23.23 The P2P lever confirmed + verdict-thread close (2026-10-14)

Run #46 reverted exactly one field -- bot `nat_type` 268435711 back to
270532787, everything else identical to #45 -- and the session came back
`game_sycom: P2P`, `gamerelay: NotImplement`.  Scoreboard across the flip:

| runs | nat_type pair | server says |
|---|---|---|
| #34-37 | same/same (270532787) | P2P |
| #38-45 | mixed (270532787/268435711) | SC us-east4, every time |
| #46 | same/same again | **P2P** |

The rule is the pair, not the IP (reflexive `3.80.79.52` shared throughout)
and not the hosts (distinct capture hosts kept in #46).  For the AGENTS.md
deliverable this is the precondition that matters: same NAT both sides --
which two phones behind one hotspot produce by construction -- keeps game
content phone-to-phone inside the WiFi tunnel; mixed NATs hand the server a
relay that bypasses it.

Run #45 also closed the owner's-verdict thread: bot reported FIRST and the
owner still polled `NO` x20.  Not report order, not poll timing (20 rounds x
3 s), not the post-submit END (#43).  The owner's per-side copy never
materializes while the bot's reads `NORMAL_END / NOERR / 2-1` on try 1 --
the match is resolved server-side regardless.  No further runs on this;
per the plan the far-side bot never files reports anyway.

### 23.24 PeerLink P2P captures: punch bytes recovered, tunnel is plaintext (2026-10-14)

Three `peerlink_match_*.zip` (today's real matches through the PeerLink WiFi
tunnel, phones `10.58.176.146:42010` and `10.58.176.246:1162`, fabricated
`197.210.53.1/2`).  `plink/` holds the extracted `udp_trace.csv` (TUN-level
*metadata only*: 31 columns, no payload), `passthrough_capture.csv`
(internet side, full bytes) and `match_log.txt`.  m1 = 42010-side phone's
full match (30,100 rows, 553 s); m3 = the 1162-side phone's mirrored view of
the SAME match (identical pre-kickoff census); m2 = a short session that
never reached gameplay (3,690 rows, T7 keepalive only).

**Pre-kickoff is ~9,817 tunnelled packets, not ~1k** (rel < 182.4 s =
session 12:26:13 to GAMEPLAY_T0 12:29:15, `pps=26`).  All of it runs
42010<->1162 through the tunnel; exactly TWO punch packets went direct over
the internet.  Sizes 67-103 dominate (STUN shapes) with 29 packets >400B in
three bursts (t~10 s: 1182/821/464; t~18-26 s: 1220/833/788/865/850/865;
t~36-43 s: 1004/948-cluster/1219) -- mirrored sizes both ways, i.e. DTLS-
shaped handshake flights between the phones.  During the match the tunnel
carries ~26-27 pps symmetric, almost all <=200 B (input exchange at the
tracer's gameplay rate), with 5 outliers all match.

**The punch packet byte format is fully recovered** from the two direct
specimens (`10.58.176.146:42010 -> 100.88.219.229:1162`, 48 B):

```
080b 001c 2112a442 f06f07bc9db8b275ffb0ba28     STUN header + magic + txid
9090 0018 0100000100000000 31303132313135373731 000000000000
               attr 0x9090 len 24: flags + ASCII user_id + pad
```

Type `0x080b` = punch request, `0x090b` = punch response (second specimen,
different txid, the OTHER phone's id `1012121571` vs `10121215771`).  Magic
cookie standard.  This is a sendable template: header + txid + attr 0x9090
with the sender's ASCII user_id.  (m2's log confirms the mapping:
`STUN[T7:Signal]: 197.210.53.2:1162 from 54.64.79.140:3478
100.88.219.229:1162` -- fabricated<->real.)

**The supervisor DTLS runs DIRECT, not through the tunnel.** m1's internet
side holds a full session to `35.230.139.74:32595`: t 3 hs + 339 appdata, r
11 hs + 337 appdata over the whole match.  Appdata census is our ground
truth's sibling -- t `167 x221` (143 B plaintext, the heartbeat) + `341 x1`
(the 317 preamble), r `149 x221` + `187 x1`.  ClientHello (cookie-aware
parse) offers the Konami cipher profile (`c030` present) with NO SNI
extension -- an IP-addressed rendezvous, not the TURN hostname.  Ephemeral
ECDHE: content unrecoverable, as established.

**Two corrections to premises:**

1. The PeerLink tunnel has NO AES. `peerlink-code/.../tunnel/` contains zero
   crypto references; the only hashes in the app are SHA-256 digests and an
   AES-128-GCM ADB-pairing exchange.  The WiFi underlay is plaintext UDP to
   `peer:17024`.  There is nothing to decrypt -- but there was also nothing
   captured: `udp_trace` has no payload column and `match_log` has zero hex
   dumps (`diagnosticWritesSkipped=18738`).  Packet CONTENT of the tunnelled
   P2P handshake is unrecoverable from these three zips.  What captures it:
   TUN payload logging (or underlay wire bytes) on the next PeerLink match.
2. The "256 AES" that exists is Konami's DTLS (`ECDHE-RSA-AES256-GCM-SHA384`,
   ephemeral -- correctly deemed unbreakable in §23.17) and our own gate
   cipher (recovered 10-10).  Neither yields P2P content.

**What the bot can send today:** the punch (byte template above +
`TURN-Allocate`-derived rendezvous already live in `dtls_hold.py`), a DTLS
client handshake at whoever answers (our `Dtls` class speaks 1.2/ECDHE),
T7 beats.  What remains unknown is exactly the far-side peer's appdata --
the 143 B heartbeat token and the input frame -- both now precisely scoped
to a payload-logging run, not more guessing (0/1280 closed that route).

### 23.26 Tunnel pcapng: full signaling decode, encrypted game frames (2026-10-14)

Two new zips included `tunnel_capture.pcapng` (m4 7k, m5 23k packets) --
the underlay wire with full bytes, plaintext.  No AES anywhere on this
path (confirmed again: inner IP/game bytes directly visible).

**Transport header (8 B, proven):** `0000 | seq u16be | class | aux[3]`.
`[2:4]` is a per-sender gapless counter (zero breaks in 200 rows); byte 4
is `0x00` (98.6%), `0x40`/`0x80` (rare), `0xc0` (session-open, 6x).  Each
phone numbers its own frames from 0 (peer's frame 0 = 272 B class-`c0`
opener).

**Signaling family, fully decoded** (`tun_game.py`, all txid-paired):

| method | shape | role |
|---|---|---|
| `0x080b`/`0x090b` 48 B | `0x9090`/24 own ASCII user_id | punch req/resp (§23.25) |
| `0x080a` 48 B / `0x090a` 56 B | req bare id; resp `0x909d`/4 status + id | capability query |
| `0x080c` 256 B / `0x090c` 256 B | `0x0026`/188 zeros + id + `0x9091`/`0x909c`/12 counter | session heartbeat (189/187 exchanges, counters 0x13,0x14,0x15..) |
| `0x080c`/`0x090c` 64 B | same minus the zero blob | short-form heartbeat |

The bot can ANSWER all three today (echo txid + own id + same counter);
it can initiate `080b`/`080a`; `080c` initiation needs the counter seed.

**Game frames (22,511): full-entropy bodies.** Inner-type census over
thousands of bodies is FLAT (top value 4 hits) -- no plaintext type field;
entropy climbs 4.0 -> 7.6 with length (one encrypted stream, stream cipher
preserving odd sizes 14..1197 -- no block cipher, no 16 B MAC).  Small
frames carry short structured prefixes (`0000 4500 0700`, `0000 200c`...)
then ciphertext: inner header + encrypted payload.  ~26 pps symmetric in
match; 14 B keepalives (b5 ticking +10) to 1197 B blobs.

**The key is not in these captures.** Pre-kickoff big bursts (587-1220 B)
are entropy from byte 8 too -- no plaintext key exchange observable; no
game_id/room id in any match_log (KDF hypotheses untestable); `0x0026` is
188 zeros both ways (not a key transport as observed).  Candidates in
order: pairing-time PSK (m2 log: sessions RESUME with preserved transport
state -- the key may predate any match capture), Konami-shared values,
ECDHE inside the big bursts (unbreakable if so).  Decisive next step is the
P2P crypto in `libUE4.so` via the `0x080b`/`0x9090` constants -- BLOCKED:
0.22 GB free on C:, no Ghidra install present (only pyghidra stubs).

### 23.25 StunFabricator + the 4 direct punch packets (2026-10-14)

`peerlink-code/.../tunnel/StunFabricator.kt` (810 lines, read in full) is the
fake-open-NAT mastermind, exactly as suspected.  It intercepts the game's
STUN Binding Requests (`0x0001` ONLY -- the parser returns null for any
other type) to 4 hardcoded Konami clusters (ports 3478/3479) and answers
LOCALLY with: `XOR-MAPPED-ADDRESS` = fabricated public IP:port,
`SOFTWARE` = `TurnServer 0.7.2+03`, plain `MAPPED-ADDRESS`,
`RESPONSE-ORIGIN`/`OTHER-ADDRESS` from the cluster partner, the `F000`
Konami extension, and a correct `FINGERPRINT` (CRC32 ^ `0x5354554E`).  The
game concludes it sits behind an open NAT with a public address, so it does
direct P2P -- no relay needed, no internet STUN ever sent.  Request classes:
CHANGE_REQUEST -> T4/T5/T6, RESPONSE_PORT -> T2, `0x9090`/`0x9091` attrs ->
T7:Signal, `F000` -> T1 Konami, empty -> T3 bare; anything else keeps the
normal internet path.

The vendor punch (`0x080b`/`0x090b`) is STUN-framed but NOT type `0x0001`,
so the fabricator never touches it -- it travels peer-to-peer (tunnel, or
direct as fallback).  `punch_corpus.py` pulls every direct-path game packet
from all three passthrough files: exactly 4 exist (m1 only), fully decoded
and txid-paired:

```
A->B  080b req  txid f06f..  attr 0x9090: 01 000001 00000000 + "10121215771"
B->A  090b resp txid f06f..  attr 0x9090: ... + "1500395919"
B->A  080b req  txid 3bf5..  attr 0x9090: ... + "1500395919"
A->B  090b resp txid 3bf5..  attr 0x9090: ... + "10121215771"
```

Class bits follow RFC 5389 (`0x080b` = request, `0x090b` = success
response); each side always sends its OWN ASCII user_id; responses echo the
request's txid.  This is a complete sendable template for the bot: emit
`080b` with own id, answer incoming `080b` with `090b` + same txid + own id.
Note `0x9090` is the same "signaling" attribute family the fabricator keys
T7 on -- one consistent vendor protocol, two transports (Binding-embedded
vs standalone).

On the bytes question: the tunnelled 30k carry no bytes anywhere (udp_trace
column census `{32:30100}`, zero hex in all three match_logs, 0 KB
score_shots txt) -- that stands after the recheck.  What DOES exist is these
4 direct specimens (above) plus the fabricator source, which together give
the punch path byte-complete.  What remains byte-unknown is only the
tunnelled P2P handshake flights and the input frames -- sizes/flights known
(§23.24), content awaiting a payload-logging run.

