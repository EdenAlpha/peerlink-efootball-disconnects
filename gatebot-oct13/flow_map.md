# Door-to-kickoff protocol map (from the full Ghidra dump)

Source: CI run 37111881935 artifact `kgs-ghidra-37111881935` (380 MB zip →
`work/ghidra_artifact/fulldump_out.txt`, 2.63 GB, 64.6M lines) — full Ghidra
analysis of the **previous app update** `libUE4.so`
(`native/lib/arm64-v8a`, SHA-verified, 160,822,968 B).

Coverage of that dump:

| section | state |
|---|---|
| SYMBOLS  | complete (4.34 M) |
| FUNCTIONS | first 500,000 fns (0x029293d0 – 0x081444a4) |
| STRINGS  | complete (404 k, with xrefs) |
| REFS     | first 12 M (to 0x081edeb0) |
| ASM      | complete (25.9 M instructions) |
| DECOMP   | **0x029293c0 – ~0x0753b414 only** (200-min deadline) |

Missing DECOMP region 0x753b414–0x8c35207 is exactly the online/room/NTL
region. Continuation launched: CI run **38109520335** (`kgs-ghidra2`, branch
`ghidra-decomp2`) decompiles everything from 0x7530000 up.

Indexer: `work/fd.py` (`index` | `info` | `decomp <addr>` | `grep <sec> <re> [n]`).

## The gate command chain, door → kickoff

Every CMD_* name below is a string in the binary with the serializer-function
xrefs shown (previous-update addresses). This is the game's own vocabulary —
the flow order is reconstructed from the chain3 live walk + room errors + task
source files; each step's C body lands with the part2 decomp.

| step | gate command | serializer fns (prev-update) |
|---|---|---|
| 1 enter online mode | `CMD_JOIN_GAME_MODE` | FUN_077acef4 / FUN_077ac578 |
| 2 relay quality | `CMD_GET_GAMERELAY_QUALITYCHECK_LIST` → `CMD_SET_GAMERELAY_QUALITY` | FUN_0772a550 / FUN_077e5204, FUN_077e482c |
| 3 create room | `CmdCreatejoinRoom` / `CMD_CREATEJOIN_ROOM` | FUN_07b24dc4 / FUN_078b1830, FUN_078b7414 |
| 3b create body fields | `reflexive_address`, `reflexive_port` | **FUN_078b1ba4, FUN_078b261c** |
| 4 recruit code | `CMD_SEND_RECRUIT_CODE` (`CmdSendRecruitCode.php`) | FUN_077c60fc, FUN_077c5c74 |
| 5 room polling | `CMD_GET_ROOM_INFO`, `CMD_GET_REQUESTED_JOIN_ROOM_INFO` | FUN_078bd59c / FUN_078bb5e8 |
| 6 join request | `CMD_SEND_JOIN_ROOM_REQUEST`, `CMD_ADD_ROOM_GUEST` | FUN_078cd70c / FUN_078b0848 |
| 6b join body fields | `reflexive_address`, `reflexive_port` | **FUN_078c5c5c, FUN_078c6268** |
| 7 room furniture | `CMD_SET_ROOM_SETTINGS`, `CMD_SET_ROOM_USER_ENTRY_SIDE`, `CMD_SET_ROOM_USER_SQUAD_ENABLE`, `CMD_SET_ROOM_USER_COMMENT`, `CMD_KICK_ROOM_USER` | FUN_078d9fe0 / FUN_078dbd70 / FUN_078dda34 / FUN_078db1b8 / FUN_078ca0b4 |
| 8 ready | `CMD_SET_ROOM_MATCH_READY` (body: `address_ipv4{host,port,reflexive_* ,nat_type}`, `gamerelay_measure_result`) | FUN_078d39a0, **FUN_078d3b50** (verified serializer), FUN_078d3eec |
| 8b unset | `CMD_UNSET_ROOM_MATCH_READY` | FUN_078deabc |
| 9 match-enable check | `CMD_CHECK_MATCH_ENABLE` | FUN_076ef318, FUN_076ef024 |
| 10 session | `CMD_GET_GAME_SESSION` (reply = `ntl` list + `game_sycom`) | FUN_07723140, FUN_07724bcc, FUN_077244c4 |
| 10b session check | `CMD_GET_GAME_SESSION_CHECK_RES` / `CMD_SET_GAME_SESSION_CHECK_RES` (the 15 s beat) | FUN_07727894 / FUN_077e3d44 |
| 11 relay list | `CMD_SET_LOCAL_GAMERELAY_LIST` | FUN_077e98d4, FUN_077e8b08 |
| 12 TURN (only if relay) | `CMD_GET_TURN_SERVER_LIST` → `CMD_SEND_TURN_ADDRESS_DATA` / `CMD_WATCH_TURN_ADDRESS_DATA` / `CMD_GET_TURN_ADDRESS_DATA` | FUN_07eaf5c8 / FUN_07eb1908 / FUN_07eae040 / FUN_07ead330 |
| 13 playdata | `CMD_SET_PLAYDATA_MATCH` | FUN_077f9f64, FUN_077f9878 |
| 14 squad screen | `CMD_SIDE_SELECT` (FUN_07dc6f60), `CMD_MATCH_SETTINGS` (FUN_07dc0560), `CMD_READY_FLAG` (FUN_07dc2da4), `CMD_ALLREADY_FLAG` (FUN_07dbe30c; wait_other @ FUN_07dbd438) | sync tasks below |
| 14b sync tasks | `TaskSyncSideSelect` FUN_07b657fc, `TaskSyncTeamSelect` FUN_07b67e60, `TaskSyncTeamData` FUN_081533f0 (`OnlineModeTaskSync*.cpp` source paths xref FUN_08153698) | also `CMD_SYNC_MATCHPLAN_DATA_LITE/FULL` FUN_07dcb798 / FUN_07dca4ec |
| 15 second click | `CMD_START_GAME` (`CmdStartGame.php`) | FUN_0780bf00, FUN_0780d618 |
| 16 in-match phases | `CMD_CHANGE_GAMEPHASE` | FUN_076c3758, FUN_076bfe84 |
| 17 result | `CMD_CHECK_GAME_RESULT` (FUN_076c7ba8), `CMD_SET_GAME_RESULT` (FUN_077e01b4, FUN_077d4270) | |
| exit | `CMD_LEAVE_ROOM`, `CMD_RETURN_ROOM`, `CMD_LEAVE_GAME_MODE` | FUN_078cb058 / FUN_078cbe14 / FUN_077ae0d0 |

Full CMD_ inventory (377 names + xrefs): `work/ghidra_artifact/cmd_inventory.txt`.

## NAT-open: what the game sends, and what proves "open"

- **Create-join room and join-room bodies carry `reflexive_address` +
  `reflexive_port`** (STUN srflx) — fns FUN_078b1ba4/FUN_078b261c (create),
  FUN_078c5c5c/FUN_078c6268 (join). The ready body adds `nat_type` +
  `gamerelay_measure_result` (FUN_078d3b50, verified earlier by killrule run).
- Room-level errors the game handles prove the server-side checks:
  `ELobbyCreatejoinRoomError::ERR_FAILED_STUNCHECK`,
  `ERR_GAMERELAY_QUALITY_NOT_MEASURE`, `ERR_FAILED_CONNECT_RELAY`,
  `ERR_FAILED_CONNECT_RELAY_TIMEOUT`, `ERR_FAILED_MULTIPLAY_PRIVILEGE`,
  `ERR_ROOM_CREATE_LIMIT` (enum-name table @ 0x092d0a00).
- NAT-type machinery: `natType` JSON key + `PEER_REFLEXIVE` + `reflexiveAddrStr`
  all inside **FUN_07e16a5c** (the NTL address emitter); `RP_NAT_TYPE` /
  `RP_REFLEXIVE_ADDRESS` builders FUN_07df86f0 / FUN_07debc10; name tables
  `NATTYPE`/`NATTYPE_PEER`/`NATTYPEV6*` FUN_07e5bc34 / FUN_07e4724c;
  `CoreNatTypeUpdate` FUN_07e14494; `TurnInitializedNatType` FUN_07e0e1f4.
- Hole-punching event machine: **FUN_07e15d60** emits all
  `START_UDP_HOLE_PUNCHING_{PROGRESS,COMPLETE,ERROR,ABORTED,TRANSPORT_FINALIZE,
  ADVICE_CANCEL_LOCAL,ADVICE_CANCEL_HAIRPIN}` + `STOP_*/KEEP_*`;
  per-peer punch: `REQUEST_PUNCHING` FUN_07ddd7e0/FUN_07e1f824,
  `START_ONE_PUNCHING`/`DONE_ONE_PUNCHING` FUN_07de0500/FUN_07e22398,
  `RETRY_PUNCHING`/`PUNCHING_FINISHED` FUN_07de09c8/FUN_07e22890/FUN_07e22c74.
- `game_sycom` (the session-reply field that arrived as `"SC"` on the relay
  path) is parsed/emitted by **FUN_07724da0, FUN_077e17d4, FUN_077e1c80**.

All of the above functions are in the part2 decompile window — exact body
field order, natType bit semantics, and the P2P-vs-relay decision surface
land with that artifact.

## The P2P data plane (post-session, pre-kickoff)

Two functions own the wire on the UDP channel (both in the part2 window):

- **FUN_07debc10 — STUN/RP message BUILDER** (write path). Attribute
  vocabulary it emits: standard STUN (`XOR_MAPPED_ADDRESS`,
  `XOR_MAPPED_ADDRESS_3489`, `XOR_PEER_ADDRESS`, `XOR_RELAYED_ADDRESS`,
  `MAPPED_ADDRESS`, `EVEN_PORT`, `REQUESTED_TRANSPORT`, `DONT_FRAGMENT`,
  `CHANNEL_NUMBER`, `FINGERPRINT`, `ATTR_EXTENSION`) **plus Konami's RP_
  extensions**: `RP_P2P_HEADER`, `RP_HOST_ADDRESS`, `RP_REFLEXIVE_ADDRESS`,
  `RP_RELAYED_ADDRESS`, `RP_NAT_TYPE`, `RP_RAND_SEED`, `RP_RELIABILITY`,
  `RP_RELIABILITY_ECHO`, `RP_SYNC_POINT`, `RP_ENTRY_IDX`, `RP_PEER_STATUS`,
  `RP_AMF_DATA`, `RP_JSON_DATA`, `UHP_FINALIZE_RET`.
- **FUN_07df86f0 — STUN/RP message PARSER** (read path, logs
  `"RecvStunMsg"`, `"Skip Attr >> [ %s ]"`, format
  `${"%s":"[ %s ][ %s ] from [ %s ][ %d bytes ]","tid":"..."}`). Parses the
  same RP_ set plus `USERNAME`, `DATA`, `LIFETIME`, `REALM`, `NONCE`,
  `MESSAGE_INTEGRITY`, `CONNECTION_ID`, `RESERVATION_TOKEN`, `ERROR_CODE`,
  `RESPONSE_ORIGIN`, `SOURCE_ADDRESS`, `OTHER_ADDRESS`, `CHANGE_ADDRESS`,
  `REFLECTED_FROM`, `TERM`.

So the punch phase is a **STUN conversation with Konami RP_ attributes**:
peers exchange host/reflexive/relayed addresses, NAT type, a random seed,
reliability/echo, sync point, entry index and peer status — then app data
(`RP_AMF_DATA` / `RP_JSON_DATA` / DATA) flows on the same channel. Higher
transport: `RP_DATA_CAST` (FUN_07dec57c). This matches PATTERN.md's STUN
introduction and the 141-external-IP match phase (zero Konami hosts).

### Exact attribute code map (decoded from both switch tables, prev-update)

Standard STUN/TURN (attribute type codes, big-endian on the wire):

| code | attr | code | attr |
|---|---|---|---|
| 0x0001 | MAPPED_ADDRESS | 0x0016 | XOR_RELAYED_ADDRESS |
| 0x0002 | RESPONSE_ADDRESS | 0x0017 | REQUESTED_ADDRESS_FAMILY |
| 0x0003 | CHANGE_ADDRESS | 0x0018 | EVEN_PORT |
| 0x0004 | SOURCE_ADDRESS | 0x0019 | REQUESTED_TRANSPORT |
| 0x0005 | CHANGED_ADDRESS | 0x001a | DONT_FRAGMENT |
| 0x0006 | USERNAME | 0x0020 | XOR_MAPPED_ADDRESS |
| 0x0007 | PASSWORD | 0x0022 | RESERVATION_TOKEN |
| 0x0008 | MESSAGE_INTEGRITY | 0x0026 | PADDING |
| 0x0009 | ERROR_CODE | 0x0027 | RESPONSE_PORT |
| 0x000a | UNKNOWN_ATTRIBUTES | 0x002a | CONNECTION_ID |
| 0x000b | REFLECTED_FROM | 0x8020 | XOR_MAPPED_ADDRESS_3489 |
| 0x000c | CHANNEL_NUMBER | 0x8022 | SOFTWARE |
| 0x000d | LIFETIME | 0x8023 | ALTERNATE_SERVER |
| 0x0012 | XOR_PEER_ADDRESS | 0x8028 | FINGERPRINT |
| 0x0013 | DATA | 0x802b | RESPONSE_ORIGIN |
| 0x0014 | REALM | 0x802c | OTHER_ADDRESS |
| 0x0015 | NONCE | | |

**Konami RP_ extensions** (own code range 0x9090–0x909d):

| code | attr | code | attr |
|---|---|---|---|
| 0x9090 | RP_P2P_HEADER | 0x9097 | RP_NAT_TYPE |
| 0x9091 | RP_RELIABILITY | 0x9098 | RP_SYNC_POINT |
| 0x9092 | RP_AMF_DATA | 0x9099 | RP_ENTRY_IDX |
| 0x9093 | RP_JSON_DATA | 0x909a | RP_PEER_STATUS |
| 0x9094 | RP_HOST_ADDRESS | 0x909b | RP_RAND_SEED |
| 0x9095 | RP_REFLEXIVE_ADDRESS | 0x909c | RP_RELIABILITY_ECHO |
| 0x9096 | RP_RELAYED_ADDRESS | 0x909d | UHP_FINALIZE_RET |

Special message codes: `TERM` = 0x9999, `ATTR_EXTENSION` = 0xf000.
Decoders: `work/stun_attrs.py` (name mapper, both tables) and
`work/rp_tables.py` (parser dispatch — cross-validated, consistent).

Bot implementation consequence: the PeerLink bot must speak this STUN+RP_
dialect on the punched UDP socket — not just raw lockstep packets — to carry
the phone from `START_UDP_HOLE_PUNCHING` to `FORMALLY_CONNECTED` and then
carry squad/settings sync + inputs.

### Wire ground truth from the real-match captures (match-2026-09-26)

Byte-level recovery from `z1-tiamant-client/passthrough_capture.csv`
(complete IP packets as hex, 13,187 rows) via `work/passthru_stun.py`:

- **16 real STUN messages** on the game's P2P port (game 26031 ↔ peer 46839),
  all 76-byte IP packets = 20 IP + 8 UDP + **48-byte STUN message**
  (20-byte header + 28-byte attributes). Nothing else on 26031/3478 in either
  passthrough capture (z2's "467" are QUIC false positives).
- **Message type/method**: method `0x20B` — request `0x080B`, response
  `0x090B` (class bit c1=0x100). Standard STUN header: `[type:2][len:2]
  [magic 0x2112A442][tid:12]`, then attributes `[code:2][len:2][value,pad4]`.
- **Single attribute in the observed exchange: `RP_P2P_HEADER` (0x9090),
  len 24**, value =
  `01 00 00 01 | 00 00 00 00 | <16-byte ASCII id, NUL-padded>` —
  e.g. `0100000100000000` + `"1500395919"` + NULs, and the other side
  `"1012115771"`. **Each side stamps its OWN id; response echoes the
  request's tid and carries the responder's id.** The ids are the senders'
  **gate `user_id`** as 10-digit decimal (bot's own gate user_id is also 10
  digits — same format). First 8 bytes are constant across both senders.
- **Retransmit semantics**: unanswered REQ repeated with the *same tid*
  after ~495 ms; the peer answered the retransmit within 3–15 ms. Both sides
  originate requests (final burst: peer REQ → local RES in 3 ms).
- **Cadence**: 4 bursts at +349 s, +712 s, +862 s, +1348 s from capture
  start (sparse re-establish/keepalive, NOT the steady stream — the steady
  stream lives inside the tunnel, see below).
- **Steady-state match transport** (`z2 .../udp_trace.csv`, 10,923 packets,
  215.9 s): **every packet is `stun|tunnel`** — the entire match rides inside
  STUN tunnel messages. Dominant UDP payload sizes **91 / 100 / 103 B**
  (2717/2566/1872×), median inter-packet gap **18.8 ms**, ~27 pkt/s per
  direction (54/s interleaved); 834 packets >130 B = events (squad sync,
  goals). Flag sets: out = `stun|peerFab|tunnel|stableKnown`,
  in = `stun|tunnel|fromPeer|inject|stableKnown`. **Zero hairpin/relay
  flags — pure P2P.**
- **Sender**: `FUN_07deafc4` (log `{"SendStunMsg":"[ %s ][ %s ] to [
  %s:%d ][ %d bytes ]",...}` @0x7debb6c); magic cookie built in ASM as
  `mov w8,#0x1221; movk w8,#0x42a4,LSL#16` → LE-store `21 12 a4 42`
  (@0x7deb0b4) — standard STUN framing confirmed.
- **Introduction**: game resolves `pesam.stun.service.konami.net`
  (35.76.243.83:3478), learns reflexive `*:26031` — one-shot, before play
  (PATTERN.md); during the match: 141 external IPs, zero Konami.
- **Game STUN message taxonomy** (PeerLink's own labels from the capture
  logs — the game's message classes): `T1:Konami` (binding/introduction,
  1×), `T3:Bare` (2×), `T4:ChgBoth` (1×), `T6:ChgPort` (1×) — T4/T6 are
  RFC3489-style NAT-type probes (CHANGE_ADDRESS/CHANGE_PORT) — and
  `T7:Signal` (403×, ~5 s keepalive to the Konami STUN server for the whole
  session). NAT classification = T1+T4+T6 sequence; T7 holds the mapping.
- **Address attribute wire shape** (parser ASM value blocks @0x7df9424
  classic / @0x7df94b0 RP_): classic `[0][family 1|2][port u16 BE]
  [addr 4|16]`; RP_HOST/REFLEXIVE/RELAYED read `[u8][u8][u16 port]
  [addr bytes]` then format via `FUN_07de3718`. Exact struct pending
  part2 decomp.
- **Parser handling classes** (prev-update `FUN_07df86f0` @0x7df9000–
  0x7df9160): `ERROR_CODE` parsed per RFC5389 — code = (value[2]&7)*10 +
  value[3] (`madd w24,w8,w10,w9`), logged w3=0x85; `UNKNOWN_ATTRIBUTES`,
  `CHANNEL_NUMBER`, `LIFETIME` only log-skipped (branch to the
  `"Skip Attr"` tail @0x7df936c); `DATA` value copied to a fresh heap
  buffer (also referenced by `RP_DATA_CAST` FUN_07dec57c).

## Room state flags observed live

`is_go_match` (FUN_075eab5c), `go_match_users` (FUN_075eb3c4) — the
room-info keys that get stuck at YES after a failed attempt (matches the
stuck-room behaviour seen with the holder).

## Body field order (reconstructed from string-xref ordering — no decomp needed)

Within a function, string xrefs are ordered by address = roughly emission/parse
order. This gives the wire shapes already:

**CmdCreatejoinRoom REQUEST (FUN_078b1830 cmd, FUN_078b1ba4 body):**
`name_tag`, `entry_restriction`, `password`, `lang`, `capacity`,
`observer_capacity`, `guest_num_by_user`, `is_coop_vs_com_single`,
`core_settings{injury, ball_type, exTime, substitution_times}`,
`match_settings`, then the **network block**:
`host_address`, `host_port`, `reflexive_address`, `reflexive_port`,
`nat_type` (×2 — v4 + v6 slots), `ps_session_id`, `xb_session_id`,
`platform_session_id_info`, `event_account_type`, `costume_id`,
`strike_arena_selected_info`.

**CmdCreatejoinRoom REPLY parser (FUN_078b261c):** reads back the room
object: settings… + **`address_ipv4{host_address, host_port,
reflexive_address, reflexive_port}`**, `address_ipv6{…}`, platform ids,
`costume_id`, `strike_arena_selected_info`.

**CmdJoinRoom REQUEST (FUN_078c5c5c body):**
`password`, `is_need_password`, **`address_ipv4{host_address, host_port,
reflexive_address, reflexive_port, nat_type}`**, `address_ipv6{host_address,
host_port, reflexive_address, reflexive_port}`, `ps_session_id`,
`xb_session_id`, `platform_session_id_info`, `is_invited`, `costume_id`,
`strike_arena_selected_info`.

**READY body (FUN_078d3b50, already verified):** `address_ipv4{host_address,
host_port, reflexive_address, reflexive_port, nat_type}` +
`address_ipv6{…}` + `gamerelay_measure_result` (parser FUN_078d3eec).

**CMD_GET_GAME_SESSION REPLY parser (FUN_07724da0):**
`gamerelay` (spec), `game_sycom` (strategy), `ntl_address_list` (peers),
`ping`, `connecting_start_time`, `connecting_retry_time`
(the 15-s wait). Serializers of the gamerelay/game_sycom fields:
FUN_077e17d4, FUN_077e1c80.

So: **the NAT-open proof is `reflexive_address`+`reflexive_port`+`nat_type`
inside the create, join AND ready bodies**; the server's answer arrives in the
session reply as `game_sycom`+`ntl_address_list` vs `gamerelay` (relay) —
which path it picks depends on the two sides' reported NAT info (bit
semantics of `nat_type` = part2 decomp target).



- create room / code entry: `INPUT_RECRUIT_CODE` FUN_0763a28c,
  `StartCreatejoinRoom` / `IsFinishCreatejoinRoom` (flow states),
  `CmdCreatejoinRoom` FUN_07b24dc4.
- squad screen: `ELobbySideSelectMenuState::{Select,Lottery,WaitForReady,
  Finished,Result,Error}`, `SetTeamData` FUN_074b05a8, `LobbySideSelect`
  FUN_0740f480.
- second click → loading → pitch: `CMD_START_GAME` → `CMD_CHANGE_GAMEPHASE`.

## Live two-bot acceptance run (2026-10-11, chain3.py --live)

Every gate request accepted (NOERR) with both PeerLink bots against the
current production server, through the entire door→kickoff→fulltime chain:

- create room (20527556) → recruit/join → seated(2) → squads → sides →
  ready → **session reply: `"game_sycom": "P2P"`** with
  `gamerelay = {NotImplement}` — **no relay assigned** because both sides
  reported `nat_type=1` with `host_address == reflexive_address` (the VM's
  public IP:44000). This is the server-side proof that the NAT-open report
  (`reflexive_address`+`reflexive_port`+`nat_type` in the create/join/ready
  bodies) is what flips the match strategy to P2P.
- `ntl_address_list` carried both peers' endpoints
  (`address_ipv4{host,44000,reflexive,44000,nat_type:1}`).
- session-check echo (15 s) → `CMD_START_GAME` (XI squads) → all six phases
  `1ST_15MIN…END` NOERR → 3 goals accepted → `CMD_CHECK_GAME_RESULT` (server
  stamped `DISCONN_HB` as expected; `CMD_SET_GAME_RESULT` still
  ERR_INVALIDARG/GKZX — unchanged known wall).
- gRPC heartbeats 24/24 both identities (15 s cadence held for 355 s).

## Cross-check against the CURRENT app update (11.1.0)

- 11.1.0 `libUE4.so` = 161,937,864 B, SHA256
  `2EA6B0B56BB590420F967DC62B4EE24C9495B92A2BB67A71C7B270E79BEBC82B`
  (`efootball-apk/native1110/`).
- In 11.1.0 the JSON key strings (`reflexive_address`, `nat_type`,
  `game_sycom`, `ntl_address_list`, …) have **no adrp+add code refs** — they
  are reached through the packed APS2 relocation tables
  (`.rela.dyn`, SHT_ANDROID_RELA, DT_ANDROID_RELA @0x2ed270, 4.1 MB), whose
  on-disk addends the local decoder cannot yet unpack (group dialect drifts).
  Command-name strings (`CmdCreatejoinRoom` etc.) ARE still direct.
- Therefore the definitive 11.1.0 verification = same Ghidra CI pipeline on
  the 11.1.0 binary itself. Draft release `libue4-1110` created (asset
  `libUE4.so`, SHA/size gated in workflow); dispatched:
  - full dump run **38119605508** (kgs-ghidra, ref main)
  - room-region decomp run **38119606522** (kgs-ghidra2, ref ghidra-decomp2,
    decomp_start 0x7530000)
- Delete the draft release `libue4-1110` after the runs finish (KONAMI
  binary must not persist).



1. Exact field order/type of createjoin/join/ready bodies (create/join builders
   FUN_078b1ba4/FUN_078c5c5c).
2. natType bitfield semantics — which bits = "open" (FUN_07e16a5c,
   FUN_07df86f0).
3. What the session reply must contain for a P2P strategy vs relay:
   `game_sycom` values and ntl list handling (FUN_07724da0, FUN_07724bcc).
4. Sync-task sequence + wire bodies (TaskSync* FUN_07b657fc/FUN_07b67e60/
   FUN_081533f0, CMD_SIDE_SELECT/CMD_SYNC_MATCHPLAN_*).
5. Punch state machine and what the client sends first on the P2P channel
   (FUN_07e15d60, FUN_07ddd7e0/FUN_07de0500).

## Decomp coverage & open dispatches (2026-10-11)

The 200-min decomp deadline is the bottleneck: ~2010 functions/200 min ≈
1.1 MB of code per run. Strategy = targeted region runs, each anchored on a
known function cluster, `decomp_deadline=230` (workflow patched on
`ghidra-decomp2`, commit c04371b6; job timeout raised 340→355).

**Delivered** — prev-update part2 run 38109856537 (artifact
`kgs-ghidra2-38109856537`, `work/ghidra_part2/fulldump2_out.txt`, 2010 blocks
0x7530228–0x7644e70):
- **FUN_0756c068** = `ntl_address_list` ENTRY parser — struct:
  `host_address` std::string @+0x00, `host_port` u32 @+0x18,
  `reflexive_address` std::string @+0x20, `reflexive_port` u32 @+0x38,
  `nat_type` u32 @+0x3c. Keys exactly as the bots send them.
- Room-info reply parser FUN_075eab5c (`room_id.id`, `room_create_time`,
  `is_go_match`, `go_match_users`, `coop_room_end_time`); error-code
  dispatch FUN_07644eb8 (giant ERR_* table); UI-flow JSON writer
  FUN_0754b8fc (`{"kind","isFinishMatch","nextFlow",...}` — UI only).

**All completed** (kgs-ghidra2, ref ghidra-decomp2, deadline 230; 6/6
runs green — artifacts ready for download):
- **38125866246** start=0x7cf4000 — RP_ attr dispatch table @0xc8fc00
  (0x9090→0x7cf4a84 P2P_HEADER, 0x9091→0x7cf4b6c RELIABILITY, 0x9097→
  0x7cf4c34 NAT_TYPE, 0x9098→0x7cf4dac SYNC_POINT, 0x9099→0x7cf4c6c
  ENTRY_IDX, 0x909a→0x7cf4de4 PEER_STATUS, 0x909b→0x7cf4ca4 RAND_SEED —
  AMF-style value codecs), STUN sender FUN_07deafc4, builder FUN_07debc10,
  parser FUN_07df86f0, punch-request FUN_07ddd7e0/FUN_07de0500.
- **38125867617** start=0x7e10000 — punch machine FUN_07e15d60, nat
  classifier FUN_07e16a5c, punch variants FUN_07e1f824/FUN_07e22398,
  latency punching FUN_07e54c40/FUN_07e5bc34, match sync timeout
  FUN_07e3f938.
- **38126067910** start=0x7700000 — session reply parser FUN_07724da0
  (`ntl_address_list`+`game_sycom`+`connecting_start_time`), room
  serializers in 0x7700000–0x7880000.
- **38126069500** start=0x7880000 — the six NAT-entry wire functions
  FUN_078b1ba4 / FUN_078b261c / FUN_078c5c5c / FUN_078c6268 /
  FUN_078d3b50 / FUN_078d3eec (create/join/ready body + reply NAT fields).
- Completed: **38119605508** (11.1.0 full dump, kgs-ghidra) and
  **38119606522** (11.1.0 room region, start 0x7530000 — truncates around
  0x7644xxx; targeted 11.1.0 runs get dispatched once the full dump's
  STRINGS/REFS reveal 11.1.0 function addresses).

Bot-side speaker `work/p2p_stun.py` implemented and loopback-tested
(4/4: req/res + id exchange, reverse direction, same-tid retransmit,
byte-exact wire form).

## 2026-10-11 (later) — CMD_SET_GAME_RESULT body decoded from the binary

Artifact `kgs-ghidra2-38126067910` → `work/ghidra_sgr/fulldump2_out.txt`
(147 MB, 0x7700000→0x0a6ae320) contains the whole SET_GAME_RESULT class:

- **FUN_077e01b4** — clean ctor (vtables 0x098d8cb8/098d8d00/098d8d30/
  098d8d50). **FUN_077d4270** — ctor with defaults:
  `abnormalend_reason` = **"NOERR"** (+0x1f1), `is_problem` = "NO",
  analyst strings `match_json`/`advice_json`/`is_invalid_advice` =
  **"NotImplement"**; caps 0x18. Non-empty string defaults ride along in
  the wire body (strings attach unconditionally — SSO csel, no
  emptiness guard).
- **FUN_077e02f4 / FUN_077e039c** — reply parsers (read `result`).
- **Serializer** 0x076d45a4..0x076d617c (`work/sgr_enc.dis`,
  `work/sgr_keys.py`): **121 setkeys in exact write order.** Root carries
  exactly three objects: `match_result` (keys 0..67), `game_check_data`
  (74..106), `analyst_set_game_result_info` (107..120).
- Structure facts from the PRE-11.1.0 disasm — later **SUPERSEDED by the
  11.1.0 re-anchor** below (that decode lacked `match_result.game_id`
  and included `oap`; both were version drift, see below).
  - empty-source **lists are omitted** (b.eq guards): pitchside_objects,
    golazo_count_list, both gameplayer parameter lists,
    advice_info_list. Empty **objects still attach**: `golazo_info: {}`
    (attach has no guard).
  - `custom_stadium` keys verified against bot `stadium()` — match (no
    `id` key; `pitchside_objects` omitted when empty).
  - bot analyst strings changed `""` → `"NotImplement"` (game's own
    placeholder literal).
  - `abnormalend_reason` battery now leads with **NOERR** (game ctor
    default for a clean finish).
- **ROOT `game_id` (2026-10-11):** every accepted match-scoped command
  (`CMD_CHANGE_GAMEPHASE`, `CMD_ADD_SCORE`, `CMD_CHECK_GAME_RESULT`,
  `CMD_GET_GAME_RESULT`) carries `game_id` at the request ROOT — the
  game's common gate send layer stamps it from session state. The bot
  never sent root `game_id` on SET; added to the chain3 battery
  (`m["game_id"] = game_id`). Alone it did NOT clear the wall.
- Also removed the pre-submit `CMD_GET_GAME_RESULT` template fetch: a
  GET/CHECK of an OPEN match returns an empty template and the match
  later resolves as the DISCONN_HB 0-3 walkover — the first contact
  after fulltime goals must be the submit itself.
- **gate404.py live result (2026-10-11):** the endpoint EXISTS —
  `CMD_TOTALLY_BOGUS_XYZ` → HTTP 404 (`_DECODE_FAIL`), while
  `CMD_SET_GAME_RESULT` with an EMPTY body → structured
  `ERR_INVALIDARG (GKZX-)` with rqid/msgid echoed. Control
  `CMD_CHECK_GAME_RESULT` (no active game) → `ERR_DATABASE (JPWM-)`.
  So the server: finds the command, finds the game (CHECK distinguishes
  not-found=ERR_DATABASE), and validates the BODY — the wall is a
  specific body arg, not the endpoint, not the envelope, not state.

## 2026-10-11 (later) — 11.1.0 re-anchor: the body drift that broke us

- All ghidra2 decodes (serializer 0x76d45a4, SGR class 0x77d4270) are
  from the PRE-11.1.0 `libUE4.so` (160,822,968 B, sha 2AC4FF17…,
  release `libue4-local`). The live server validates against the
  **11.1.0 client** (161,937,864 B, sha 2EA6B0B5… — local copy
  `peerlink-efootball-disconnects/efootball-apk/native1110/libUE4.so`,
  hash verified against the CI input).
- 11.1.0 ELF layout differs: `.text` PT_LOAD off=0x2862500
  vaddr=0x2866500 → **vaddr = file_offset + 0x4000** (the old binary
  had vaddr == file offset); Ghidra addr = vaddr + 0x100000 (rule
  unchanged; verified: string file 0x00BDD7D3 = 'abnormalend_reason',
  Ghidra 0x00CDD7D3). `work/dis1110.py` = STR-annotated capstone
  annotator (disassembles at the vaddr base; capstone prints adrp
  targets as absolute pages). String map must come from BOTH the DATA
  section (capped at 5,000,000 lines) and the STR section (has xrefs +
  short strings like 'faul'; still misses 'id' — read those from the
  binary directly).
- **11.1.0 serializer = FUN_07895324** (Ghidra; standalone body
  serializer; a second inlined builder FUN_07896fd4 spans 0x8AEC).
  Re-anchored via 'abnormalend_reason' xrefs in the 11.1.0 full dump.
  Output: `work/sgr_enc1110.dis`, **116 annotated setkeys**.
- **The ONLY structural diff vs the old binary: `game_id` is the FIRST
  key of `match_result` in 11.1.0** — attached to the match_result
  container (field +0x1e8, u64) BEFORE `abnormalend_reason`. The old
  binary lacked it; removing it (on stale evidence) was wrong.
  Restored. **`oap` IS still a player-entry key** (loop-top preload
  `x22='oap'` at vaddr 0x07795614 — the dump's string table omits
  short strings like `oap`/`id`, which made them *look* removed;
  `work/unann1110.py` verified every unannotated adrp+add target
  straight against the binary: only `oap`, `id` ×5 are real, the rest
  are loop-stride false positives). Unique key sets old vs 11.1.0 are
  identical (106 each). Both request-class ctors (FUN_07895038,
  FUN_078a0f7c) write the same `CMD_SET_GAME_RESULT` /
  `CmdSetGameResult.php` — **no command rename in 11.1.0**.
- Live tests (2026-10-11): `chain3_sgrfix_20261011_124318.log`
  (no match_result.game_id, no root game_id → ERR_INVALIDARG),
  `chain3_rootgid_*.log` (+ root game_id, match_result.game_id still
  missing → ERR_INVALIDARG), `chain3_1110body_*.log`
  (match_result.game_id restored but oap accidentally dropped →
  ERR_INVALIDARG), `chain3_full1110_*.log` — **complete 11.1.0 shape
  (match_result.game_id + oap + NotImplement + NOERR + root game_id +
  no pre-submit GET): STILL ERR_INVALIDARG on all 8 variants.** Body
  shape is therefore NOT the binding constraint — the wall is server
  STATE (the DISCONN_HB walkover stamp lands somewhere inside the
  submit window and closes the match). Next: `--precheck` run (CHECK
  right after END to date the stamp) and `--realorder` (goals during
  phases + immediate submit after END).

## 2026-10-11 — tunnel/DTLS closure

- PeerLink source (`peerlink-code/`, jni + tunnel/) has **zero
  encryption code** — the tunnel rewrites/forwards only. The
  steady-state match stream in `passthrough_capture.csv` (`16feff`
  records, epoch 0) is **eFootball's own DTLS**, end-to-end between the
  two game instances — not decryptable with anything of ours and not
  needed: the server only sees gate HTTP + heartbeats; bot↔bot never
  speaks DTLS.
- Plaintext layers (all decoded): STUN punch + RP_ headers (method 0x20B,
  attr 0x9090), gate bodies (bot cipher). Capture totals (13187 rows):
  dtls 2260, stun 16, ent 1478, ip4 12, ctl/short 5418, other 4003; no
  SET_GAME_RESULT in captures (only CMD_SET_GAMERELAY_QUALITY).
- All six CI region runs green; artifacts: 38119605508 (11.1.0 full),
  38119606522 (11.1.0 room), 38125866246 (RP_ dispatch), 38125867617
  (punch machine), 38126067910 (SGR — downloaded), 38126069500 (NAT
  wire fns).

## 2026-10-11 (latest) — the wall is server STATE, dated; the missing half is TURN

- **Run #6 `chain3_mapstamp_20261011_145730.log` (decisive):**
  `stampcheck post-start -> gameend=INVALID abnormal=DISCONN_HB score 0-0` —
  the DISCONN_HB/INVALID stamp exists **immediately after START_GAME**, before
  any phase; every later checkpoint identical (walkover becomes 0-3 DISCONN
  after END). Timer/phase/goal theories are dead; body shape (run #4, all 8
  11.1.0-exact variants) is not the constraint either.
- **Heartbeat exonerated:** 11.1.0 `FUN_07cefbf4` writes exactly one key
  (`heartbeat_interval_msec`) — matches the bot's BeatStream payload exactly
  (`hb1110.dis`).
- **Complete post-room spec extracted** → `work/POSTROOM_FLOW.md` (+ full
  decomp bodies in `work/flow_decomp.txt` 33 fns / `work/flow_decomp2.txt`
  15 fns / caller graphs `flow_callers*.txt`). Konami's own LATENCY registry
  (`FUN_07e5bc34`) gives the canonical order; the step our bot never sends:
  **CMD_GET_TURN_SERVER_LIST immediately after GET_GAME_SESSION** (bare
  envelope — 11.1.0 state machine `FUN_07f969c0` builds it with no body keys;
  out-of-state → GKZX-, logged `work/turn_probe.log`).
- TURN reply shape (parsers `FUN_07eaf14c`/`FUN_07eaf768`):
  `turn_server_list[{zone, address, port, tls_port}]`,
  `turn_account{id, pw, origin, server_certificate, server_certificate_data_size}`,
  `turn_account_param`, `turn_time_limit`. Post-start exchange:
  `CMD_GET/WATCH_TURN_ADDRESS_DATA` (bare; reply `address` = base64 blob +
  `address_data_size`) and `CMD_SEND_TURN_ADDRESS_DATA {target_user_id,
  address(b64), address_data_size}`; ntl entry = `{user_id, xuid,
  address_ipv4{host,port,reflexive_*,nat_type}, address_ipv6{…}}`
  (`FUN_077240d4`, `xuid` DAT_00c42eed).
- Embedded phase-manager config (`FUN_07e36874`):
  `game_result_timeout_sec: 45`, `CMD_CHANGE_GAMEPHASE/ADD_SCORE/ADD_FOUL
  timeouts 30 s`, `at_match_polling_interval_msec 30000`.
- chain3 now sends: bare GET_TURN_SERVER_LIST right after GET_GAME_SESSION
  (both identities) and GET/WATCH_TURN_ADDRESS_DATA right after START_GAME;
  first run `chain3_turnlist_20261011.log` (in progress at time of writing).
- **2026-10-11 later runs** (`chain3_t7run`, `chain3_ready`, `chain3_sessid`):
  GET_TURN_SERVER_LIST → GKZX- in-state with 7 body variants ⇒ P2P matches
  never get TURN creds (relay-only); not our wall. T7 Signal = BINDING_REQUEST
  + attr 0x9090 (Konami STUN answers both IPs; bot keepalive
  `work/stun_keepalive.py` 180/180). CMD_READY_FLAG/ALLREADY_FLAG = in-band
  only (gate 404). Gate-real post-start steps now all NOERR:
  CMD_GET_SESSION_ID {game_id} (reply platform_session_id_info),
  CMD_SEND_TURN_ADDRESS_DATA both directions, WATCH returns
  response_flg:1 + peer blob. Full-chain run `chain3_full_20261011.log` decides
  whether DISCONN_HB is a standing default cleared by filing a result.

- **2026-10-11 evening -- the z2 capture decoded** (passthrough_capture.csv
  has 11 plaintext gate/NTL HTTP POSTs; the earlier "encrypted only" read was
  wrong for HTTP): real phone flow adds **ntl.service.konami.net** --
  GateInfo.php handshake (titleCode PES2022, version 6.0.1, apiLevel 4 ->
  STATUS/API_STATUS/LOG_ACTIVE/SERVER_TIME/PUT_LOG_URL) then ReportLog.php
  lifecycle markers (pds/pde = punch phase, uds/ude = udp session, ~70-280 s
  apart) + UDP/5521 2-byte hop-count probes to ~30 GCP IPs.  gate-side run
  #4: CMD_USER_DATA_SYNC / CMD_TEAM_DATA_SYNC = HTTP 404 _DECODE_FAIL, no
  Cmd*Sync*.php in 11.1.0 -> in-band like READY_FLAG.  Precheck vs mapstamp
  contrast settles the heartbeat question: WITHOUT mid-match CHECK polls the
  server walks over DISCONN 0-3 within 0.5 s of END; WITH them gameend stays
  INVALID (window open) -> `--poll` added to chain3 (30 s cadence both
  identities, at_match_polling_interval_msec).  Server's open-match template
  match_result = 5 keys; echo-template submit variant added; run
  chain3_full5_20261011.log.

## 2026-10-11 (night) � DISCONN_HB root cause: both bots advertised ONE endpoint

- **`gameend` is NOT the submit gate.** mapstamp run kept
  `gameend=INVALID` (open) through END and every SET variant still returned
  `ERR_INVALIDARG`/`GKZX-` (t+2.8s .. t+14.5s since END). The "open window"
  theory is dead. `abnormal=DISCONN_HB` was already present at the
  post-start check at t+2s � before any heartbeat of ours could matter.
- **Why the server calls the link dead:** both PeerLink bots run on this ONE
  VM behind ONE public IP and both read the same `work/peer_endpoint.json`,
  so `CMD_SET_ROOM_MATCH_READY` advertised the identical reflexive endpoint
  `3.80.79.52:44000` for BOTH identities. The server's own echo confirms it �
  `ntl_address_list` contained two entries with the same
  `host_address/host_port/reflexive_address/reflexive_port`. Two peers at one
  ip:port is impossible NAT proof; the server resolves the match dead on
  arrival.
- **Fix (each identity binds its own local port + does its own STUN):**
  - `udp_punch.py` output file is now per-port � `:44000` ?
    `peer_endpoint.json`, `:44001` ? `peer_endpoint_bot.json`
    (log `peer_listen.log` / `peer_listen_44001.log`).
  - `chain3.py`: `endpoint_net()` ? `endpoint_net(tag)`;
    `match_ready(g, rid, tag)`; the `CMD_SEND_TURN_ADDRESS_DATA` blob was
    built ONCE outside its loop so both sides published the same address �
    now built per identity inside the loop.
  - This VM's NAT preserves the port (nat_type 1), so binding 44001 yields a
    real distinct reflexive `3.80.79.52:44001`. Verified live:
    owner `3.80.79.52:44000` (stun_session.py), bot `3.80.79.52:44001`
    (udp_punch.py PEER_PORT=44001). Run #11 `chain3_full11_20261011.log`.
- **`statistical_data.link_type` must stay `""`.** Run #10 set it to
  `LINK_TYPE_PEERS` (xrefs `FUN_07f3ba98`/`FUN_07f26c50` = P2P-SDK enum
  region, NOT the gate builder `FUN_078a259c`/`FUN_078a4574`) and it broke
  the PRE-match check: `check_res` GKZX- ? `check_state` NO ? `START_GAME`
  ERR_DATABASE/EVDU-. Same key name, different subsystem. Reverted; run #10
  aborted at start_game, run #11 isolates the endpoint fix.


## 2026-10-11 night (cont) -- the data plane finally exists

- **The two punch sockets had NEVER exchanged a single UDP packet.**
  Root cause was a wedge, not the network: `udp_punch.py` called
  `sock.settimeout(None)` whenever `load_target()` returned None. Both
  instances were started BEFORE `peer_punch_refresher.py` wrote any
  target file, so each parked in a blocking `recvfrom` and never
  re-checked the target again. Sat there for ~50 min logging nothing.
- **Fix 1 - never block indefinitely.** The receive timeout is now a
  fixed `0.5` s regardless of target state, so the loop always wakes up
  and re-reads the target file.
- **Fix 2 - `:44000` needed a responder that answers.** `stun_session.py`
  held `:44000` but only pumped its own T7 events; it does not answer
  inbound STUN binding requests. Moved the Konami T7 keepalive to
  `:44002` (`PEER_PORT=44002`) and put `udp_punch.py` on `:44000`, so
  BOTH identities are now punch responders that answer each other.
- **Result: first real data plane between the two bots.**
  `PUNCH ANSWERED by 3.80.79.52:44001 -- path is open` on the owner side,
  `PUNCH ANSWERED by 3.80.79.52:44000 -- path is open` on the bot side.
  Verified bidirectional.
- **Fix 3 - it was a positive feedback flood.** With two responders
  answering each other, each inbound request fell through to `continue`,
  which immediately sent another punch, which was answered instantly:
  ~770 pkt/s, **27 MB of log in 70 s** (disk was down to 1.59 GB free).
  Added outbound pacing (`PUNCH_EVERY = 0.5` s, the real client cadence
  behind `START_UDP_HOLE_PUNCHING_COMPLETE` /
  `KEEP_UDP_HOLE_PUNCHING_COMPLETE`), announce `PUNCH ANSWERED` once per
  peer, and throttle per-peer inbound lines to `LOG_EVERY = 60` s.
  Steady state is now **624 / 628 bytes per 45 s**.
- **Why this might be the DISCONN_HB key:** `abnormal=DISCONN_HB` was
  stamped within 2 s of `CMD_START_GAME`, i.e. the server resolving the
  match dead on arrival. If the server validates the advertised NAT proof
  by probing those addresses, the previous state - where nothing at all
  answered on `:44001` - is exactly "advertised peer is dead". Both
  ports now answer binding requests.
- Run #14 launched with the live data plane: `--live --poll --antenna`.
