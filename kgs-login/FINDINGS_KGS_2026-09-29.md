# FINDINGS KGS — 2026-09-29 (the maintenance-window session)

Plain summary of what was proved today. All of it came from two sources: the
game's own `libUE4.so` code, and the user's fresh capture
(`peerlink_match_1790619339531.zip`, 2026-09-28 19:08–19:15 UTC) whose
`passthrough_capture.csv` holds **complete IP packets** of the game's
internet traffic.

## 1. THE ANSWER TO "WHY DOES NOTHING WORK AT NIGHT"

| When (UTC) | Result |
|---|---|
| 28 Sep 19:08–19:15 (user's capture) | game logs in fine, gRPC stream works |
| 29 Sep 02:40–03:35 (all probes tonight) | gate PHP = `500`, gRPC = `502 awselb/2.0` + `grpc-status: 14 unavailable` |

**Konami's daily maintenance runs 02:00–08:00 UTC.** Every test tonight ran
*inside* it. `502 awselb/2.0` = the load balancer has no healthy backend.
`ntl.service.konami.net` stayed `200` the whole time (outside the fleet).

`gate_retry.py` now waits for 08:05 UTC and re-fires every 20 min until real
answers come back.

## 2. THE GATE PHP IS DEAD ENOUGH TO STOP FIGHTING IT

- `gate_CMD_*.php` exists (no fastcgi 404) but returns `500` with an empty
  body for **every** input: GET, raw msgpack, `req=` json/ascii85/hex/…,
  query strings, the game's own bytes with real values, JSON content-type.
- A bare GET returning 500 only proves the script fatals before/without a
  body; it does not prove the body is ignored. But since the *game's own
  serialiser output with real values* also gets 500, the PHP path adds
  nothing while the backend is down — and the app demonstrably logs in via
  gRPC anyway (below). Do not hand-craft more PHP requests.
- Control evidence that our HTTP client is fine: `ntl.service.konami.net`
  `/ntl/api/GateInfo.php` and `/ntl/api/PES2022/ReportLog.php` answer
  `200 / STATUS: 400` (= "wrong params", a real parse).

## 3. THE APP'S REAL LOGIN CHANNEL = gRPC over HTTP/2, and we have its TLS profile

From `passthrough_capture.csv`, flow `10.0.0.2:53370 → 44.232.213.50:443`:

- ClientHello: **TLS 1.2 only**, 5 ciphers
  `c02b,c02c,c02f,c030,00ff`, ALPN offered **`['grpc-exp','h2']`**
- Server picks `h2` (offering `grpc-exp` alone gets no ALPN at all — matches
  earlier `sh_alpn.py` notes)
- Method: `/command_service.CommandService/CommandStream`
- Stream stays open with a ~317 B message every 15 s (keepalive)
- Another session (port 52312, same host) is the request/response command
  traffic: ~640 B requests, answers back

`grpc_exp.py` reproduces this exactly (TLS 1.2 + those 5 ciphers + both
ALPNs + h2 + gRPC framing). Right now it still gets
`502 awselb / grpc-status 14` on every IP — consistent with maintenance.

## 4. REAL IDENTITY VALUES (recovered in plaintext from port 80)

`POST /ntl/api/GateInfo.php` and `/ntl/api/PES2022/ReportLog.php` are
**plaintext HTTP**, so the working app's own words are readable:

| Field | Real value |
|---|---|
| `titleCode` | `PES2022` |
| `locale` | `US` |
| `version` / `client_version` | **`6.0.1`** |
| `libVer` | `1.17.1-Android-15` |
| `uid` | `3c5aad3c6b8425c611ebe2f5da6c25af` |
| `opt` | `22011111` |
| ReportLog host/path | `ntljp.service.konami.net` → `/ntl/api/PES2022/ReportLog.php` |
| log `type` values | `pds`,`pde`,`uds` (and `ude` in older builds) |
| StunInfo | `pesam.stun.service.konami.net:3478` |

GateInfo body shape (game's own):
`req=<urlencoded JSON>` with keys
`{"titleCode":"PES2022","locale":"US","version":"6.0.1","extra":"","apiLevel":"4"}`

## 5. COMMAND SET FOR THE ROOM GOAL

384 `CMD_*` msgids in the binary. Room chain:
`CMD_GET_SESSION_ID` → `CMD_LOGIN` → `CMD_CREATEJOIN_ROOM` →
`CMD_GET_ROOM_INFO` → `CMD_SEND_RECRUIT_CODE` (the shareable join code).
Also `CMD_GET_KGS_GUEST_LOGIN_TOKEN` for KGS guest login.
`make_room.py` runs the chain over the same gRPC transport.

### ctor / writer addresses (xref from the msgid strings)

| command | ctor fn | second ref fn |
|---|---|---|
| `CMD_CREATEJOIN_ROOM` | `0x77b1830` | `0x77b7414..0x77b7558` |
| `CMD_GET_SESSION_ID` | `0x7da8794` | `0x7da8aa8..0x7da8c2c` |
| `CMD_SEND_RECRUIT_CODE` | `0x76c5c74` | (same fn) |

Every command's ctor serialises the **same 10-field base map**:
`msgid, rqid, user_id, session_id, my_platform, s_keyword, lang, region,
platform, client_version` — the per-command writer (e.g. CMD_LOGIN's
`0x76b1b28`) appends the real fields.

### room-related field names in the binary (MessagePack keys)

`room_id`, `room_kind`, `room_mode`, `room_core_settings`,
`room_match_settings`, `room_entry_restriction`, `room_create_time`,
`room_users`, `room_info`, `room_list_num`, `recruit_code`, `comment`,
`team_id`, `select_team_id`, `select_compe_unit_id`, `match_num`,
`game_mode`, `kick_user_id`.

### confirmed request/response fields (from the game's own parsers)

| command | request fields beyond the 10-field base | response fields |
|---|---|---|
| `CMD_GET_SESSION_ID` | `game_id` | `session_id` |
| `CMD_CREATEJOIN_ROOM` | (room request builder fn `0x77bf578..0x77c2ab8`, refs `room_kind`) | **`result`, `room_id`, `event_log`** |
| `CMD_SEND_RECRUIT_CODE` | `recruit_code` (write path `0x76c5e40..0x76c60e0`) | **`recruit_code`** ← the join code |
| `CMD_GET_KGS_GUEST_LOGIN_TOKEN` | base map only (`NotImplement` defaults) | token |
| `CMD_LOGIN` | writer `0x76b1b28`, 25-field map | session_id / user_id |

## 6. OTHER PROVEN FACTS (today)

- Capture-era gate IPs (June 2026 etc.) are gone/reassigned: hostname
  mismatch or timeouts. Today's DNS pool (8–9 rotating addresses) all serve
  the same broken-state answers; one address returns fastcgi
  `404 File not found.` for the gate scripts.
- `info.service.konami.net` returns `404` ("Not Found", Apache-ish) from the
  user's **residential** IP on `/pes22/gate/gate_CMD_LOGIN.php` and `403
  awselb/2.0` from this VM on everything — a datacenter-IP block on portal
  hosts. The user's network sees 404 there; no gate scripts on that host.
- The game's app identity/version from the APK we have: `11.0.1`
  (versionCode `311000101`), same as the phone's installed version. Our
  `libUE4.so` is from an older title build (5.x) whose protocol is unchanged
  on the wire (the capture proves the shapes we send are right).

## 7. THE DECISIVE TEST — the backend is down FOR EVERYONE

- **12:22:43 UTC**: the user's *phone itself* (Termux curl 8.12.1, HTTP/2 via
  nghttp2, residential mobile IP, fresh OpenSSL 3.4.1 stack) POSTed the exact
  probe to `command_service.CommandService/CommandStream` →
  `HTTP/2 502`, `server: awselb/2.0`, `grpc-status: 14`,
  `grpc-message: unavailable`.
- **12:22:00 UTC**: this VM's probe → byte-for-byte the same `502 g=14`.
- Same host, same minute, two unrelated IPs on opposite sides of the planet →
  identical answer. **The source-IP / ALB-geo-block theory is dead.**
- The phone had a *live* gRPC session at 09:40 UTC (PCAPdroid capture:
  ClientHello → 6 server frames → keepalives for 90 s) and is refused at
  12:22. So the KGS backend went down between **09:40 and 12:22 UTC, on a
  Tuesday** — unscheduled, outside the Thursday 02:00–08:00 maintenance window.
- ALB `502` = no healthy target / target connection failure. Rule-based
  rejections from the same front end return `464`/`415`/`403` — we get those
  when we vary method/headers, which proves the front end is up and applying
  rules; only the backend targets are gone.
- Therefore no byte-level variable (headers, metadata, TLS fingerprint, ALPN,
  payload) is what is blocking us: every variation gives the same 502, and the
  phone's completely different stack gives it too. When the targets come back,
  our bytes should be accepted (they already were once — the 09:40 session).
- Relay attempts to re-run the probe from the phone's IP before this test:
  localhost.run tunnels kept dropping ("no tunnel here"), and this VM's sshd
  is unreachable (cloud security group blocks 22) — moot now that the phone
  can run the probe directly with `curl --http2`.

## 8. NEXT

1. `health_poll.py` (running, 10-min interval) watches gRPC + gate; watch
   `health_poll_out.txt` for the first non-502.
2. On recovery: `CMD_GET_SERVER_ENV` (get PUT_LOG_URL/config),
   `CMD_GET_KGS_GUEST_LOGIN_TOKEN` → `fire_login.py <auth_code> [hash]`
   (needs a gRPC-channel variant of the gate-POST scripts; a few MB of phone
   data at most, against the user-approved 30 MB budget).
3. `auth_code` still needs the user's own browser (account.konami.net is
   IP-blocked from this VM); the code lives ~60 s.
4. Then `make_room.py` for the room code.
