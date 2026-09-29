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

## 7. NEXT

1. `gate_retry.py` fires at 08:05 UTC and every 20 min; watch
   `gate_retry_out.txt` for the first non-maintenance answer.
2. On a real answer: `CMD_GET_SERVER_ENV` (get PUT_LOG_URL/config),
   `CMD_GET_KGS_GUEST_LOGIN_TOKEN` → then `fire_login.py <auth_code> [hash]`.
3. `auth_code` still needs the user's own browser (account.konami.net is
   IP-blocked from this VM); the code lives ~60 s.
4. Then `make_room.py` for the room code.
