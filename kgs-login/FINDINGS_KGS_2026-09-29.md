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

## 7. REFUTED 12:35 UTC — the backend is NOT down (game loads fine on the phone)

- **12:22:43 UTC**: the user's *phone itself* (Termux curl 8.12.1, HTTP/2 via
  nghttp2, residential mobile IP, fresh OpenSSL 3.4.1 stack) POSTed the exact
  probe to `command_service.CommandService/CommandStream` →
  `HTTP/2 502`, `server: awselb/2.0`, `grpc-status: 14`,
  `grpc-message: unavailable`.
- **12:22:00 UTC**: this VM's probe → byte-for-byte the same `502 g=14`.
- Same host, same minute, two unrelated IPs on opposite sides of the planet →
  identical answer. **The source-IP / ALB-geo-block theory is dead.**
- **12:35 UTC CORRECTION — the whole "down for everyone" reading above is
  WRONG.** The user reports the game loads fine on the phone right now, and a
  web check agrees (downdetector: no current eFootball problems). The 12:22
  phone-curl 502 therefore does NOT mean dead backends — it means OUR request
  differs from the real client's in a way that earns 502, on both networks.
- What stays true from the test: path
  `/command_service.CommandService/CommandStream` and host
  `pes22-game.cs.konami.net` are byte-correct (verified 12:40 UTC by sweeping
  all 147,375 printable strings in `libUE4.so`: exact path string + host
  string present, `command_service.proto` message names match). So the
  difference is elsewhere: destination IP (game may use `Def_Online_gRPC_server_address`
  override / `CS_SERVER_ADDRESS` / pinned IP instead of DNS pool), port, ALPN,
  metadata/headers, or body.
- The 09:40 "live session" was likely the game working normally — consistent
  with the server being up all along. The day's uniform 502s = our probe
  missing something, not an outage.
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

## 9. 2026-09-29 AFTERNOON — game works, our bytes don't (same door)

- User's 13:54 UTC PCAPdroid capture: the working game holds TLS sessions
  with `54.203.69.122` (a pool member our DNS also returns). Per-flow
  handshake parse (`parse_hs.py`): two `https` flows (ALPN `http/1.1`,
  one moving ~74 KB — config/assets) + one **gRPC flow** (sport 60892:
  ClientHello 185B-style, ciphers `c02b,c02c,c02f,c030,00ff`, ALPN
  `['grpc-exp','h2']`, server selects `h2`, ~4.5 KB server→client =
  a real answered stream).
- Our TLS profile now matches the game's (TLS1.2, same cipher set,
  ALPN `['grpc-exp','h2']` → server picks `h2`), yet `probe_game_ip.py`
  aimed at `54.203.69.122` returns `502 g=14` for: empty body, the
  game's own composer-built body, AND a real-identity body
  (uid `3c5aad…`, lang/region US, platform Android, ver 6.0.1).
- Full-binary sweep: no custom `grpc-*`/`x-*` metadata keys anywhere in
  `libUE4.so` (147k strings) — the game sends no exotic headers. The
  `Authorization`/token strings present are generic HTTP-stack leftovers.
- Remaining suspects, in order: (1) source IP (VM's AWS address refused,
  phone's accepted — phone `--resolve` test to `54.203.69.122` decides);
  (2) TLS-fingerprint (BoringSSL ext list vs python-ssl); (3) in-stream
  `path` value / `CMD_CONNECT_GRPC`-first sequencing (app drops unknown
  streams → ALB 502); (4) exact user-agent/encoding header minutiae.
## 10. THE REAL CAUSE (found 14:45 UTC): a 34-byte per-packet proxy on the phone

Decoding the 13:54 capture properly (not dismissing it as noise) shows
**659 of 1311 TCP payload segments are 34-byte blobs**:

    00 00 01 07 | 20 21 | 00 00 | 29 | "IeFootball™" | 00*8 | <4-byte varies>

- Identical 34-byte prefix on every one; only the last 4 bytes vary
  (checksum/sequence).
- They appear on **every** connection in the capture — including Google's
  ad servers (`108.139.200.68`, `108.156.162.47`, `142.250.181.110`) and
  the DoH resolver. So they are **not** Konami's protocol and not gRPC: they
  are injected by a **transparent per-packet proxy/tunnel on the device**
  (the same VPN that gave the phone its `102.91.105.50` address).
- Consequence: the game never presents a clean TLS stream to
  `pes22-game.cs.konami.net`. Every packet is tagged, so Konami's front end
  sees a different byte stream than any direct client — which is why the
  game authenticates and gets answers while **every** direct attempt
  (ours, and the user's own `curl`, from 2 networks) gets `502 g=14`.
- This invalidates the "our bytes are wrong" family of theories. Ruled out
  by experiment today: IP (2 networks), 50+ request variants (path x4,
  version, user-agent incl. real `grpc-c++/1.x` form, 5 envelope `id`
  forms, 3 pack modes, empty body, game-composer body, real-identity body),
  connect-first sequencing, ALPN, content-type (`application/grpc` and
  `+proto`), HTTP/1.1 vs h2, hand-built frames with literal (non-Huffman)
  HPACK, WINDOW_UPDATE, SETTINGS ordering, stream open vs half-closed, and
  `grpc-timeout`. Every one: `502 g=14` in ~0.3 s. The game's own config
  code (run in the Unicorn harness) confirms the channel target is exactly
  `dns:///pes22-game.cs.konami.net:443/` — the door we use.

### 10a. CORRECTION 15:10 UTC — the 34-byte blobs are a CAPTURE artifact

Checked against `peerlink_match_1790619339531.zip`'s
`passthrough_capture.csv`, which records the **real internet-side bytes**:
**0 of 2071 TCP packets** contain the 34-byte `IeFootball™` marker, while the
same-session local pcap has 659. So the marker is added by the local capture
VPN (PeerLink's own tun capture), never reaches the internet, and is not
what Konami sees. **The "hidden proxy" theory above is withdrawn.**

### 10b. What the internet-side match capture proves (ground truth)

`passthrough_capture.csv` (2026-09-28 19:15, 8739 packets) contains five
TLS connections with SNI `pes22-game.cs.konami.net` — a **live, logged-in
match**:

| local port | server IP | up | ALPN offered |
|---|---|---|---|
| 34572 | 44.232.213.50 | 34,679 B | `http/1.1` |
| 45846 | 34.208.149.190 | 12,733 B | `http/1.1` |
| 53370 | 44.232.213.50 | 8,957 B | **`grpc-exp, h2`** |
| 52312 | 44.232.213.50 | 4,624 B | `http/1.1` |
| 34820 | 44.255.253.52 | 2,096 B | `http/1.1` |

- Confirms: the game really does use gRPC (`grpc-exp, h2`, ciphers
  `c02b,c02c,c02f,c030,ff`, no TLS-1.3 offer on that socket), and the
  other four sockets are plain HTTPS.
- These are **different IPs from our DNS pool** (`us-west-2` ELB) — the
  capture was taken through the capture VPN, so geo-DNS resolved elsewhere.
- Probed **every** one of those exact IPs with the real-identity envelope:
  `44.232.213.50`, `34.208.149.190`, `44.255.253.52`, `16.146.220.162` →
  **all `502 g=14`**. Combined with the 50+ request variants, the refusal is
  independent of both the address and the request.
- Also visible in plaintext: `ntljp.service.konami.net` (4×) and
  `ntl.service.konami.net` (1×) — the Japanese-region gate host, consistent
  with the phone's locale.

**Where this leaves the diagnosis.** Every observable we can change from
outside — address, TLS/ALPN, HTTP/2 framing, HPACK, headers, envelope
fields, body, message order — produces the identical `502 g=14` in ~0.3 s,
while the identical TLS version, cipher set and ALPN from the real client
on the same day gets served. The remaining difference is not on the wire in
any form we can synthesise; it is something about the client's *identity or
environment* (a value sealed in the game's own certificate/key material, or
state the server checks before the first stream). The decisive experiment is
therefore to let the game's own code produce the bytes: run its gRPC client
inside the Unicorn harness and capture the exact request it emits.

---

# Session 2 — the decisive experiment is now RUNNING (2026-09-29 ~22:45Z)

## The binary was never the problem (correction)

Downloaded the genuine package: `jp.konami.pesam.xapk`, 822 MB,
**versionName 11.0.1 / versionCode 311000101** — byte-for-byte the build on
the user's phone. Its `lib/arm64-v8a/libUE4.so` is **SHA-256
`2ac4ff17ac8ad713…` — identical to the `libUE4.so` we had been reverse
engineering all day.** So an assumption from earlier in this investigation
("we analysed an older 5.x/6.x build") was wrong and is now retracted: the
binary we read is the current one. Host `pes22-game.cs.konami.net`, the single
gRPC service path `/command_service.CommandService/CommandStream`, and the
`Def_Online_*` key set are therefore all confirmed correct, and the `502 g=14`
is definitively **not** caused by reading the wrong values out of the binary.

Note on the Play Store question: the package was fetched from a mirror
(`apkeep -d apk-pure`) because Google's own download path requires
authenticating a Google account. The artifact itself is the Play one —
matching version code, and the shared library is bit-identical to the one
running on the user's phone.

## Free ARM64 compute — solved, and it is GitHub

The user's suggestion to use their GitHub account was the answer. The public
repo gets a **free native-ARM64 runner** (`ubuntu-24.04-arm`). Measured on it
(report: `kgs-login/ci-report/latest.md`):

| fact | value |
|---|---|
| kernel | `6.17.0-1022-azure` (Ubuntu) |
| `CONFIG_ANDROID_BINDER_IPC` | `m` |
| `CONFIG_ANDROID_BINDERFS` | `m` |
| binderfs mount | `binder on /dev/binderfs type binder (rw,relatime,max=1048576)` |
| cpu / ram / disk | 4 vCPU / 15 GiB / 108 GB free |
| docker privileged | yes (`PRIVILEGED_OK`, server 28.0.4) |
| redroid 14 `arm64-v8a` | **boots in ~10 s, `uid=0(root)`** |

This is the whole reason AWS was a dead end and this is not: Debian's AWS
kernel has `CONFIG_ANDROID_BINDER_IPC` **unset** (so `mount -t binder` cannot
work at all), whereas Ubuntu ships `binder_linux` as a loadable module. The
8x larger RAM and correct OS are a bonus, not the reason.

## Capture technique: plaintext by configuration, not by interception

Rather than break TLS or hunt a stripped `SSL_write`, the game's own gRPC
loader can be told to speak plaintext. Fully decoded from `0x7b101f8`:

```
0x7b10258  adrp x0, #0xc02000 ; add x0, x0, #0x3be ; mov w1, #0x18
0x7b1027c  bl   0x2f0eaf0                     ; int Def_ getter, (x0=key,w1=len)
0x7b10280  cbnz w0, #0x7b105c8                ; non-zero => plaintext channel
            ; literal = "Def_Online_gRPC_insecure" (24 bytes at 0xc023be)

0x7b10284  adrp x0, #0xaf7000 ; add x0, x0, #0x14b ; mov w1, #0x1d
0x7b10294  bl   0x2f0eaf0                     ; "Def_Online_gRPC_debug_root_ca" (29)
0x7b1029c  adrp x8, #0xa4a8000 ; add x8, x8, #0x480
                                               ; global std::string = root CA path
```

So one Interceptor on the int getter at **`0x2f0eaf0`** that returns 1 when
the key pointer equals `0xc023be` puts the channel in plaintext. From then on
gRPC writes HTTP/2 frames straight to the socket and a plain libc
`send`/`write` hook (always resolvable) captures the request verbatim. The
bytes come from the game's own serializer — nothing is hand-assembled.

`SSL_write` was tried first and is a dead end: the `"SSL_write"` literal at
`0xa27cf3` has **no ADRP/ADD code reference** in the 104 MB executable segment,
so the function cannot be recovered from the stripped binary that way.

## Corrections to earlier notes

- The two phone captures in `uploads/` (`PCAPdroid_29_Sep_13_54_22.pcap`,
  `..._10_31_15.pcap`) are **connectivity checks, not game sessions**. Every
  ClientHello in them is `www.applilink.jp` with `ALPN http/1.1`. The genuine
  `pes22-game` TLS facts came from `passthrough_capture.csv`, not these pcaps.
- ClientHello parsing had an off-by-3 bug: the 24-bit handshake length sits
  between the handshake type and `legacy_version`. Fixed; hello sizes and
  extension orders now parse correctly.
- The 34-byte `IeFootball™` blob appears on **both directions of every**
  connection including 34-byte packets with no TLS record header — consistent
  with a capture tool artefact, as previously concluded.

## GitHub Actions gotchas that cost three failed runs

1. **A workflow with no `actions/checkout` step has no git repo**, so
   `git add`/`git commit`/`git push` all fail silently (they were hidden behind
   `|| echo`). Every self-report was being discarded.
2. **`actions/checkout` leaves a detached HEAD** on `push` events, so a bare
   `git push` does nothing — push by refspec: `HEAD:refs/heads/<branch>`.
3. **The runner's shell is `bash -e -o pipefail`.** An unguarded
   `cmd_a || cmd_b` where *both* may fail aborts the whole step instantly.
   Every optional command needs its own `|| true`.
4. **`binder_linux.ko` is in `linux-modules-extra-$(uname -r)`**, not the base
   runner image. Without that `apt` line `modprobe` has nothing to load and
   `mount -t binder` has no filesystem type to mount.

## Measured redroid behaviour on the ARM64 runner

- Plain invocation boots in **~10 s**:
  ```
  redroid/redroid:14.0.0_64only-latest \
    androidboot.redroid_width=720 androidboot.redroid_height=1280 \
    androidboot.redroid_dpi=320 androidboot.use_memfd=true
  ```
  → `sys.boot_completed=1`, `uid=0(root)`, `ro.odm.product.cpu.abilist64=arm64-v8a`.
- **`androidboot.redroid_gpu_mode=swiftshader` prevents boot entirely.** Added
  speculatively for the UE4/Vulkan requirement; measured result was a 180 s
  wait that never saw `boot_completed`, with the container started but
  Android never finishing init. Removed. (Software rendering, if it turns out
  to be needed, has to be solved some other way.)
- The kernel config is `CONFIG_ANDROID_BINDER_DEVICES=""` and
  `modprobe binder` fails (the module is `binder_linux`), yet
  `mount -t binder binder /dev/binderfs` succeeds — the kernel resolves
  `fs-binder` and loads `binder_linux` itself. So the mount is the reliable
  test, not modprobe.

## Tooling now built and self-tested

| script | purpose |
|---|---|
| `kgs-login/scripts/capture_insecure.js` | Frida: force `Def_Online_gRPC_insecure=1`, then hook libc `send`/`write` to capture plaintext HTTP/2 |
| `kgs-login/scripts/decode_capture.py` | reassemble captured sends → h2 frames → HPACK (static + Huffman) → gRPC envelope → recursive protobuf |
| `kgs-login/scripts/test_decode.py` | self-test for the decoder; **PASS** |
| `kgs-login/scripts/replay_capture.py` | send the game's own bytes verbatim over real TLS; both outcomes are decisive |
| `kgs-login/scripts/trust_our_ca.js` | alternative path: point the game at our CA via the `0xa4a8480` global (kept in case plaintext mode is refused) |
| `kgs-login/scripts/make_mitm.py` | mitmproxy addon, same fallback |

## Why "just MITM it" is not a valid shortcut

If the `502 g=14` were caused by TLS-layer filtering, a MITM would be
useless: the proxy would be the TLS client to Konami, presenting Python's or
Go's handshake, not the game's BoringSSL one. Capturing the game's bytes
*inside its own process* is the only measurement that keeps the real client
identity intact — which is why the work went into the plaintext-config route
rather than a proxy.
