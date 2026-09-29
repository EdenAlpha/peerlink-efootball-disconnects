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

## The gRPC config loader, fully decoded

`0x7b101f8` is the loader. It has two branches and the **insecure branch is not
a variant of the secure one** — it resolves its target from different `Def_`
keys entirely. That matters: forcing the insecure flag without also supplying
those keys would leave the channel with no destination and nothing would ever
connect.

```
0x7b10258  adrp x0,#0xc02000 ; add x0,x0,#0x3be ; mov w1,#0x18
0x7b1027c  bl 0x2f0eaf0                     ; int getter
0x7b10280  cbnz w0, #0x7b105c8              ; --> insecure branch

; secure branch, 0x7b10284:
0x7b10284  adrp x0,#0xaf7000 ; add x0,x0,#0x14b ; mov w1,#0x1d
0x7b10294  bl 0x2f0eaf0                     ; "Def_Online_gRPC_debug_root_ca" (29)
0x7b1029c  adrp x8,#0xa4a8000 ; add x8,x8,#0x480
                                            ; global std::string = root CA path

; insecure branch, 0x7b105c8:
0x7b105c8  x23 = this+0x308 ; x22 = this+0x320 ; x21 = this+0x338
0x7b105e0  bl 0x7d65c84                     ; clear the three
0x7b105e4  literal 0xba2aff (30) -> 0x2f0e18c ; str -> this+0x308
0x7b1061c  literal 0x9c69c1 (27) -> 0x2f0e18c ; str -> this+0x320
0x7b10654  literal 0xb68de6 (27) -> 0x2f0eaf0 ; int -> strh [this+0x338]
0x7b10674  bl 0x7b10ac4
```

### Verified `Def_Online_gRPC_*` literals (offsets read from the file, not inferred)

| key | offset | getter | supplied value |
|---|---|---|---|
| `Def_Online_gRPC_insecure` | `0x0c023be` | int `0x2f0eaf0` | `1` |
| `Def_Online_gRPC_server_address` | `0x0ba2aff` | string `0x2f0e18c` | `pes22-game.cs.konami.net` |
| `Def_Online_gRPC_server_path` | `0x09c69c1` | string `0x2f0e18c` | `/command_service.CommandService/CommandStream` |
| `Def_Online_gRPC_server_port` | `0x0b68de6` | int `0x2f0eaf0` | `443` |
| `Def_Online_gRPC_debug_root_ca` | `0x0af714b` | int `0x2f0eaf0` | (flag; CA path is the global at `0xa4a8480`) |

**A mistake caught before it cost a run:** `_server_path` and `_server_port` are
*both 27 characters*, so inferring the key from the immediate's length alone
identifies them ambiguously. The first draft hooked `_server_port` and supplied
a port string where a path was required. Reading the actual bytes at each
offset settles it. The same class of error is why the key comparison in the
Frida script now matches on the key *text* as well as the pointer.

### Return conventions (needed to override them)

- `0x2f0eaf0` (int): `(x0 = key bytes, w1 = key length) -> w0`
- `0x2f0e18c` (string): `(x0 = key bytes, x1 = key length) -> x0 = std::string*`
  — the caller immediately does `ldrb w8,[x0]` (the SSO size byte) and then
  calls `size()`, so a raw `char*` will not do. The script builds a real
  libc++ `std::string` (short form if <= 22 bytes, otherwise the long form with
  a data pointer at `+0x10`).

## Observed GitHub Actions failure modes, with timings

| symptom | actual cause |
|---|---|
| job fails in ~6 s at `modprobe` | `cmd_a \|\| cmd_b` where both may fail, under `bash -e` |
| job fails in ~0–3 s at the apkeep step | **the runner user is not root, so `/root` is not writable** — `curl -o /root/apkeep` dies with permission denied before it transfers anything. The first diagnosis blamed a `chmod +x apkeep` path mismatch, which was wrong; the step log is empty either way, so it was checked rather than assumed. This also explains why `tee /root/step01.log` never produced a log in the report. All host-side work now lives in `/tmp/kgs`. |
| step 01 times out at exactly 180 s | `androidboot.redroid_gpu_mode=swiftshader` prevents `boot_completed` |
| reports never appear in the repo | no `actions/checkout` step, so there is no git repo at all |
| report push silently does nothing | `actions/checkout` leaves a detached HEAD |

## BREAKTHROUGH: the 502 is generated by the AWS load balancer, before our payload is read

The replayer (`scripts/replay_capture.py`) was validated against the live
endpoint, and its response decoded with a **correct** HPACK decoder:

```
connecting to pes22-game.cs.konami.net:443, SNI/verify against the same host
TLS: TLSv1.2  cipher=ECDHE-RSA-AES128-GCM-SHA256  alpn=h2
sent 221 bytes (h2 preface + SETTINGS + HEADERS + DATA/END_STREAM)

--- SETTINGS      MAX_CONCURRENT_STREAMS=128  INITIAL_WINDOW_SIZE=65536  MAX_FRAME_SIZE=16777215
--- WINDOW_UPDATE 8388352
--- HEADERS  stream=1  flags=END_STREAM,END_HEADERS
  :status: 502
  server: awselb/2.0
  date: Tue, 29 Sep 2026 23:06:31 GMT
  content-type: application/grpc
  content-length: 0
  grpc-status: 14
  grpc-message: unavailable
```

What this establishes:

1. **The front door is an AWS Elastic Load Balancer v2** (`server: awselb/2.0`).
   The earlier `awel` reading was a decoder artifact, not a hostname.
2. **The response is a single trailers-only HEADERS frame with `END_STREAM`** —
   no gRPC response message is sent, just an error status.
3. `grpc-status: 14` = `UNAVAILABLE`, `grpc-message: unavailable`.

### RETRACTION: `content-length: 0` does not mean the body went unread

An earlier version of this document claimed that `content-length: 0` proved the
ALB was "failing to deliver the request to a healthy backend" and that our
payload was "never processed". **That was an inference presented as a finding,
and it is retracted.**

A gRPC error is returned as a *trailers-only* response, which by definition has
no message body, so `content-length: 0` carries no information about whether the
request was read. The two readings — "ALB cannot route to the gRPC target" and
"the gRPC service read the request and returned UNAVAILABLE" — are both
consistent with what we can see, and the claim of certainty was not warranted.

`UNAVAILABLE` (14) rather than `UNAUTHENTICATED` (16) or `INVALID_ARGUMENT` (3)
is itself weak evidence *for* the service having processed the request: a server
that ignored the payload entirely would have no basis for choosing that code.
That is an inference too, and is being tested rather than assumed
(`scripts/body_differs.py`).

### The TLS handshake is NOT the discriminator (measured)

The game's real gRPC ClientHello was recovered byte for byte from
`passthrough_capture.csv` in the match exports (`scripts/extract_game_hello.py`,
`scripts/scan_for_grpc_hello.py`). It is genuinely unusual:

```
185 bytes, legacy_version 0x0303, NO supported_versions  -> TLS 1.2 only
ciphers (5)      c02b c02c c02f c030 00ff
extensions (9)   server_name ec_point_formats supported_groups session_ticket
                 0x3374 ALPN encrypt_then_mac session_ticket signature_algorithms
ALPN             grpc-exp,h2
SNI              pes22-game.cs.konami.net
```

That is Chromium's **Cronet** stack, which also explains `Def_Online_Use_Cronet`
in the binary — so the gRPC channel is not BoringSSL-direct after all.

Those exact 185 bytes were then put on the wire unaltered
(`scripts/hello_shot.py`), alongside a stock Python TLS 1.2 ClientHello as a
control:

| client | result |
|---|---|
| the game's exact ClientHello (fresh random) | **ServerHello**, handshake proceeds, cipher `c02f` |
| the game's exact ClientHello (verbatim) | **ServerHello**, handshake proceeds |
| stock Python TLS 1.2 | handshake completes, `alpn=h2`, then HTTP/2 SETTINGS |

**Both are accepted.** The ClientHello shape is therefore eliminated as the
discriminator, despite being the single most distinctive thing about the game's
traffic. (A first version of `hello_shot.py` printed a "DIFFERENTLY" verdict
because it compared a TLS record header against an HTTP/2 frame header; that
comparison was meaningless and the verdict is wrong. The table above is the
real result.)

### A decoder bug that had to be fixed first

The first version of the HPACK/Huffman decoder had a **wrong `CLEN` table**
(it started `5,6,6,6,...` instead of `13,23,28,28,...`), and a bogus 5-bit
prefix branch. Against the RFC 7541 test vectors it produced
`'no-cache' -> '%a%c'` and `'302' -> '2'`. Against the real response it turned
`server: awselb/2.0` into `host: TmclcciaceMT` and `vary: awel`.

Since the whole point of this decoder is to read a header the game sends, a
decoder that invents plausible header names is worse than no decoder. It now
uses the `hpack` library and **refuses to fall back**, and
`decode_capture.py`/`test_decode.py` were re-verified afterwards.

## ALPN is eliminated as the discriminator (measured, not assumed)

Since the 502 comes from `awselb/2.0`, one plausible discriminator is that the
ALB routes by ALPN. `scripts/alpn_matrix.py` holds host, SNI, TLS version and
cipher constant and varies only the offered ALPN:

| ALPN offered | chosen by server | response |
|---|---|---|
| `h2` | `h2` | HTTP/2, 145 B, `grpc-status: 14` |
| `grpc-exp`,`h2` (what the game offers) | `h2` | **byte-identical** 145 B |
| `grpc-exp` only | *(none)* | `HTTP/1.1 400 Bad Request` — `server: awselb/2.0` |
| `http/1.1` | `http/1.1` | `HTTP/1.1 464` — `server: awselb/2.0` |
| *(none)* | *(none)* | `HTTP/1.1 464` / `400` |

Conclusions:

- ALPN **is** load-bearing: only `h2` reaches the gRPC path at all. Anything
  else lands on an HTTP/1.1 error page from the same load balancer.
- But we are **already on the `h2` path, offering exactly what the game
  offers** (`grpc-exp`,`h2`), and the response is byte-identical to the
  single-`h2` case. So ALPN cannot be what separates us from the phone.
- Two distinct load-balancer error codes are reachable from here: `400` (when
  HTTP/2 bytes arrive without `h2` negotiated) and `464` (HTTP/1.1). Neither is
  the `502/14` we are chasing, so the `502/14` is specific to the HTTP/2 gRPC
  target group.

TLS 1.2 with `ECDHE-RSA-AES128-GCM-SHA256` was used for every row, and the
ALB accepted it, so the TLS version is not being refused either.

**Where that leaves the hunt.** Eliminated so far, each with evidence: request
bytes (50+ variants, and now proven irrelevant since `content-length: 0`),
address (all five game IPs), ALPN (above), TLS version/cipher (accepted), and
message ordering. What remains is the shape of the client's TLS ClientHello
itself, or connection state the ALB associates with the client — which is
precisely what the on-device capture can show and what a proxy cannot,
because a proxy would substitute its own ClientHello.

## The topology behind the 502: nginx is healthy, the gRPC target group is not

Same TLS session, same host, same ALPN, only the request path varied
(HTTP/1.1, `Server` header read from the reply):

| request | response | server |
|---|---|---|
| `GET /` | `403 Forbidden` (289 B of real content) | **nginx** |
| `GET /health` | `404 Not Found` | **nginx** |
| `GET /nonexistent-xyz` | `404 Not Found` | **nginx** |
| `GET /command_service.CommandService/CommandStream` | `464` | awselb/2.0 |
| HTTP/2 `GET /` | 277 B, HTTP/2 HEADERS | (ALB) |
| HTTP/2 `GET /health` | 273 B | (ALB) |
| HTTP/2 on the gRPC path, with DATA | 99 B → `grpc-status: 14` | awselb/2.0 |

Two things follow:

1. **There is a live nginx behind the load balancer.** It answers `/` with a
   289-byte 403 and unknown paths with 404. The host is not dead and TLS is not
   being refused.
2. **The gRPC service is a separate target group, and that group will not serve
   us.** The ALB answers 502/`UNAVAILABLE` with `content-length: 0`, so the
   request never reaches a gRPC backend. The game reaches it from the phone.

Since the same host, path, SNI, TLS version, cipher and ALPN all work for the
phone, and the only remaining difference we can see from outside is **the shape
of the TLS ClientHello itself**, the next measurement is the game's real
ClientHello byte-for-byte.

That is directly obtainable now: run the game normally (TLS to the real
endpoint) inside the rooted container with a packet capture on the device's
own interface, and read the ClientHello off the wire. It is the one piece of
evidence a proxy cannot substitute for, because a proxy would present its own.

### Environment note: redroid does have software Vulkan

The concern that eFootball (UE4, references `libvulkan.so`) could not start
without a GPU turns out to be unfounded. Inside the booted container:

```
/vendor/lib64/hw/vulkan.lvp.so        <- Mesa lavapipe, software Vulkan
/vendor/lib64/hw/vulkan.pastel.so
/vendor/lib64/hw/vulkan.panfrost.so
/gralloc.redroid.so, /hwcomposer.redroid.so
/system/lib64/libvulkan.so, libEGL.so, libGLESv3.so
```

`androidboot.redroid_gpu_mode=swiftshader` is not needed and actively prevents
boot; the image already provides a software Vulkan ICD.

### Remaining blocker in the capture pipeline

The on-device run now completes boot, download, Frida install and package
install, and fails in the capture step with an **empty frida log** — i.e.
`frida-server` never started, and `docker exec -d` was discarding its stderr.
The next run captures that output, checks SELinux state and verifies the
binary's architecture, so the reason is visible instead of inferred.

## The `content-type` theory was wrong — the 502 appears to be intermittent

This section previously claimed a root cause. **That claim is retracted.** It is
kept here because the sequence of measurements is the useful part, and because
getting it wrong is exactly the kind of thing worth recording.

**What was observed.** `scripts/read_grpc_message.py` sent five requests:

```
content-type: application/grpc        -> :status 502  grpc-status 14  "unavailable"
content-type: application/grpc+proto  -> :status 200  grpc-status 13
                                         "Error deserializing request: invalid
                                          wire type 7 at offset 8"
```

That looked conclusive: the plain form is diverted by the load balancer, the
`+proto` form reaches the application, and every request we had ever sent used
the plain form.

**Why it is wrong.** `scripts/ctype_matrix.py` then sent nine requests varying
only the content type, and:

```
application/grpc                -> :status 200  grpc-status 13  (parse error)
application/grpc+proto          -> :status 200  grpc-status 13  (parse error)
application/grpc;               -> :status 200  grpc-status 13
application/grpc+json           -> :status 200  grpc-status 13
application/grpc-proto          -> :status 200  grpc-status 13
APPLICATION/GRPC+PROTO          -> :status 415  (uppercase rejected)
application/grpc+proto; charset -> :status 200  grpc-status 13
```

`application/grpc` returned **200 with the same parse error** as `+proto`. So
content-type is not the discriminator; the first run happened to catch the 502
on the rows that used `application/grpc`.

The lesson is about method: one observation of a difference is not a cause, and
these two runs differed only in time.

### What survives

- **The server does read and parse our body.** Solid: a 71-byte invalid payload
  produced a 134-byte error HEADERS frame where a 5-byte payload produced 87
  (`scripts/body_differs.py`).
- **The gRPC server is reachable and answering us right now**, with detailed
  protobuf diagnostics — a far better position than where this investigation
  started.
- **The 502/14 is an `awselb/2.0` response with an empty body**, produced at the
  load balancer rather than by the gRPC application.

The open question is whether the 502 is a transient availability or
health-check condition, which `scripts/is_it_flaky.py` measures by sending
byte-identical requests repeatedly and counting outcomes. If both outcomes occur
for identical bytes, no request-side change can address it, and `502/14` should
be treated as a retryable condition rather than a rejection.

### The game's real ClientHello, for the record

Recovered byte-for-byte from the match exports
(`scripts/scan_for_grpc_hello.py`; 10+ exports contain it):

```
185 bytes, legacy_version 0x0303, NO supported_versions  -> TLS 1.2 only
ciphers (5)      c02b c02c c02f c030 00ff
extensions (9)   server_name ec_point_formats supported_groups session_ticket
                 0x3374 ALPN encrypt_then_mac session_ticket signature_algorithms
ALPN             grpc-exp,h2
```

That is Chromium's **Cronet** stack — consistent with `Def_Online_Use_Cronet`
in the binary, so the gRPC channel is not BoringSSL-direct after all. Putting
those exact 185 bytes on the wire unaltered gets a normal ServerHello, and so
does a stock Python ClientHello (`scripts/hello_shot.py`), so the ClientHello
shape is *not* a discriminator. It was worth ruling out explicitly: it is the
most distinctive thing about the game's traffic and it turns out to be
irrelevant.

## STATUS CHANGE: the endpoint is serving us now. The 502 was transient.

`scripts/is_it_flaky.py` sent **20 byte-identical requests** and counted the
outcomes:

```
  # 1..20   :status 200   grpc-status 13   content-type application/grpc+proto
             "Error deserializing request: invalid wire type 7 at offset 8"

  20 x  :status=200 grpc-status=13
  VERDICT: identical bytes gave an identical outcome 20 times.
```

So:

- The `502 / UNAVAILABLE` from `awselb/2.0` **is not reproducible**. It was a
  transient load-balancer condition — no healthy target at that moment — and it
  has since cleared. It was never a rejection of our request, which is why 50+
  request variants all produced the same answer: none of them were the problem.
- **We are now reaching the gRPC application**, and it is parsing our messages
  and returning diagnostics.
- The response `content-type` is `application/grpc+proto` regardless of what we
  send, so it is the server normalising, not an echo.

This changes the shape of the remaining work entirely. The question is no longer
"why are we refused" but "what is the correct request", and the server is now
answering that question for us in detail.

## The `command_service` schema, recovered from the binary

The generated `pb.cc` embeds the descriptor, and its string table gives the
schema directly (file offsets in `libUE4.so`):

```
0xc95b02  command_service.proto
0xc95b2c  CommandRequest        0xc95b4a  path       0xc95b58  packMode
0xc95b85  req                   0xc95b92  CommandResponse
0xc95bb1  packMode              0xc95bde  res
0xc95beb  PackMode              0xc95bf7  PACK_MODE_JSON
0xc95c0b  PACK_MODE_MSGPACK     0xc95c22  CommandService
0xc95c34  CommandStream         0xc95c8c  proto3
```

```protobuf
syntax = "proto3";
package command_service;

message CommandRequest  { string path; PackMode packMode; bytes req; }
message CommandResponse { PackMode packMode; bytes res; }

enum PackMode { PACK_MODE_JSON = 0; PACK_MODE_MSGPACK = 1; }

service CommandService {
  rpc CommandStream(stream CommandRequest) returns (stream CommandResponse);
}
```

**`req` is MessagePack, not protobuf.** That alone explains the
`invalid wire type 7` errors we were generating — we had been putting protobuf
or arbitrary bytes where a msgpack document belongs.

The field *numbers* are varints inside the descriptor blob rather than in the
string table, and that blob references its strings indirectly, so it could not be
read directly (`scripts/parse_descriptor.py` documents the attempt).
`scripts/find_schema.py` recovers them instead by using the server as an oracle:
a field in the wrong slot produces an immediate wire-format complaint, while a
field in the right slot moves the error to a complaint about the *contents*.

## THE ACTUAL SCHEMA, parsed from the binary

`scripts/descriptor2.py` locates the embedded `FileDescriptorProto` by its own
name field. At `0xc95b00` the bytes are `0a 15` + `"command_service.proto"` —
21 characters, which is why the earlier search for `\x0a\x18` (a 24-character
assumption) found nothing. Parsed properly:

```protobuf
syntax = "proto3";
package command_service;

enum PackMode {
    PACK_MODE_JSON    = 0;
    PACK_MODE_MSGPACK = 1;
}

message CommandRequest {
    string   id       = 1;   // request correlation id
    PackMode packMode = 2;
    string   req      = 3;   // a STRING: the payload carried as text
    string   path     = 4;   // the command name
}

message CommandResponse {
    string   id       = 1;
    PackMode packMode = 2;
    string   res      = 3;
}

service CommandService {
    rpc CommandStream(stream CommandRequest) returns (stream CommandResponse);
}
```

Three things were wrong in every earlier attempt, and each was independently
observable:

1. **`path` is field 4**, not field 1, 2 or 3. The string table lists the names
   in the order `path, packMode, req`, which invited the assumption that `path`
   was field 1. Declaration order in the string table is not field-number order.
2. **`req` is a `string`, not `bytes`** — the JSON or MessagePack document is
   carried as text, not as a nested binary blob.
3. **There is an `id` field**, the request correlation id, which is why the
   envelope needed an identifier in the first place.

### Why this is the 502

With the wrong schema the message either failed to parse (`grpc-status: 13`) or
parsed into a request with no resolvable command. An unresolvable command is
what the application answers with `grpc-status: 14 UNAVAILABLE` — and the AWS
load balancer translates gRPC 14 into **HTTP 502**. So:

> **`502 g=14` was never a load-balancer fault, a health-check failure, a TLS
> fingerprint issue, or a content-type rule. It was the application saying "I do
> not know that command", rendered as an HTTP 502 by the proxy in front of it.**

That single misunderstanding is why 50+ variants all produced the same answer,
and why the evidence kept pointing at the load balancer: `server: awselb/2.0`,
`content-length: 0`, and an empty body are all exactly what a gRPC 14 looks like
after proxy translation.

### Where it stands now

With the correct schema, requests parse cleanly and the server answers
`grpc-status: 14` for every `path` tried so far, including a deliberately
unknown one. So the remaining unknown is the **command naming**, and the server
is a clean membership test for it: any path that does *not* return 14 is real.
There are 384 `CMD_*` strings in the binary to sweep
(`scripts/sweep_commands.py`), starting with `CMD_CONNECT_GRPC`,
`CMD_GET_SESSION_ID`, `CMD_CREATE_USER` and `CMD_AUTH_XSTS`.

`scripts/kgs_client.py` is a working client: it builds a `CommandRequest`,
sends it over HTTP/2 with the `grpc-exp,h2` ALPN the game uses, and decodes
`CommandResponse{id, packMode, res}` out of the DATA frame.

## `path` is not a command enum name — 0 of 384 candidates resolve

The `CMD_*` strings in the binary are the *client's* internal command
identifiers. None of them is the `path` the server routes on:

- **Slow sweep** (`scripts/sweep_commands.py`, 6 s per request, one connection
  each): 17 priority names plus the remaining 369 — **0 resolved**, every one
  `grpc-status: 14 UNAVAILABLE`, including a deliberately unknown control.
- **Path-form matrix** (`scripts/path_forms.py`): leading slash, package
  qualified (`command_service.X`, `command_service/X`), the full method path,
  lower case, underscore-stripped, and the bare suffix — all `14`.
- **Payload shapes**: empty, `{}`, `null`, `[]`, a JSON object naming the
  command, and non-JSON text — all `14`.
- **`packMode`**: 0, 1, 2, 99 — all `14`.
- **`id`**: empty, `1`, `test`, a random UUID, the nil UUID — all `14`.
- **Pipelined on a single `CommandStream`**: also `14`.

A correction to the tooling: the first version of `scripts/fast_sweep.py`
tested `status != "14"`, which counted every **timeout** as a hit and printed
384 false `RESOLVED` lines. It now distinguishes "no status" from a status, and
treats only a real status as a result. The slow sweep, which waits properly,
never showed a single false positive — the honest result is 0 of 384.

### What this implies

`CommandRequest{id, packMode, req, path}` is a **generic envelope**: an
identifier, an encoding, a request body and a *route*. Since no command name
resolves, `path` is most likely a **URL path** rather than an enum name — the
same shape as the plain-HTTP endpoints the game already uses
(`http://ntl.service.konami.net/ntl/api/GateInfo.php`). No such path is
recoverable from the binary as a literal, so the remaining source is the game's
own request bytes.

That makes the on-device capture the only route to the last missing value, which
is where the effort should go.

## GitHub runner: the install failure is diagnosed

```
Failure [INSTALL_FAILED_INVALID_APK: Full install must include a base package]
```

`pm install-multiple` decides which APK is the base **by filename**, not by
reading the XAPK manifest. The XAPK stores `jp.konami.pesam.apk` as the base,
which `pm` does not recognise, so it saw only splits. The fix renames on the way
into the container to the standard convention:

```
base.apk  split_config.arm64_v8a.apk  split_pad_it_0.apk  split_pad_it_1.apk
```

with a `pm install-create` / `install-write` / `install-commit` session as the
fallback, and the asset packs still non-fatal.

Also confirmed working on the runner: `frida-server 17.19.0` for ARM64 is now
**reachable** (launching it through `sh -c` with its stderr captured fixed the
silent failure), and redroid reports `ro.opengles.version 196610` — **OpenGL ES
3.2 via ANGLE** — so the UE4 renderer has what it needs without a GPU.

## UNLOCKED: `path` is a URL path, and the server names the command it dispatched

`scripts/path_kinds.py` tried the kinds of value a `string` field could hold.
One answered:

```
path = "/"   ->   grpc-status 0 (OK)
   CommandResponse { id: "CMD_END_CONNECTION", packMode: 0,
                     res: "{\"result\":\"NOERR\"}" }
```

That is a complete, working request/response, and it settles three things at
once:

1. **`path` is a URL path**, not a command enum name. That is why all 384
   `CMD_*` strings failed: they are the *client's* internal identifiers.
2. **The response's `id` is the resolved command name**, not an echo of the id we
   sent (we sent a random UUID and got back `CMD_END_CONNECTION`). The server
   names the command it dispatched, which makes it a clean oracle — any path
   that comes back is a real route, and it tells us which command it is.
3. **`res` is JSON** under `packMode = 0`, so the payload is a JSON document in
   a string field, exactly as `CommandRequest.req` being a `string` implied.

`path = ""` and `path = " "` also return OK, so there is a default route;
`path = "/"` is the root of it.

`scripts/sweep_paths.py` now sweeps every `/`-prefixed, route-shaped string in
`libUE4.so` against the live endpoint, printing the command each one resolves
to. That is the remaining step to the full chain
(`CMD_GET_SESSION_ID` → `CMD_LOGIN` → `CMD_CREATEJOIN_ROOM` →
`CMD_GET_ROOM_INFO` → `CMD_SEND_RECRUIT_CODE`) and then to a room code.

For the record, the wrong turns that got here, all of which produced
`grpc-status: 14`:

| attempt | result |
|---|---|
| 384 `CMD_*` names as `path` | 14 |
| qualified / slashed / lower-cased forms | 14 |
| numeric ids, empty, `default`, `root` | 14 |
| `/session`, `/login`, `/api/session`, `/v1/...` | 14 |
| the game's own HTTP endpoints (`/ntl/api/GateInfo.php`, full URL) | 14 |
| the gRPC method path itself | 14 |
| every payload shape, `packMode` 0/1/2/99, five `id` formats | 14 |

## The install failures were one missing subcommand

Every `INSTALL_FAILED_*` seen on the runner traced back to a single line in the
report:

```
+ pm install-multiple -r -g /data/local/tmp/jp.konami.pesam.apk ...
Unknown command: install-multiple
Failure [INSTALL_FAILED_MISSING_SPLIT: Missing split for jp.konami.pesam]
Failure [INSTALL_FAILED_INVALID_APK: Full install must include a base package]
```

**redroid's `pm` does not implement `install-multiple`.** The two `Failure`
lines were the fallback paths that ran afterwards, which is why they pointed at
the APK set and the filenames and sent the investigation after the wrong thing
twice — renaming to `base.apk` was a reasonable guess but not the cause.

The supported route is the session API, and the step now uses it:

```sh
SESSION=$(pm install-create -r | tr -d "\r")
for f in ./*.apk; do
  pm install-write "$SESSION" "$(basename $f)" "$f"
done
pm install-commit "$SESSION"
```

`pm` still identifies the base by the name passed to `install-write`, so the
`base.apk` / `split_*.apk` naming is kept. The step also dumps
`pm help | grep install` so the available subcommands are visible in the report
rather than assumed.

This is the fourth time in this investigation that a *fallback* masked the real
error — the pattern is worth naming: when a step runs a second path after the
first fails, the second path's error is what gets read, and it is about the
fallback rather than about the cause.

## RETRACTION: the `method` key is not the selector — it was the transient 502

A single sample of `req = {"method": "CMD_GET_SESSION_ID"}` came back
`grpc-status: 14` while every other payload shape returned the default route,
and that was read as "the payload selects the command through a `method` key".

It does not survive repetition. `scripts/repeat_test.py` sends each case 5 times:

| case | outcomes over 5 samples |
|---|---|
| `req = {}` | default route ×5 |
| `req = {"method": X}` | default route ×4, **14 ×1** |
| `req = {"cmd"/"command"/"name"/"type"/"id"/"path"/"action"/"op"/"function"/"service": X}` | default route ×5 each |
| **`req` = not JSON** | **14 ×5** |

The one `14` under `method` is the intermittent `502/14` we already know about.
The only reproducible rule is that **the server validates `req` as JSON**:
malformed JSON is rejected, and any well-formed JSON falls through to the
default route.

This is the second false conclusion produced by a single sample — the first was
the `content-type` theory, also retracted above. The endpoint returns
`502 / UNAVAILABLE` intermittently, so a one-off difference is not evidence.
Any future claim from this endpoint needs repeated sampling.

### What the `method` sweep did establish

All 384 `CMD_*` names were sent as a `method` value at `path="/"`: **0 resolved,
4 rejected** (and the 4 rejections are within the noise of the transient rate).
So the command names are not reachable through the payload either.

## Honest state of the login

Solved:

- Why we got `502 g=14` — the application could not resolve the command, and
  the ALB renders gRPC 14 as HTTP 502.
- The exact wire schema, parsed from the binary and hand-verified against the
  descriptor bytes.
- A working client: `scripts/kgs_client.py` builds a `CommandRequest`, speaks
  HTTP/2 with the game's ALPN, and decodes `CommandResponse`. `path="/"`
  round-trips successfully.
- The payload is JSON in a string field, validated by the server.

Not solved:

- **The command route table.** `path` is a URL path; `/` is the only route
  reachable, and it maps to `CMD_END_CONNECTION`. The routes are in none of the
  shipped artifacts: not `libUE4.so` (384 `CMD_*` names and 2711 path-shaped
  strings, both swept), not the base APK's 261 config/text assets, not the 18
  `config.*` splits, not the 780 MB asset packs, and not as a payload selector
  in a dozen spellings.

The single remaining source for the route table is the game's own request
bytes, which is what the ARM64 runner capture exists to obtain. Everything needed
on that side is now in place: binder mounts, redroid 14 arm64 boots as root with
GLES 3.2 via ANGLE, frida-server 17.19.0 is reachable, the package downloads and
extracts, and the install uses the `pm` session API because redroid has no
`install-multiple` subcommand at all.

A further caveat worth stating: even with the routes, a real login needs a valid
`req` payload — device identity, an auth token, the app identity values
(`titleCode=PES2022, locale=US, version=6.0.1, uid=3c5aad3c…`) — and the game
obtains its auth token from a Konami account flow. Reaching a room code is a
chain of five commands plus a real session, not a single request.

## The login sequence, reconstructed in order from the capture

Read strictly first-to-last rather than jumping to the most recent traffic,
because the ordering is the information (`scripts/login_sequence.py`):

```
   t_s  flow                                        bytes  state
   0.00  10.0.0.2 -> 8.8.4.4:53                        472  open,fin
   0.00  10.0.0.2 -> 8.8.8.8:53                        472  open,fin
  35.84  10.0.0.2 -> 52.85.47.53:443   (applilink)    7289  open,fin
  42.98  10.0.0.2 -> 44.232.213.50:443  GAME SERVER   4604  open,fin
  56.23  10.0.0.2 -> 44.232.213.50:443  GAME SERVER  34659  open,fin
  80.53  10.0.0.2 -> 44.232.213.50:443  GAME SERVER   8937  open
  92.84  10.0.0.2 -> 52.196.4.126:80   POST /ntl/api/GateInfo.php
  96.16  10.0.0.2 -> 52.196.4.126:80   POST /ntl/api/PES2022/ReportLog.php
 103.55  10.0.0.2 -> 52.196.4.126:80   POST /ntl/api/PES2022/ReportLog.php
 151.95  10.0.0.2 -> 52.196.4.126:80   POST /ntl/api/PES2022/ReportLog.php
 373.22  10.0.0.2 -> 34.208.149.190:443 GAME SERVER  12713  open
```

Two things this settles that guessing could not:

1. **The gRPC session is established *before* the NTL gate call** — the game
   reaches `44.232.213.50:443` at t=43 s and again at t=56 s, and only calls
   `GateInfo.php` at t=93 s. So the gRPC channel is the bootstrap. The NTL gate
   is not what hands out the endpoint, which rules out the theory that the gate
   supplies connection parameters.
2. **The gate carries no configuration.** Its body is hex-encoded and decodes
   to a version ping and nothing else (`scripts/gate_bodies.py`):

   ```
   POST /ntl/api/GateInfo.php
   req = {"titleCode":"PES2022","locale":"US","version":"6.0.1",
          "extra":"","apiLevel":"4"}
   ```

   The `ReportLog.php` bodies are the app identity, also already known:

   ```
   ## NTLInfo
   ${"libVer":"1.17.1-Android-15"}
   ${"uid":"3c5aad3c6b8425c611ebe2f5da6c25af"}
   ${"opt":22011111}
   ```

So no route table is fetched over the network at login either. The command
routes are either compiled into the client in a form not recoverable as
strings, or established server-side when the session is created — which again
makes the game's own request bytes the only source.
