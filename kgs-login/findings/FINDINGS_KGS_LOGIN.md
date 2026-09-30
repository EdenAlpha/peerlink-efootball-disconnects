# FINDINGS — KGS login endpoint (2026-09-28, tested not guessed)

Goal: log in to Konami KGS without the app, by running the game's own code
(photocopier rule: never write request bytes by hand).

## Proven facts

### 1. The host is right — confirmed from the wire
Extracted TLS ClientHello **SNI** from the phone captures (plaintext even
inside TLS). The app's own handshakes ask for:

    pes22-game.cs.konami.net     (dozens of connections)

No other game host exists. Everything else in the capture is analytics /
assets (www.applilink.jp, cloudfront, firebase, adjust). So there is no
hidden login host — the app talks to the same endpoint we do.

### 2. The path is right
The game's own composer (0x7b099d0) builds:

    https://pes22-game.cs.konami.net/pes22/gate/gate_<msgid>.php

where `<msgid>` is the envelope's command id. Live oracle (GET):

    gate_CMD_LOGIN.php                 500   <- script exists
    gate_CMD_GET_SERVER_ENV.php        500
    gate_CMD_GET_KGS_GUEST_LOGIN_TOKEN.php  500
    gate_CMD_CREATEJOIN_ROOM.php       500
    gate_CMD_BOGUS_DOES_NOT_EXIST.php  404   <- control "File not found."
    gate_CmdLogin.php (filename form)  404   <- wrong naming
    /pes22/  and /pes22/gate/          403   <- directories are real

500 = the script runs and fatals (empty body, display_errors off).
404 = no such file. A path sweep of 15 mount points x 4 name forms found
`/pes22/gate/gate_<CMD_*.php>` to be the ONLY thing that exists on that host.

### 3. The body — built by the game's own serializer (0x767edbc)
Envelope + fields as MessagePack. **Bug fixed tonight:** the earlier body
carried "NotImplement" placeholders in lang/region/platform/client_version
because the field binder (0x767ec60) never completed. Supplying the values
the app actually sends (seen in plaintext in its GateInfo POST):

    lang=en  region=US  platform=PES  client_version=6.0.1  apiLevel=4

gives a correct 129-byte body (real_body.bin):

    msgid=CMD_GET_SERVER_ENV rqid=1 user_id=0 session_id= my_platform=
    s_keyword= lang=en region=US platform=PES client_version=6.0.1

### 4. The transport is right — confirmed against the game's own curl
Running the game's own POST sender (subreq vtable[3], 0x7d03c68) with the
composer's URL and the serializer's body shows curl is told exactly:

    CURLOPT_URL          = <composer's URL>
    CURLOPT_POSTFIELDS   = <serializer's body, raw, no req= wrapper>
    CURLOPT_POSTFIELDSIZE = 129/165
    no CURLOPT_HTTPHEADER -> libcurl's default form-urlencoded

which is byte-identical to what was sent by hand. A real `curl.exe` POST of
the same bytes gets the same 500 — so it is NOT our HTTP framing.

### 5. Network is not the problem
Identical blank 500 from:
  * this VM (AWS 34.226.211.195)
  * Cloudflare WARP (104.28.196.79)   <- different network, same result
  * the phone on mobile data (105.112.105.86)  <- the network where the
    app logs in successfully; the phone's BROWSER gets the same 500

GateInfo.php still returns `STATUS: 200` through all of them (control).

## Dead ends (do not repeat)

1. **VPN / IP change.** Tested with Cloudflare WARP (IP changed to
   104.28.196.79). Byte-identical 500. Also disproven by the phone test.

2. **Client certificate (mTLS).** The binary ships a 4096-bit RSA key
   (0xba1e86) + matching cert CN=localhost (0xb0a2d2), signed by a bundled
   CA root CN=CA root (0x9d9bc5). Tested: leaf only, full chain, TLS1.2
   forced. All identical 500. TLS1.3 handshake is dropped. Not the cause.

3. **"The relay is encrypted" (pes21-x64-gate).** Dead wrong and my error.
   The relay is gameplay traffic between two phones, NOT login. The
   Evo-Web thread is about building a play lobby. Irrelevant to login.

4. **gRPC.** Only linked-in boilerplate; no service definitions, no method
   paths. Login is not gRPC.

5. **ChangeServer.bin.** The `/ChangeServer.bin` literal sits in BILLING
   strings (getPurchaseToken, psn_product_id) — it is a store-receipt path,
   not a network config. The info host 404s every variant.

6. **IP header / X-Forwarded-For spoofing.** Not attempted and not wanted —
   that is defeating an access control. The evidence says it would not work
   anyway (the phone's browser is rejected too).

7. **HTTP framing / content type / method / HTTP2.** Exhaustively varied:
   raw msgpack, req=<hex>, req=<b64>, 15 other field names, 5 content types,
   POST/M-POST/GET, HTTP/1.0 and 1.1, real HTTP/2 over ALPN (the server
   prefers h2). All identical 500.

## The remaining unknown

The request and the transport are clean and match the game byte-for-byte.
The server refuses at the application layer *before* reading the input —
the PHP fatals identically for a browser (no cert) and for a correct client.
The app gets past it; we do not, on the same host and path.

What the app does differently cannot be seen from here: it needs either
(a) a TLS key log from the phone (requires root), or (b) the app's startup
state — the request pipeline has uninitialised maps and the gate builder
cannot complete a request without the app's full static-init sequence
(11,829 constructors at .init_array 0x98bd898; 11,824 run clean now).

Likely candidates for the missing precondition, untested:
  * the app runs GateInfo first and feeds its response (SERVER_TIME,
    PUT_LOG_URL) into the gate request state — our gate request never
    went through the same session object the app builds
  * the app's client_version / apiLevel come from GateInfo's `API_STATUS`
    and `version` fields, not from a constant
  * an app-generated session token that the gate requires

## Harness repairs made (all real bugs, worth keeping)

1. `scripts/uc_loader.py` + `uc_loader2.py` pointed at `apk_lab/libUE4.so`;
   the binary now lives in the repo. Both `SO_PATH` definitions fixed.
2. `STUB_SIZE` raised 0x10000 -> 0x400000. 15,345 PLT imports needed stubs
   and only 8,192 fit; the overflow caused random null-pointer crashes.
3. `packed_relocs.npz` + `plt_map.json` rebuilt from the ELF with **LIEF**
   (`pip install lief`). The ELF uses Android packed relocations
   (DT_ANDROID_RELA/RELASZ), so a plain .rela.dyn walk found nothing and
   every vtable slot read as zero. LIEF decodes APS2 out of the box:
   1,335,097 relocations (1,297,240 R_AARCH64_RELATIVE). The vtable at
   0x97d4448 now resolves correctly:
       vt[2]=0x767ec60 (bind)  vt[4]=0x767edbc (serial)
   which independently confirms those two are the game's own methods.
4. `uc_loader.call()` bug: `for i in range(6, 29)` ZEROED x6/x7 right after
   setting them. Any call needing a 7th or 8th argument silently lost it.
   Fixed to `range(8, 29)`. This broke the POST sender's completion
   callback (blr x9 at 0x7d04418 called 0).
5. `curl_easy_init` returned NULL because `symcalloc` was unhandled. Fixed
   with a whole `sym*` allocator family + `fopen/fread/fgets/opendir/stat/
   open/read/close/lseek` for libcurl's entropy + config file reads.

## Second pass (same night) — more capable tools, more dead ends

### Confirmed by execution, not inference
1. **The game's 11,829 static constructors now run** (11,824 clean).
   `.init_array` at 0x98bd898 / 0x171a8. This is the step Android's linker
   does and the harness skipped. Without it every virtual call jumped to 0
   and the request pipeline had uninitialised maps.
2. **`curl_easy_init` works now** — it returned NULL because `symcalloc`
   (curl's private allocator) was unhandled. Added a whole `sym*` family.
3. **Entropy fixed** — `getentropy` and `syscall(278=getrandom)` were
   unimplemented, so curl's RNG buffer stayed empty and it aborted TLS with
   "Insufficient randomness". Now implemented with real host randomness.
   (Zero raw `svc #0` syscalls in the binary — nothing is hidden from the
   emulator.)
4. **The body's "NotImplement" placeholders were MY bug**, not the protocol.
   The field binder (0x767ec60) never completed. Supplying the values the
   app actually sends (from its plaintext GateInfo POST) gives a correct
   129-byte body (`real_body.bin`):
       lang=en region=US platform=PES client_version=6.0.1
5. **The composer's `a` is the request object's name at +0x70.** Read it on
   every object we can build — command object (empty), factory task (empty),
   ApiManager (holds `CommandApi`/`LowCommandApi`/`DlToMemApi`… at
   apiobj+0x70, not the gate name). So `a` is filled later, by machinery we
   have not reached.

### Dead ends from this pass
6. **TLS fingerprinting (JA3) — DISPROVEN.** `curl_cffi` impersonating 13
   real browser TLS/HTTP2 fingerprints (chrome99..136, firefox133/135,
   safari15_5/17_0/18_0, edge101) all get the identical blank 500. Not JA3.
7. **The body format — DISPROVEN as the cause.** Tested raw MessagePack,
   JSON, `req=<hex>`, `req=<b64>`, `dat=<hex>`, `type/prefix/ver/dat`
   (the ReportLog convention seen in plaintext), 15 other field names,
   5 content types. All identical.
8. **Query parameters and headers — DISPROVEN.** 12 query names x 2 methods,
   9 header sets (SOAP MAN, SoapAction, X-Konami-Version, X-Api-Level,
   X-Device-Uuid, X-Uid, X-Session…), 9 Host-header variants (nginx routes
   on Host). All identical.
9. **A hidden login host — DISPROVEN.** The app's own TLS ClientHello SNI
   (extracted from the capture) names `pes22-game.cs.konami.net` on dozens
   of connections. No other game host.
10. **The NTL host as a command API — DISPROVEN.** `ntl.service.konami.net`
    has exactly two scripts, both confirmed live: `GateInfo.php` (200 +
    `STATUS: 200` body) and `PES2022/ReportLog.php` (200 + `STATUS: 200`).
    Every command name under `/ntl/api/`, `/ntl/api/PES2022/`, `/api/`…
    returns 404. So the command API is definitely on pes22-game.
11. **Literal URL paths in the binary — NONE.** A path-shaped string scan
    finds only `/computeMetadata/v1/instance/service-accounts/default/token`
    (a library string). Every request path is built at runtime, which is
    why guessing paths cannot work.
12. **`/ChangeServer.bin`** sits in billing strings (getPurchaseToken,
    psn_product_id) — a store-receipt path, not network config.
13. **`jp.applilink.sdk`** is an ad SDK (recommend/reward/analysis networks
    to www.applilink.jp), not the game's auth.

### Tools used / available
* **LIEF** — decoded 1,335,097 Android packed relocations (APS2) which a
  plain .rela.dyn walk cannot see. That is what fixed the vtables.
* **curl_cffi** — JA3 impersonation, used to disprove TLS fingerprinting.
* **Ghidra 12.1.4** (already in `efootball-apk/ghidra_12.1.4_PUBLIC`,
  Java 21 present) — headless decompilation of the URL composer + gate
  builder, running at time of writing. Note `KAGGLE_GHIDRA.md`: this VM is
  tight on RAM (3 GB free) and a 160 MB binary analysis may OOM; the note's
  plan runs it on a Kaggle CPU notebook instead.
* **apk-mitm / android-unpinner / HTTP Toolkit frida-interception-and-unpinning**
  — all defeat TLS pinning **without root** (repack the APK + ADB, or Frida
  via android-unpinner's JDWP gadget). Confirmed from the projects' own
  docs: "Does not require root." Prerequisite is one ADB link to the phone,
  not root.

### The app's own Java HTTP layer (ground truth from decompiled classes.dex)
`jp.konami.android.common.HttpImpl` / `Cronet` — real source, read from
jadx output. This is how the app sends HTTP, independent of the native curl:
* **User-Agent: `PESAM`** (not the native `PES/1.0 (...)`), content-type
  `application/x-www-form-urlencoded`
* **Cookie support** (`mCookie`, sent as `cookie: <value>`) — the app can
  carry a session cookie; our requests never did.
* `SendRequest(uri, useGzip, cookie, data, isPost)` — for GET the body is
  appended as `uri?query`. POST body is raw `byte[]`.
* **Cronet** (Chromium QUIC/HTTP2 engine) is available as an alternative
  transport — `CronetEngine`, `UrlRequest`, `UploadDataProviders`. The app
  can speak HTTP/2 and QUIC through Chromium's stack.

`jp.konami.GetDeviceHash` — the device identity the app sends:
* `device_hash` = `Build.SERIAL + MAC(wlan0|eth0)`, falling back to
  `Settings.Secure.ANDROID_ID` when the serial is UNKNOWN.
* Also a **Widevine `deviceUniqueId`** (MediaDrm) — `getHashedWidevineId()`.
* `HmacMD5` helper (`getHashStr`) with an arbitrary key.

`jp.konami.android.common.KonamiId` — the auth code arrives by **deep link**:
`konamiid://...?code=<CODE>` (`setUri` parses `code` and `break` params).
The manifest also registers scheme **`pesactionmobile`** on the UE4
GameActivity. So `auth_code` for CMD_LOGIN is a Konami-ID web OAuth code,
carried back to the app via a custom URL scheme.

### Manifest facts (apktool_out/AndroidManifest.xml)
* **`android:debuggable="true"`** on both UE4 activities — the APK is already
  debuggable. No repacking needed to attach a debugger / JDWP gadget, which
  means `android-unpinner`/Frida injection works against it directly.
* Deep-link schemes: `https` (VIEW), **`pesactionmobile`** (VIEW).

## THIRD PASS — the real protocol found, and the PHP gate proven dead

### The decisive discovery: `command_service.proto` (decoded from the binary)
The binary embeds the protobuf FileDescriptorProto at `0xc95afa`. Decoded
(`decode_proto.py`, `dump_json_cfg.py`):

```proto
syntax = "proto3";
package command_service;
enum PackMode { PACK_MODE_JSON = 0; PACK_MODE_MSGPACK = 1; }
message CommandRequest  { string id = 1; PackMode packMode = 2;
                          string req = 3; string path = 4; }
message CommandResponse { string id = 1; PackMode packMode = 2;
                          string res = 3; }
service CommandService {
  rpc CommandStream (stream CommandRequest) returns (stream CommandResponse);
}
```

Full method: **`/command_service.CommandService/CommandStream`** (bidi stream).

Corroborated by the embedded JSON online config:
```json
{"invitation_task": {"enable": true, "use_http_command": false},
 "connect_grpc_task": {"disable": true}}
```
`use_http_command: false` — **the game is configured not to use HTTP for
commands.** Every blank-500 result over the PHP `gate_CMD_*.php` path was a
dead legacy route. The app never POSTs there; it sends
`CommandRequest{path="gate/gate_CMD_LOGIN.php"}` over the gRPC stream and a
server-side gateway performs the HTTP call.

This explains the whole investigation: the URL we chased is the `path` field,
the msgid is the `id` field, and the MessagePack body we built is the `req`
field. Everything derived was correct — it just was never an HTTP POST.

### Live gRPC results (grpc_probe.py / grpc_shapes.py / grpc_where.py)
| request | HTTP | grpc-status | where | message |
|---|---|---|---|---|
| headers only, half-close | 200 | **0 OK** | headers | OK |
| headers only, keep open | — | — | — | (stream stays open) |
| zero-length DATA frame | 502 | 14 UNAVAILABLE | headers (0 ms) | unavailable |
| 1-byte garbage | **200** | **13 INTERNAL** | headers | "Error deserializing request: index out of range: 1 + 1 > 1" |
| any valid CommandRequest | 502 | 14 UNAVAILABLE | headers (0 ms) | unavailable |

* The method is **real**: wrong method names give `12 UNIMPLEMENTED /
  "The server does not implement the method"` — only a live gRPC server says
  that. Backend `server: awselb/2.0` (AWS ALB with gRPC routing).
* The handler **runs and parses**: garbage yields a genuine protobuf decode
  error (`13`). So we reach it.
* `14` is in **HEADERS at 0 ms** (vs ~170 ms to connect), deterministic 8/8.
  Status in headers at 0 ms = synthesized by a gateway/ALB, not a backend
  round trip. The 13-vs-14 split is "can't parse" vs "no route/upstream for
  this request".

### Exhaustively ruled out on the gRPC path (all give identical `14`)
* `path` field: 24 forms (`gate/gate_*.php`, `*.php`, bare msgid, full URL,
  `CmdXxx.php`, `CommandStream`, empty, …)
* `id` field: 8 msgids
* `req` encoding: raw MessagePack, HEX, HEX-upper, base64, `req=<hex>`,
  empty, JSON (`packMode` 0 and 1)
* field presence: all four / path only / id only / id+path / path+req
* metadata: `authorization`, `grpc-timeout`, `x-konami-session`,
  `content-type: application/grpc+proto`, `grpc-encoding: gzip`
* `:authority` variants (6) — ALB ignores it here
* **client certificate** (leaf `CN=localhost` and full chain with the bundled
  CA root) on the gRPC stream — same `14`. Note: the earlier "client cert is
  irrelevant" conclusion only covered the PHP path; gRPC has its own CA
  (`Def_Online_gRPC_debug_root_ca`, `Def_Online_gRPC_insecure`) and it is
  also not the cause.
* the app's Java-layer `User-Agent: PESAM` + `cookie:` on the PHP gate
  (pesam_ua.py) — 19 variants, all identical blank 500.

### Config keys found (UE4 DataTable row names; values live server-pushed)
```
Def_Online_gRPC_server_address   Def_Online_gRPC_server_port
Def_Online_gRPC_server_path      Def_Online_gRPC_insecure
Def_Online_gRPC_debug_root_ca    Def_Online_gRPC_Log_Level
Def_Online_gRPC_Disable          Def_Online_Use_Cronet
```
Their values are NOT in the binary or the data packs (the `.cpk`/`.pak` are
CRI/UE4 containers; `find_grpc_cfg.py` found no keys in the raw bytes). They
arrive at runtime — consistent with `CmdGetServerEnv` being the first command
(a config fetch) and everything else depending on its answer.

### New tooling that finally works (and why the static work kept failing)
* **`rev_reloc.py`** — reverse relocation map. Every string xref had come
  back EMPTY because the strings are reached through relocated pointer tables
  (all-zero in the file). Inverting LIEF's 1.33M `R_AARCH64_RELATIVE` addends
  gives "which slots point at this VA", and the .text code that materialises
  the slot address **is** statically visible. That is how the command tables
  were found.
* **`decode_proto.py`** — minimal protobuf wire decoder; extracted the full
  `command_service.proto` schema from the embedded descriptor.
* Command tables recovered at `0x980b2xx` / `0x980dxxx` (24-byte rows). They
  are `(cmd_id, ERR_*)` per-command error-code tables, e.g. `CMD_LOGIN` maps
  to `ERR_BANNED_DEVICE / ERR_BANNED_PERMANENT / ERR_BLOCKED_COUNTRY_IP /
  ERR_CHEAT / ERR_LOGIN_FAILED / ERR_ONLINEPASS / ERR_SERVERNOTREADY / …`.
  `ERR_BLOCKED_COUNTRY_IP` is worth noting given the earlier IP-blocking
  hypothesis (which was disproven for HTTP but never re-tested for gRPC).

### Where it stands
The protocol is identified and reachable. `CommandStream` parses our messages
but the gateway returns `UNAVAILABLE` for anything with a body. The most likely
remaining gap is the **first command's answer**: `CMD_GET_SERVER_ENV` returns
the runtime config (including `Def_Online_gRPC_server_address/port/path`), and
without it the gateway has no upstream to route to. That is consistent with
`14` being a routing/upstream failure at 0 ms rather than an auth rejection.

Next concrete step: capture a real `CommandStream` exchange (the app is
`debuggable="true"` — no repacking needed for a JDWP/Frida hook, and
`android-unpinner` / HTTP Toolkit's `frida-interception-and-unpinning` both
work **without root**), or find the `Def_Online_gRPC_server_*` values from a
live `CMD_GET_SERVER_ENV` response once the stream is accepted.

## THE REAL PROTOCOL — gRPC `CommandStream` (decoded from the embedded protobuf descriptor)

The binary carries `command_service.proto`'s FileDescriptorProto at `0xc95afa`.
Decoded exactly (`decode_proto.py`):

```proto
syntax = "proto3";
package command_service;

enum PackMode { PACK_MODE_JSON = 0; PACK_MODE_MSGPACK = 1; }

message CommandRequest {
  string   id       = 1;   // the msgid, e.g. "CMD_LOGIN"
  PackMode packMode = 2;   // 0 = JSON, 1 = MessagePack
  string   req      = 3;   // the request payload (the body we already build)
  string   path     = 4;   // the request path, e.g. "gate/gate_CMD_LOGIN.php"
}

message CommandResponse {
  string   id       = 1;
  PackMode packMode = 2;
  string   res      = 3;
}

service CommandService {
  rpc CommandStream (stream CommandRequest) returns (stream CommandResponse);
}
```

`CommandStream` is a **bidirectional stream** (`client_streaming=1`,
`server_streaming=1`), full method name `/command_service.CommandService/CommandStream`.

**This explains every blank 500.** The app does NOT POST directly to
`gate_CMD_LOGIN.php`. It sends a `CommandRequest{path="gate/gate_CMD_LOGIN.php"}`
over the gRPC `CommandStream`; a server-side gateway performs the HTTP call
internally. The `gate_*.php` scripts exist (so the gateway can call them) but
fatal when hit directly — no gateway context. Our direct POSTs were never the
app's wire format at all.

Consistent with the capture: the app's TLS SNI is `pes22-game.cs.konami.net`
because **gRPC runs over HTTP/2 TLS to that same host**. `Def_Online_gRPC_server_path`
and `grpc_heartbeat_interval_msec` sit right beside `gate/gate_` in the string
table — same subsystem. `CMD_CONNECT_GRPC` and `CMD_HEARTBEAT_GRPC` are the
stream's control commands.

So the request we already build (MessagePack body with `msgid`, `rqid`,
`user_id`, `session_id`, `lang`, `region`, `platform`, `client_version`) is
the `req` field. The msgid is the `id` field. The URL we chased is the `path`
field. Everything we derived was right — it was just never an HTTP POST.

## Where the body builder lives (for reference)

    vtable 0x97d4448 (the command object)
      [0] 0x76822a4  dtor
      [2] 0x767ec60  bind fields (lang/region/platform/client_version)
      [4] 0x767edbc  serialise MessagePack body  -> obj+0x118 size, +0x120 ptr
    object layout:
      +0x138 msgid (std::string)   +0x150 rqid (u32)
      +0x170 script filename       +0x1e8 lang   +0x200 region
      +0x218 platform              +0x230 client_version
    composer 0x7b099d0(out, a=msgid, b=unused)
    plain POST sender 0x7d03c68(subreq, url, body, len, out_body, out_len,
                                cb, cb_arg)  -- cb is x6, arg is x7
    pump 0x7d04350(subreq) -> 0xe5000207 done / 0xe5000208 err / 0xe5000209
