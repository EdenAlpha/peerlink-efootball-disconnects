# KGS login — headless eFootball: from captures to the real protocol

Everything learned about Konami's eFootball (`pes22` / `jp.konami.pesam`)
server protocol, and the tools that learned it. Two lines of work:

1. **`captures/match-2026-09-26/`** (repo root) — why two phones freeze mid
   match and get kicked to the lobby.
2. **`kgs-login/`** (this directory) — how to log in to Konami KGS without the
   app, by running the game's own code. This directory.

Read `findings/FINDINGS_KGS_LOGIN.md` first — it is the current, tested
verdict. The `FINDINGS_M2*.md` notes are the milestones in order.

---

## The story, beginning to end

### M22 — a working request, for one endpoint
`ntl.service.konami.net/ntl/api/GateInfo.php` answered `STATUS: 200` to a
byte-exact copy of the game's own bootstrap request. First live Konami
response. (`findings/FINDINGS_M22_live_login.md`)

### M23 — the pointer tables are invisible in the file
**The finding that explains every dead end.** This binary uses Android packed
relocations (`SHT_ANDROID_RELA`, APS2). Consequence: every pointer table —
vtables, dispatch tables, handler registries — is **zero-filled in the file**.
Static scans for who points at a function or string return nothing, not
because the reference is absent but because it only exists after the loader
unpacks the relocations. Call-graph ascent, raw pointer scans, ADRP+ADD
scans, branch-target scans: all empty, all misleading.
(`findings/FINDINGS_M23_dispatch_tables.md`)

### M24 — the HTTP stack
The sub-request object, its vtable, the composer, the senders, the pump.
GateInfo runs end to end **through the game's own code**.
(`findings/FINDINGS_M24_http_stack.md`)

### M25 — the gate endpoint
`https://pes22-game.cs.konami.net/pes22/gate/gate_<msgid>.php`. Real command
names answer 500 (the PHP runs and fatals); invented names answer 404. The
path is right — and the IP theory is disproven here by testing three
different networks (AWS, Cloudflare WARP, a phone on mobile data) and getting
the byte-identical blank 500. (`findings/FINDINGS_M25_gate_endpoint.md`)

### M26 — LIEF unpacks the relocations, the vtables come alive
`pip install lief` decodes APS2: **1,335,097 relocations**, 1,297,240 of them
`R_AARCH64_RELATIVE`. The vtable at `0x97d4448` resolves, and it independently
confirms the two functions we had been calling by hand (`0x767ec60` bind,
`0x767edbc` serialise) really are the game's own methods.
(`findings/FINDINGS_M26_vtables_zero.md`)

With the tables alive, several long-standing harness bugs surfaced and were
fixed (`scripts/uc_loader.py`, `scripts/uc_loader2.py`):
* `STUB_SIZE` raised 64 KB -> 4 MB (15,345 PLT imports did not fit)
* `call()` zeroed `x6`/`x7` right after setting them — any call needing a 7th
  or 8th argument silently lost it
* `symcalloc`/`symfree` (curl's private allocator) unimplemented — that is why
  `curl_easy_init` returned NULL
* `getentropy`/`syscall(278)` unimplemented — curl's RNG stayed empty and TLS
  aborted with "Insufficient randomness"
* `fopen`/`fread`/`fgets`/`open`/`read`/`stat`/`opendir` — libcurl's entropy
  and config-file reads
* the 11,829 `.init_array` constructors were never run (11,824 now run clean)

### The verdict — the PHP gate is dead by design
The binary's own embedded config says it:

```json
{"invitation_task": {"enable": true, "use_http_command": false},
 "connect_grpc_task": {"disable": true}}
```

**`use_http_command: false` — the game is configured not to use HTTP for
commands.** Every blank 500 over `gate_CMD_*.php` was a dead legacy route. The
app never POSTs there.

### The real protocol — `command_service.proto`
Decoded from the protobuf FileDescriptorProto embedded at `0xc95afa`
(`scripts/decode_proto.py`):

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

Full method: **`/command_service.CommandService/CommandStream`** — a
bidirectional stream over HTTP/2, on `pes22-game.cs.konami.net`. The URL we
chased all along is the `path` **field**; the msgid is the `id` field; the
MessagePack body we built is the `req` field. Everything derived was correct —
it just was never an HTTP POST.

### The endpoint is live and speaks the protocol
| what is sent | what comes back |
|---|---|
| stream opened, no message | `grpc-status: 0 OK` |
| 1 byte of garbage | `grpc-status: 13` *"Error deserializing request: index out of range: 1 + 1 > 1"* |
| any valid `CommandRequest` | `grpc-status: 14 UNAVAILABLE` |

The garbage case is the proof: the server **parses the protobuf and reports a
decode error**. Only a real gRPC server does that. Wrong method names get
`12 UNIMPLEMENTED` / *"The server does not implement the method"*. Backend is
`server: awselb/2.0` (AWS ALB with gRPC routing).

### Where it stands
`CommandStream` accepts the connection and parses the messages, but the
gateway answers `14` to anything with a body. The `14` arrives in **headers at
0 ms** (vs ~170 ms to connect) and is deterministic 8/8 — a gateway routing
decision, not a backend round trip.

Ruled out on the gRPC path, all giving identical `14`: 24 `path` forms, 8
`msgid`s, 6 `req` encodings (raw MessagePack, hex, base64, JSON, `req=<hex>`,
empty), field-presence combinations, `authorization` / `grpc-timeout` /
`x-konami-session` metadata, 6 `:authority` variants, and the **client
certificate** (leaf and full chain).

Strongest remaining lead: `CMD_GET_SERVER_ENV` is a config fetch whose answer
supplies `Def_Online_gRPC_server_address` / `_port` / `_path` — the values are
not in the binary or the data packs; they arrive at runtime. Without them the
gateway has no upstream to route to, which matches `14` as a routing failure
rather than an auth rejection.

---

## Layout

```
kgs-login/
  README.md            this file
  findings/            FINDINGS_KGS_LOGIN.md  (current verdict) + M22..M26
  scripts/             every tool written along the way (233)
  harness/             the Unicorn ARM64 emulator harness
     scripts/          uc_loader.py / uc_loader2.py  (ELF loader + libc stubs)
     peerlink/         online_client, game_http, netsplice, kgs, rooms, ...
  evidence/            bodies, logs, outputs, the Ghidra headless script
```

### Notable tools
| tool | what it does |
|---|---|
| `scripts/decode_proto.py` | minimal protobuf wire decoder; pulled `command_service.proto` out of the binary |
| `scripts/rev_reloc.py` | **reverse relocation map** — "which slots point at this VA". Inverts LIEF's 1.33M `R_AARCH64_RELATIVE` addends; this is what cracked the invisible pointer tables |
| `scripts/rebuild_relocs_lief.py` | rebuilds `packed_relocs.npz` + `plt_map.json` from the ELF via LIEF (APS2) |
| `scripts/grpc_probe.py` / `grpc_shapes.py` / `grpc_where.py` | raw gRPC over HTTP/2; the live results above |
| `scripts/capture_hosts.py` | TLS ClientHello SNI + DNS extraction from the phone captures — ground truth for which hosts the app talks to |
| `scripts/send_real_body.py` | drives the game's own serializer + composer + POST sender under the emulator |
| `evidence/ghidra/Deco.java` | Ghidra headless decompiler for the composer + gate builder |

### Tools used, and what they were for
* **LIEF** — decoded the Android packed relocations (APS2) that a plain
  `.rela.dyn` walk cannot see. That is what fixed the vtables.
* **Unicorn** — runs the game's own ARM64 code headless (no GPU, no device).
* **Ghidra 12.1.4** — headless decompilation (already in `efootball-apk/`).
* **curl_cffi** — TLS fingerprint impersonation; used to **disprove** the JA3
  theory (13 real browser fingerprints, all identical).
* **h2 / hpack** — the raw HTTP/2 gRPC client.

### Ruled out, with the evidence that killed it
Full list in `findings/FINDINGS_KGS_LOGIN.md`. Short version: the IP address
(three networks, same result), TLS fingerprinting (13 browser fingerprints),
the client certificate (leaf/chain/none, on both PHP and gRPC), the request
body format (MessagePack, JSON, hex, base64, 15 field names, 5 content types),
query parameters and headers (30+ variants, 9 Host variants), a hidden login
host (the app's own TLS SNI says otherwise), gRPC-as-`Def_Online_gRPC_*`-less
guesswork, `ChangeServer.bin` (a store-receipt path, not network config),
and `jp.applilink.sdk` (an ad SDK).

### Not redistributed here on purpose
`pristine_libUE4.so` (160 MB, Konami property), `funcs_eh.txt`, `packed_relocs.npz`
(374 MB), `plt_map.json`, `ghidra_vtables.txt`, `dynsym_funcs.txt`, the Ghidra
project, and **Konami's client TLS private key** (`bin_privkey.pem` /
`client_key.pem` / `chain_key.pem`) — extracted during the mTLS work but not
published. The extracted **certificates** (`ca_root.pem`, `client_cert.pem`)
are included; the private keys are not.

---

## Capture thread

The other half of this repo — `captures/match-2026-09-26/`, `VERDICT.md`,
`DISCONNECT_CENSUS.md`, `CAPTURE_AUTOPSY.md`, `WORKING_EVIDENCE.md` — is the
P2P disconnect investigation. Two phones, three stalls, `0pps cliff`, DTLS to
`turn.konami.com` going quiet 0.7-3.4 s before each cliff. That work is
unaffected by anything in this directory.
