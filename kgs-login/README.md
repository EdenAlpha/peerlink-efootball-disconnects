# KGS login — running the game's own code instead of reimplementing it

## The problem

eFootball's KGS endpoint (`pes22-game.cs.konami.net`, gRPC) answers every
request we synthesise with **`502 g=14`** — in ~0.3 s, on every one of the
server's own IPs, with the game's real envelope and body. The game itself, on a
real phone, is served normally.

Address, TLS/ALPN, HTTP/2 framing, HPACK encoding, headers, envelope fields,
body and message order have all been varied. Every combination produces the
same refusal. So the remaining difference is **not synthesisable from outside**
— it is something about the client's own code or state.

The rule this directory follows: **never hand-assemble request bytes.** Run the
game's own `libUE4.so` and read what it emits.

## What is established

- The genuine Play package is **eFootball 11.0.1, versionCode 311000101** —
  the build on the user's phone.
- Its `lib/arm64-v8a/libUE4.so` is **byte-identical** (SHA-256
  `2ac4ff17ac8ad713…`) to the binary being reverse engineered. The binary was
  never the problem; an earlier assumption that it was an older build is
  retracted.
- Host, the single gRPC service path
  `/command_service.CommandService/CommandStream`, and the `command_service`
  schema are all confirmed correct.

## How the capture works

`libUE4.so` has gRPC statically linked, and its gRPC configuration is read
through two `Def_` getters. Decoded from the binary:

```
0x7b101f8   gRPC config loader
0x7b10258   literal 0x0c023be "Def_Online_gRPC_insecure" (24)
0x7b1027c   bl 0x2f0eaf0            ; int getter
0x7b10280   cbnz w0, 0x7b105c8      ; non-zero => plaintext channel
```

Forcing that flag to 1 makes the channel **plaintext**, so gRPC writes HTTP/2
frames straight to the socket and an ordinary libc `send`/`write` hook captures
the request verbatim. No TLS interception, and no need for BoringSSL's
`SSL_write` — which cannot be recovered from the stripped binary anyway (its
string literal at `0xa27cf3` has no code reference in the 104 MB text segment).

The insecure branch resolves its own destination, so all four keys are supplied
(offsets read from the file, not inferred from length — `_server_path` and
`_server_port` are both 27 characters):

| key | offset | getter | value |
|---|---|---|---|
| `Def_Online_gRPC_insecure` | `0x0c023be` | int `0x2f0eaf0` | `1` |
| `Def_Online_gRPC_server_address` | `0x0ba2aff` | string `0x2f0e18c` | `pes22-game.cs.konami.net` |
| `Def_Online_gRPC_server_path` | `0x09c69c1` | string `0x2f0e18c` | `/command_service.CommandService/CommandStream` |
| `Def_Online_gRPC_server_port` | `0x0b68de6` | int `0x2f0eaf0` | `443` |

The string getter returns a `std::string*` (the caller reads the SSO size byte
immediately), so a real `libc++ std::string` is constructed for the reply.

## Where it runs

The free **ARM64 GitHub runner** (`ubuntu-24.04-arm`, public repo). Measured on
it: kernel `6.17.0-1022-azure` with `CONFIG_ANDROID_BINDER_IPC=m`, binderfs
mounts, docker privileged allowed, 4 vCPU / 15 GiB / 108 GB, and redroid 14
`arm64-v8a` **boots in ~10 s as root**.

This is also exactly why AWS Graviton was a dead end: Debian's AWS kernel has
`CONFIG_ANDROID_BINDER_IPC` **unset**, so `mount -t binder` cannot work at all.
Ubuntu ships the driver as a module. The OS was the deciding factor, not the
CPU architecture or the instance size.

## Files

| file | purpose |
|---|---|
| `FINDINGS_KGS_2026-09-29.md` | full record, including retractions |
| `scripts/capture_insecure.js` | Frida: force plaintext, hook `connect`/`send`/`write`, dump frames |
| `scripts/decode_capture.py` | captured sends → h2 frames → HPACK → gRPC envelope → protobuf; flags non-standard headers |
| `scripts/test_decode.py` | decoder self-test (PASS) |
| `scripts/replay_capture.py` | send the game's own bytes verbatim over real TLS |
| `scripts/trust_our_ca.js` | fallback: point the game at our CA via the global at `0xa4a8480` |
| `scripts/make_mitm.py` | mitmproxy addon, same fallback path |
| `ci-report/latest.md` | what the runner last observed |

## Why the replay step is decisive

Sending the game's own captured bytes over a real TLS connection gives one of
two answers, and both are conclusive:

- **served normally** → the difference was in the request bytes, and diffing
  the capture against our probes localises it;
- **`502 g=14` again** → the request bytes are not the problem, so the
  difference is in the transport (TLS fingerprint / connection setup).

A MITM would *not* answer this: the proxy would itself be the TLS client to
Konami, presenting a different handshake from the game's BoringSSL. Capturing
inside the game's own process is the only measurement that keeps the real
client identity intact.

## Actions traps (each one cost a run)

| symptom | cause |
|---|---|
| report never appears in the repo | no `actions/checkout` step ⇒ no git repo; the `\|\| echo` hid it |
| report push does nothing | `actions/checkout` leaves a detached HEAD — push by refspec |
| step dies in seconds | the shell is `bash -e -o pipefail`; guard every optional command |
| step 02 dies in 0–3 s | the runner user is not root, so `/root` is unwritable |
| `modprobe` finds nothing | `binder_linux.ko` is in `linux-modules-extra-$(uname -r)` |
| Android never finishes booting | `androidboot.redroid_gpu_mode=swiftshader` blocks `boot_completed` |
