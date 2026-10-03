# Ghidra kill-rule findings — run 37101844662 (2026-10-03)

Headless analysis of the real 160 MB `libUE4.so` (SHA256
`2AC4FF17AC8AD713D9531C2601E38A3C8335E02EA882BA2DC4445C191C1298CD`)
on `ubuntu-24.04` free runner, Ghidra 12.1.4, via
`.github/workflows/kgs-ghidra.yml`.

- Run: https://github.com/EdenAlpha/peerlink-efootball-disconnects/actions/runs/37101844662
- Result: SUCCESS, `ANALYSIS_RC=0`, gate passed with 3805 result lines
- Elapsed: 93 min (06:04Z → 07:37Z)
- Full log + results: artifact `kgs-ghidra-37101844662` (14-day retention);
  `killrule_out.txt` copied into this repo at `efootball-apk/ghidra_results/`.
- The binary traveled via draft release `libue4-local`, **deleted after the
  run** (KONAMI property, do-not-redistribute). Nothing of KONAMI's persists
  in the repo or on GitHub.

## Target addresses (all 14 found; xrefs + decompiled callers)

| string | string addr | xref | function |
|---|---|---|---|
| `is_cheat_user` | `00c434bf` | `07842974` (PARAM) | `FUN_078428d4` |
| `OnlineModeTaskCheckCheat` | `00b384e9` | `07b4a83c` (READ) | `FUN_07b4a610` |
| `CmdGetTurnServerList` | `00b38506` | `07eb53b8` (READ) | `FUN_07eb5364` |
| `DETECT_NAT_ABORTED` | `00ada6c8` | `07e15db4` (DATA) | `FUN_07e15d60` |
| `reflexive_address` | `00ca1410` | `078d4a54` (READ) | `FUN_078d3eec` |

Remaining targets (same file, same shape): `E_TURN_ALLOCATION_MISSMATCH`
(xref `09a5cef8`, no func), `MATCH_STOP_COUNT_SELF_BUF_EMPTY`
(`FUN_07e5bc34`, `FUN_07e4724c` — decompile failed, `FUN_07e5dd74`),
`TurnReconnectWaitTimeMs` (`FUN_07d05844`), `NTL_PEER_KEEPALIVE_COUNT`
(`FUN_07e5bc34`, `FUN_07e4724c`), `KeepAliveTimerUs`,
`MatchAbortTimerCoefficient`, `CHECK_STUN_RTT_TIMEOUT`, `NTL_PEER_KEEPALIVE`,
`MultiplaySessionRecvThreadReceiveTimeoutUs`.

## What the bodies say

- **`FUN_078428d4`** (`is_cheat_user` reader): msgpack-style key lookups —
  `FUN_03092514(param_1 + 0xf0, "result")`, then `"is_cheat_user"` inside
  it. It *reads the server's cheat verdict* out of a task result object, and
  touches fields `param_1 + 0x1f0 / +0x1f8 / +0x200`. A reader, not the
  guard; the guard is its caller.
- **`FUN_07e15d60`**: NAT-detect state enum decoder — `DETECT_NAT_COMPLETE`
  (`-0x1afffeff`), `DETECT_NAT_ERROR` (`-0x1afffefe`), `DETECT_NAT_ABORTED`
  (`-0x1afffefd`). This is the "no STUN → abort" state machine's string
  mapper; the abort decision lives in its caller.
- **`FUN_078d3eec`** (`reflexive_address` reader): reads the STUN reflexive
  address out of a response object.

## FindEncryptKey result

Header literal at `00bd120e` (image base `0x00100000` → region
`0xbcd20e–0xbd520e`), 25,901,970 instructions scanned, **740 functions**
reference the region. First hits are gRPC/protobuf internals
(`basic::Mutex`, `xds_client`, `MATERIAL_KEY_NONE`, …) — the region is a
large string blob, so the match is too broad. Next pass should narrow to
functions whose literals include `pes-custom-encrypt` itself or crypto names.

## Closed paths (do not redo)

- PyGhidra `.py` scripts cannot run under `analyzeHeadless` — Java ports only.
- `findBytes(Address,String,int,TaskMonitor)` does not exist; the working
  signature is `findBytes(Address,String,int,int)` returning `Address[]`.
- The GitHub live-log API freezes for long stretches on long jobs (proven:
  60–90 min frozen while the process worked). Liveness comes from the
  in-log 60 s `HEARTBEAT` line the workflow now prints, not from the API.
