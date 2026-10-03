# FINDINGS_GHIDRA_KILLRULE — kill-rule / abort-path xrefs in libUE4.so

Source: headless Ghidra 12.1.4 auto-analysis of `libUE4.so`
(160,822,968 B, SHA256 `2AC4FF17…1298CD`) on `ubuntu-24.04`
(4 vCPU / 16 GB), run `37101844662`, post-scripts
`FindKillRule.java` + `FindEncryptKey.java`.
Raw output (3805 lines): `efootball-apk/ghidra_results/killrule_out.txt`
(same file in the run artifact, 14-day retention).
Full analysis log: `ghidra_run.log` in the same artifact.

## Result

All 14 target strings found in `.rodata`, each with code xrefs into
real functions. No target came back empty.

| target | strings | xrefs | functions |
|---|---|---|---|
| E_TURN_ALLOCATION_MISSMATCH | 1 | 1 | (data ref only) |
| MATCH_STOP_COUNT_SELF_BUF_EMPTY | 5 | 11 | FUN_07e4724c, FUN_07e5bc34, FUN_07e5dd74 |
| TurnReconnectWaitTimeMs | 1 | 1 | FUN_07d05844 |
| NTL_PEER_KEEPALIVE_COUNT | 1 | 2 | FUN_07e4724c, FUN_07e5bc34 |
| KeepAliveTimerUs | 1 | 1 | FUN_07d0986c |
| reflexive_address | 1 | 8 | FUN_078b1ba4, FUN_078b261c, FUN_078c5c5c, FUN_078c6268 (+4 more in file) |
| CmdGetTurnServerList | 2 | 7 | FUN_07b4a278, FUN_07b4a610, FUN_07b57050, FUN_07eaf040 |
| DETECT_NAT_ABORTED | 1 | 1 | FUN_07e15d60 |
| MatchAbortTimerCoefficient | 1 | 1 | FUN_07d0ae34 |
| is_cheat_user | 1 | 2 | FUN_078428d4 |
| OnlineModeTaskCheckCheat | 1 | 2 | FUN_07b4a278, FUN_07b4a610 |
| CHECK_STUN_RTT_TIMEOUT | 1 | 1 | FUN_07e15d60 |
| NTL_PEER_KEEPALIVE | 1 | 2 | FUN_07e4724c, FUN_07e5bc34 |
| MultiplaySessionRecvThreadReceiveTimeoutUs | 1 | 1 | FUN_07d076c0 |

## RETRACTION: these are not the abort functions

An earlier version of this file claimed `FUN_07e15d60` was "one patch point
[covering] the NAT-abort kill path" and that `FUN_07e5bc34` was an abort hub.
**That was wrong.** Reading the decompilations shows every one of these
functions is a *consumer of a string literal*, not a decision that kills
anything. Patching them would change log text and nothing else.

Classified from the actual decompiled bodies:

| function | what it really is | evidence in the dump |
|---|---|---|
| `FUN_07e15d60` | `int -> const char*` error-code name lookup | body is only `if`/`switch`/`return "..."` chains, e.g. `if (param_1 == -0x1afffefd) return "DETECT_NAT_ABORTED";`. No side effects, no calls. |
| `FUN_07e5bc34` | stats/telemetry string builder | appends fragments via `FUN_03015088`, then `FUN_07e5fe98(param_1, str, "STATS_FORMAT")`. `"STATS_FORMAT"` is the giveaway: it emits a stats line. |
| `FUN_078428d4` | server-response field parser | walks a `key=value` blob with a `\` escape loop, storing results at `+0xf0` / `+0x960`. Reads `is_cheat_user` as a field name. |
| `FUN_07b4a610` | log/telemetry emitter | assembles `"Cheat ..."` inline on the stack (`local_61 = 0x61656843` = `"Chea"`), then logs it with `CmdGetTurnServerList`. |
| `FUN_078d3eec` | STUN reflexive-address formatter | builds an address byte-by-byte into a 90-byte stack buffer, then emits `reflexive_address`. |

So the xref counts in the table above measure **how many places log these
strings**, not how many paths can kill the process.

## What is actually useful here

1. **These are the strings the game emits when it aborts.** Boot a build and
   grep logcat for `DETECT_NAT_ABORTED`, `MATCH_STOP_COUNT_SELF_BUF_EMPTY`,
   `CHECK_STUN_RTT_TIMEOUT`, `E_TURN_ALLOCATION_MISSMATCH` — whichever appears
   first names the abort that actually fired. That is instrumentation, and it
   turns a blind patch loop into a targeted one.
2. **The decision sites are the *callers* of these formatters.** Reachability
   goes string -> logging function -> state machine that chose to abort. To
   patch a kill you need the upward edge, which this run did not capture.
3. `FUN_07e5bc34` -> `FUN_07e5fe98` is still worth one more look: `FUN_07e5fe98`
   is the telemetry sink, so the *stats emitter* is identifiable even though the
   abort decision is not.

## Next run must capture this

The full dump in flight (`FindFullDump.java`) records function names/sizes and
string xrefs but **no decompiles**, and `-deleteProject` discards the analysis
afterwards — so the upward call graph will not be recoverable from it without
another ~70 min run. The follow-up script should batch-decompile:

- every function containing `BL` to each of the formatter addresses above
  (caller discovery), and
- every caller of the telemetry sink, since those are the abort sites.

## Caveats

- Addresses are file offsets in this build (`FUN_07xxxxxx`); rebase per boot.
- Ghidra log shows the usual UE4 noise (LSDACallSiteTable errors,
  scattered decompile warnings) — analysis itself reported success.
- **Do not patch anything from this file.** Collect real aborts from logcat first.
