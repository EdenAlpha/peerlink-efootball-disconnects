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

## What this means for the strip-down

- The abort/timeout paths are ordinary reachable functions, not inlined
  mysteries. `FUN_07e5bc34` is the hub: it touches
  `MATCH_STOP_COUNT_SELF_BUF_EMPTY`, `NTL_PEER_KEEPALIVE_COUNT`, and
  `NTL_PEER_KEEPALIVE`.
- `FUN_07e15d60` owns both `DETECT_NAT_ABORTED` and
  `CHECK_STUN_RTT_TIMEOUT` — one patch point covers the NAT-abort kill path.
- `FUN_07b4a278` / `FUN_07b4a610` own both `CmdGetTurnServerList` and
  `OnlineModeTaskCheckCheat`.
- `DETECT_NAT_ABORTED` has exactly 1 xref: smallest blast radius to neuter.
- Full decompilations (up to 120 lines per caller) are in
  `killrule_out.txt` under each `TARGET:` block.

## Caveats

- Addresses are file offsets in this build (`FUN_07xxxxxx`); rebase per boot.
- Ghidra log shows the usual UE4 noise (LSDACallSiteTable errors,
  scattered decompile warnings) — analysis itself reported success.
- Next: pick one abort (recommend `FUN_07e15d60`), patch, boot stripped
  APK on a device, read crash log, repeat.
