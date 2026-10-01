# Lane `i`, 2026-10-01 — live `.rodata` dump and the connection rules

`libUE4_rodata_live.bin` is 42,098,688 bytes read **out of the running game**
(`/proc/<pid>/mem` of `jp.konami.pesam`, PID 6261), mapped
`f6abeee18000-f6abf163e000 r--p` at file offset 0 — the ELF's first read-only
segment, i.e. `.rodata`.

This is the game's own string table, captured live. It is the closest thing we
have to the "constitution of the connection" that `README.md` asks for.

## The disconnect rules, by name

Found adjacent to `pes-custom-encrypt`, in
`OnlineSystemApiManagerver3.cpp` and `OnlineModeTaskCreatePlatformGameSession.cpp`:

| offset | literal |
|---|---|
| `0xad12f3` | `ChangeoverPeerReceiveIdleTimeMsThreshold` |
| `0xad131c` | `DcTestPingTimeoutMs` |
| `0xad1330` | `DcTestNumPing` |
| `0xad12de` | `DoesBlockSocketError` |
| `0xad12af` | `AsymmetricInputDelayTurnDisconnectedModeEnable` |
| `0xad1238` | `P2P_LOW_LEVEL` |
| `0xad1246` | `InputDelayBufferSizeStandardValueRecentBasicStatisticsMaxSize` |
| `0xad13e3` | `AccessLineTesterPrivateNetworkQualityPoorThreshold` |
| `0xad142a` | `FecQueueParityEncoderRedundancy` |

`ChangeoverPeerReceiveIdleTimeMsThreshold` and the `DcTest*` ping watchdog are
the plausible mechanisms behind the symmetric mid-match freeze: the game kills
the match when the peer looks idle or the ping probe fails.

## Confirms M17 independently

```
0x00ad11a7  G:\PES22HC\Dev-600Series\Source\Shared\pes\Game\Online\OnlineSystem\Api\OnlineSystemApiManagerver3.cpp
0x00ad120e  pes-custom-encrypt
0x00ad1221  verify
0x00ad1228  HttpClientImpl2
```

The encrypt header is written by `HttpClientImpl2` in
`OnlineSystemApiManagerver3.cpp` — exactly as `FINDINGS_M17_kgs_wire.md` states,
now read from live memory rather than the on-disk file.

Also present, confirming the msgpack envelope fields:
`s_keyword` at `0xa97259`, `my_platform` at `0xaaabee`.

## Two corrections

**`AES256` is a false lead.** There are 44 hits in this segment and every one is
OpenSSL or gRPC boilerplate, e.g.
`ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:...` at `0x9c7a05`,
with `Rekeying failed.` and `nonce_length is nullptr.` nearby. This is the same
cipher-suite list that exists in the static binary. It is **not** the game's
request cipher. An earlier report of "`AES256=8` in the rw segment" was that
noise, and the device-side `-m 10` cap hid that there were 44.

**On-device `grep` is unreliable over these binaries.** It reported **zero**
hits for `pes-custom-encrypt` in a segment that demonstrably contains it at
`0xad120e`. Verify locally against a pulled copy; never trust a device-side
count. That is why `inspect_game_strings.py` exists.

## The AES key is still not found

No key literal sits adjacent to the header, so it is not a plain string beside
the cipher configuration. It is either derived at runtime or stored as raw
binary. The next search must look for **high-entropy binary blobs** near the
`HttpClientImpl2` code, not printable runs.

## Scripts

- `inspect_game_strings.py <segment>` — prints the string neighbourhood of the
  game's own anchors, for contrast with the OpenSSL region
- `inspect_aes_context.py <segment>` — prints context around every `AES256`
  occurrence and lists all 16/24/32-byte printable runs in the segment