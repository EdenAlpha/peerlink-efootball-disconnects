# Working evidence (2026-09-26, no speculation)

## APK acquired
- `efootball-apk/eFootball-2024_11.0.1_apkcombo.com.xapk` 862,826,266 bytes (823 MiB), from APKCombo `/r2` signed URL (valid 4h from 18:24 UTC).
- Contains `jp.konami.pesam.apk` 22MB + `config.arm64_v8a.apk` 57MB + `pad_it_0/1.apk` 386/395MB.
- Native: `native/lib/arm64-v8a/libUE4.so` 160,822,968 bytes. UE4 engine. 404,159 ASCII strings.

## Native confirms (libUE4.so strings, with file offsets)
- `pesam.stun.service.konami.net` @12361298 (1 hit). Matches capture DNS: z1 learns `35.76.243.83` (match_log `DNS-LEARNED STUN IPv4`), IPv6 `2406:da14:...`.
- STUN/TURN: `ERR_FAILED_STUNCHECK` (lobby create/join), `CHECK_STUN_RTT_TIMEOUT`/`CHECK_STUN_RTT_COMPLETE`, `SendStunMsg ... tid ... act` @10953544, `ALLOCATE_SUCCESS_RESPONSE`, `REFRESH_REQUEST`, `CHANNEL_BIND_REQUEST`, `E_TURN_ALLOCATION_MISSMATCH` @10251944, `E_NOSUPPORT`, `E_SKIP`.
- DTLS: `DTLSv1.2`, `dtls1_check_timeout_num`, `dtls1_retransmit_message` (25 hits). Matches capture: game UDP `16feff...` (DTLS handshake) `t 208B` / `r 190/194B` to `34.22.210.195:30650` etc.
- Keepalive/timeout names: `TurnNetworkIoReconnectServerTimeWaitMs` @10251029, `TurnReconnectWaitTimeMs` @10487790, `NtlReconnectWaitTimeMs` @12200932, `NTL_PEER_KEEPALIVE_COUNT` @12121675, `KeepAliveTimerUs` @12120984, `MultiplaySessionRecvThreadReceiveTimeoutUs` @10251231, `LinkTimeoutUs`, `PingIntervalUs`, `EstablishedConnectionTimeoutUs`, `LoadTimeoutMs`, `MatchAbortTimerCoefficient`.
- Match-stop rules: `MATCH_STOP_COUNT_SELF_BUF_EMPTY_BURST_L1/L2/L5`, `MATCH_STOP_COUNT_BUF_EMPTY_MCACTIVE`, `MATCH_STOP_COUNT_SELF_BUF_EMPTY_BURST_L1_MCACTIVE` (same rodata region as above).
- `turn.konami.com`: 0 hits in libUE4.so AND 0 hits in all 37 APK splits (checked raw bytes). TURN address is dynamic (via `ntl.service.konami.net`, see below), not hard-coded.
- VPN detection: `tun0` 0, `VpnService` 0, `magisk` 0, `emulator`/`qemu`/`genymotion` 0, `RootBeer` 0, `frida` only `Friday` FP. `isDeviceRooted` x1, `SafetyNetAttestationSucceeded/Failed` x2 (standard UE4). No VPN-specific checks in native lib.
- Java dex (`classes.dex` 76k strings): no game netcode (only Firebase heartbeat, protobuf). Netcode is native.

## Captures confirm (both phones)
- 3 stalls 02:34:48 / 02:37:15 / 02:45:53, Z1-Z2 delta 31/99/112ms. `54B burst` 2s before each cliff (`MatchAutomationEngine.kt:36-43,98-101`: dying tick shrinks to uniform ~54B, 45 in ~1.1s, threshold 6) = game decides, then `pps=0`.
- Pre-stall: DTLS `208t/190r` ping-pong until ~750ms before cliff. During 21s: zero game DTLS, only DNS `8.8.8.8:53`, TCP 443, QUIC `8.8.8.8:443` (z2), len-30 `:5521` probes. STUN keepalives continue. Internet works, game stops.
- DNS (z1 plaintext): `pes22-game.cs.konami.net x19`, `ntl.service.konami.net x8` -> 5x A incl `35.174.175.11` (seen TCP 443/80), `pesam.stun.service.konami.net x2` -> `35.76.243.83`. z2 DNS encrypted (QUIC), only 2 plaintext names.
- Screenshots: `z2/.../shot_0006_OTHER.jpg` = black + eFootball logo (loading). `z1 shot_0533_STATS_BOARD_0-0.jpg` = clean 10-min match after.

## Still open (needs Ghidra RE, not speculation)
- Exact values for `TurnReconnectWaitTimeMs`, `NTL_PEER_KEEPALIVE_COUNT`, `MATCH_STOP_COUNT_*`, `MatchAbortTimerCoefficient` + code path for `E_TURN_ALLOCATION_MISSMATCH` (direct ADRP+ADD xref not found with Rd-matched scan; likely enum-indexed table, needs Ghidra).
- TURN address delivery via NTL API (TLS, can't see cleartext; need runtime hook or NTL response MITM).
- No VERDICT yet. Next: Ghidra headless on libUE4.so for the 4 xrefs above, or runtime test (disable STUN fabrication, use real STUN, see if stalls stop).

## Deep-internals update (APK dissected, CAPTURE_AUTOPSY §6-7 hunt)

- jadx 1.5.6 decompile of base APK done (9,679 classes, 129 errors — obfuscation, normal). Game netcode is native, not Java.
- apktool 2.12.0 decode done. Manifest: `compileSdk 36`, INTERNET/ACCESS_NETWORK_STATE/WIFI/WAKE_LOCK etc.
- `Reachability.smali` (`PESAM_Reachability`): checks only WIFI(1)/CELLULAR(0)/ETHERNET(3) transports, never VPN(4). On PeerLink VPN the active network reports `ACTIVENETWORK:UNKNOWN`. No explicit VPN ban — VPN is UNKNOWN to the game.
- `GetRooting.smali`: `isDeviceRooted()` via `Runtime.exec("su")`. No Java caller (called from native via JNI — class string in libUE4.so). Root check live; `tun0`/`ppp0`/vpn: zero hits in all smali + native.
- Hunt list: `agones`/`nabeshin`/`sdk.gameserver` 0 hits (dynamic via NTL/GateInfo). `reflexive_address`/`reflexive_port`/`PEER_REFLEXIVE`/`RP_REFLEXIVE_ADDRESS` present. `is_cheat_user` + `is_cheat` JSON fields + `OnlineModeTaskCheckCheat.cpp` + `CmdGetTurnServerList` (TURN via API — explains 0 `turn.konami.com` hits). `DETECT_NAT_ABORTED`, `E_TURN_QUOTA_ERROR`, `FREE_TURN_PORT_ERROR/ABORTED`, `MATCH_STOP_COUNT_*` x27 (L1-L5, BURST, SELF/BUF, MCACTIVE). `FakeKeepAlive` warning. `5521` 0 hits (dynamic mesh port).
- Captures: `turn.konami.com` arrives live inside DTLS 256B server→phone records (cert), not via DNS/binary. `GateInfo.php` POST plaintext to `35.174.175.11:80`. TCP inbound not byte-captured (v1 scope) so GateInfo response unseen.
- Ghidra 12.1.4 (543MB, SHA ddac49… verified) + Corretto 21 installed. Headless `FindKillRule.py` (14 targets: xrefs + decompile callers) running on libUE4.so.


## Platform collectors + solution branch (cont.)
- GetMyIpAddress.GetIpAddressList() enumerates ALL NetworkInterfaces: game CAN see tun0 (10.0.0.2) + wlan0/ap0 + rmnet. No Java callers (JNI from native). Whether native filters interface names needs Ghidra caller list: open.
- Detector constants (ours): GAMEPLAY_PPS_MIN=24 MAX=27 (MatchAutomationEngine.kt:75-76), ZERO_PPS_THRESHOLD=1 (:104), GAMEPLAY_ARM_SAMPLES=15 (:107).
- GateInfo baseline both phones identical: POST ntl.service.konami.net /ntl/api/GateInfo.php titleCode PES2022 locale US version 6.0.1 apiLevel 4, z1 1790386119275 z2 1790386131554. Response not captured (no inbound TCP).
- Solution branch Peerlink-app@test/no-stun-fabrication (bec0ef9): toggle + RULE 1b + STUN-drop fix + HONEST_MODE_NOTES.md protocol. Independent review: gating correct, ports over-broad noted, one default-true change (unknown-profile passthrough, intended per KDoc).
- PeerLink logs contain zero NTL/punch/alloc lines (game-internal); T7 STUN keepalives continue through all stalls; TURN-IP lookup failed 02:24 both phones (own resolver), TurnIps=0 all match.

## Hotspot/WifiManager/root/interface sweep (cont.)
- Hotspot/tether/softap/AP detection: NONE in native (HotSpot* hits are UE4 UI, tether hits all PhysX cloth FP, ap0/p2p0/softap/TETHERING 0, SSID/BSSID 0). wlan0/rmnet0 single hits sit inside UE4 Slate/UI string runs (SExpanderArrow/SListView, MenuDropdown/VirtualKeyboard): packing coincidence, not network code.
- GetWifiManager: RSSI/signal tracking (calcRssi, s_rate, s_wifiInfo, NetworkCallback, getConnectionInfo). No SSID/BSSID reads. Signal quality, not hotspot gating.
- GetTrafficStats: byte counters only.
- TURN cert anomaly: server delivers turn.konami.com cert inside DTLS 256B records with validity 2019-07-26 to 2021-... (expired 5y before 2026 capture) yet sessions establish and run 8+ min. Expiry not the immediate killer; noted for Ghidra (cert validation path).
