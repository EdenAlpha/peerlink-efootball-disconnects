# The pattern: how a PeerLink match actually connects

Established 2026-10-01 by reading the match exports in
`captures/match-2026-09-26/` (two phones: `z1-tiamant-client`, `z2-elijah-hotspot-owner`)
and `p2p-disconnect/FINDINGS_P2P_2026-09-29.md`.

## The three lines that explain the architecture

From `z1-tiamant-client/match_log.txt`:

```
[02:28:35.895] [DNS-QUERY]     Watching STUN DNS: 'pesam.stun.service.konami.net'
[02:28:41.431] [DNS-LEARNED]   STUN IPv4: 35.76.243.83
[02:28:44.452] STUN[T1:Konami]: 197.210.53.1:26031 from 35.76.243.83:3478
                                     -> 10.57.220.5:26031
```

1. The game resolves Konami's STUN server.
2. It learns a candidate public address.
3. It sends a STUN binding request, port 26031.

Both phones do this **independently**, seconds apart, and neither needs to know
the other's address in advance.

## The finding that matters

**During the match, the phone contacts 141 distinct external IPs and not one of
them is Konami.**

Measured over the 2,024-second span of `z1-tiamant-client/passthrough_capture.csv`
(13,187 packets, complete IP payloads as hex):

| external IP | proto | packets | what it is |
|---|---|---|---|
| `8.8.8.8` | udp | 1629 | Google DNS |
| `34.156.177.234` | udp | 1223 | gameplay P2P peer |
| `108.156.162.47` | tcp | 1167 | Google/YouTube (ads) |
| `104.199.46.171` | udp | 549 | gameplay P2P peer |
| `32.184.206.158` | tcp | 419 | Google |
| `216.58.223.194` | udp | 270 | gameplay P2P peer |

Zero occurrences of any Konami host in the match-period traffic. The only Konami
contact is the STUN negotiation before gameplay begins.

## What this implies for the PeerLink bot

Konami's role is **introduction**, not participation. It hands each phone a
public candidate address; after that the match is pure P2P between the two
phones. It is, in effect, a phone-number exchange.

PeerLink already *observes* that introduction -- it watches the DNS query for the
STUN host and the `STUN[T1:Konami]` binding. Both endpoints are therefore already
known to both sides, and PeerLink could bring the bot in as the far-side peer
without the bot ever speaking to Konami.

**If that holds, the KGS join-code path -- and the `0xa4cff68` API-base-URL
blocker -- is not on the critical path at all.** That is worth testing before more
time goes into the URL hunt.

## Why the game cannot log in without the Play-installed data

Settled, and the user's recollection needed correcting on this point: the APK was
never missing. `efootball-apk/` holds the 862 MB XAPK, all three splits
(`pad_it_0.apk`, `pad_it_1.apk`, `config.arm64_v8a.apk`) and the real 160 MB
`libUE4.so`.

What is separate is the **asset OBB**, and it is protected by CRIWARE DRM:

```java
// com.criware.vod.CriAesDecryptor  (jadx: AES/CBC/NoPadding)
this.decryptor = Cipher.getInstance("AES/CBC/NoPadding");
keySpec = new SecretKeySpec(key, "AES");
ivSpec  = new IvParameterSpec(iv);
```

Two facts about this:

- The Java package is a **JNI shim**. Only `CriAesDecryptor` and
  `CriHttpRequest` exist; no app code calls them. The key and IV are supplied by
  native code in `libUE4.so`.
- `CriHttpRequest` has a plain `Open(url)` / `Connect("POST")` / `DownloadChunk()`
  interface, which means the key material is **fetched over HTTP** at some point
  in the flow.

`NoPadding` also means asset blocks are fixed-size and independently
addressable -- convenient for random access into a downloaded OBB.

So: the Play install is the *mechanism* that provides decryptable, key-consistent
asset data, not an obstacle to be worked around. Verified earlier by
`split_pad_it_0`/`split_pad_it_1` appearing only after a Play install, while
sideloads produce no PAD splits and cannot log in.

Note: `GameActivity.java:694` contains a **separate** PBKDF2-derived AES key. That
is not the KGS body cipher and not the CRIWARE asset cipher; do not conflate them.

## What the exports are, and are not

They are **not** PCAPs. They are richer for this purpose:

| file | contents |
|---|---|
| `udp_trace.csv` | 10,923 packets, per-stage **nanosecond** timing through every tunnel stage, `status`/`flags` per packet |
| `passthrough_capture.csv` | 13,187 **complete IP packets** as hex, internet-side, with event markers |
| `match_log.txt` | full session log |
| `score_shots/` | 192 screenshots |

A PCAP would give the same bytes with less context.

**The real gap is not format, it is coverage.** `FINDINGS_P2P_2026-09-29.md`
established that 12 of 14 exports are healthy and the single anomalous match ran
400 s with one end starved at 137:1 outbound. No export was taken *through* a
visible freeze. That is the capture worth taking next.