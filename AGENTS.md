# AGENTS.md — read this first, every session

You are working on **PeerLink**. This file exists because the goal was
misunderstood repeatedly in 2026-10-01 despite being written down elsewhere.
Read it before reading anything else. Do not answer questions about the
objective from memory or from whichever file happens to be open.

## The actual goal

PeerLink tunnels two phones' eFootball traffic over local WiFi so neither
depends on the internet. The upgrade: **the far side is a PeerLink bot**, not a
second human phone.

Both sides run the same deterministic physics, so they **never exchange game
state — only inputs**. Same inputs, same simulation, same goal. That is why one
phone can host both.

**Deliverable: create an eFootball room, read the join code, connect the bot as
the far-side peer.**

### Three things that are NOT the goal

- **Clearing the tutorial gate.** A room is made through the KGS protocol, not
  the game's UI. We do not need the title screen or any menu. A whole session
  was spent driving the UI to clear the gate. That was a means mistaken for the
  end.
- **A Konami account.** The game has guest login
  (`CmdGetKgsGuestLoginToken.php`). Proven: the burner device reached the title
  screen with `User ID: ASGN-994-264-515`, no account ever linked, 18 gate
  requests fired.
- **The KGS join code, necessarily.** During a match the phone contacts 141
  external IPs and **zero** Konami hosts. Konami's only role is the STUN
  introduction before kickoff. PeerLink already watches it. If the bot can ride
  that introduction, the join-code path is not on the critical path at all.
  **Test this before spending more time on it.**

## The missing piece, in one line

**One live memory dump taken while the game is logging in.**

We are not missing code. We have run Konami's own `libUE4.so` headlessly under
Unicorn (`kgs-login/harness/scripts/uc_loader2.py`). What we lack are the
*values* that only exist in a running, logged-in game:

- session object contents, task parameters (`+0x410` and siblings)
- the three POST-header args `a4, a5, a6` — `0x7d03e10` bails if any is NULL
- the AES-256 body key
- the 40-byte `sign` cookie value

Headless, all of those are zero, which is why the server fatals with
`HTTP 500` on every request while a fake script name correctly returns 404.
Not an IP block, not a naming error, not a TLS problem — the requests are
intrinsically incomplete.

So: **run the game, log in, dump memory, read the values out.** Then copy them
instead of fabricating them. That single dump unblocks the whole stack.

## The two walls, and what each really is

1. **The file on disk has zeroed vtables.** No `DT_RELA`; only packed Android
   relocations (`SHT_ANDROID_RELA`/`APS2`). Most C++ calls load a null vtable
   slot and branch to 0. Partial workaround: read the tables out of a *running*
   process (`find_dispatch.py`). See `kgs-login/findings/FINDINGS_M26_vtables_zero.md`.
2. **The server returns 500 to everything.** Address is right (real name 500,
   fake name 404). Verified *not* an IP block by repeating through Cloudflare
   WARP — byte-identical 500. See `FINDINGS_M25_gate_endpoint.md`.

## What is already done — do not redo it

| thing | state |
|---|---|
| NTL `GateInfo.php` | **live-verified 200** |
| MessagePack request format | **byte-exact**, round-trip tested |
| gate endpoint shape | `0x7b099d0` → `/pes22/gate/gate_<msgid>.php` |
| game's HTTP stack | runs headlessly; GET `0x7d03b68`, POST `0x7d04148` |
| session + task factories | `0x7cda280`, `0x7dc91d8` build real objects |
| `kgs.py` room endpoints | `create_room`, `room_info`, `join_request` already coded |
| applilink account flow | 63 flows recovered from `flows.mitm` |
| STUN introduction | fully mapped in `captures/match-2026-09-26/PATTERN.md` |

## False leads — do not re-derive these

- **`0x86` / `0x80` are NOT msgpack headers.** Both were random first bytes of
  ciphertext that happened to be valid markers. Each looked like a breakthrough
  for a moment. The bodies are encrypted. If you "find" a msgpack header in a
  gate body, check the byte is not just luck.
- **`403 awselb/2.0` is a datacenter-address policy**, proven by `info.service.konami.net`
  returning **404 from the user's residential IP** (accepted, processed) and 403
  from a runner. Not an outage, not a client problem. Do not hedge this.
- **"The plaintext is not in memory" was never established.** The scan selected
  zero regions and reported "0 offsets" — it inspected nothing. Retracted.
- **`0xa4cff68` being all zeros does not block the URL.** `FINDINGS_M23` shows the
  builder reads a static at `0x97d4448`, and the live host is already known.
- **The APK was never missing.** 862 MB XAPK, three splits, real 160 MB
  `libUE4.so`. Only the CRIWARE-encrypted asset OBB is separate
  (`AES/CBC/NoPadding`, key fetched over HTTP, supplied by native code).
- **`peerlink_restored/kgs.py` local copy is at
  `kgs-login/harness/peerlink/kgs.py`.** M17 lives in
  `EdenAlpha/peerlink-session-bundle`, not here.

## Working rules

- **Photocopier.** Run the game's code; read its bytes. Never hand-assemble
  request bytes, never guess the key, never fabricate a region.
- **One screenshot, one decision, one tap.** No blind tap chains, no queued
  multi-step commands. After every action, look before deciding the next.
- **Read the findings before theorising.** `kgs-login/findings/` (M22–M26) and
  `captures/match-2026-09-26/PATTERN.md` already answer most questions.
- **Never spoof headers or `X-Forwarded-For` to get past an access control.**
  Konami's 403 stops the work; that is the correct outcome, not a failure to
  route around.
- **Shell scripts must stay LF.** A CRLF line ending makes every `case` on
  `/proc/<pid>/maps` fields silently fail. `.gitattributes` enforces this; if a
  scan reports zero of anything, check line endings first.
- **Never `git checkout` with an uncommitted new file** — it deletes it.
- **Never `git add -A`.** Explicit paths only; `git pull --rebase` before push.
- Repo is **public**. Never commit a credential literal. The burner account
  password was pasted in chat this session and must be rotated by the user.

## Driving the phone

Commands go on `live-cmd-<lane>/cmd.txt` (single command, one line).
Results, screenshots and logs appear on `live-res-<lane>/`. One verified action
per round trip; round trip is 60–120 s. **Run logs are unreadable mid-run — all
observability comes from the `live-res-<lane>` branch.**

An ARM64 runner (`ubuntu-24.04-arm`) is unlimited on this public repo. Step 01
(Play install, ~2 GB) takes ~2.5 h; the live loop is step 05.