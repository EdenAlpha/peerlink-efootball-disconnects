# PeerLink: what we are actually trying to do

Written after losing the thread three times in one session. Every failure had the
same cause: answering from whichever document happened to be open instead of the
one that states the goal. This file is the goal, in one place.

## The deliverable

**PeerLink needs to create an eFootball room and give two phones a join code.**

That is the whole objective. Everything else is either a means to it or a
distraction from it.

## The reason the tutorial gate is NOT the deliverable

A room is created through the **Konami Game Server (KGS) protocol**, not through
the game's UI. We do not need to clear the tutorial gate, reach the title screen,
or drive the game's menus. We need to speak the protocol.

So "clear the tutorial gate" is a *means* that was mistaken for the goal, and
driving the UI to do it was always the wrong approach.

## What already exists and works

Per `FINDINGS_M17_kgs_wire.md` (in `EdenAlpha/peerlink-session-bundle`), and
locally in `kgs-login/harness/peerlink/kgs.py`:

| component | state |
|---|---|
| NTL `GateInfo.php` bootstrap | **live-verified 200 OK** |
| KGS request format (MessagePack) | **byte-exact**, round-trip tested |
| envelope serializer/parser | decoded from `libUE4.so`, offsets known |
| `CmdLogin.php` body builder | 23 fields, `w2=0x17` |
| RSA-2048 public key + `ChangeServer.bin` hook | decoded |
| runtime config dump under Unicorn | done |
| room endpoints (`create_room`, `room_info`, `join_request`) | **already in `kgs.py`'s `CMD` map** |

The endpoints that produce the join code are already coded. This is not a
greenfield reverse-engineering problem.

## The one thing blocking it

From the M17 status board:

> `guest login -> room create -> match` | **blocked on URL above**

The game builds its request URL at runtime from a **4-entry environment table at
`0xa4cff68`** (getter `0x814a04c`; flag at `+0x2c`, SSO string at `+0x30`),
populated during the 12-state online bootstrap state machine
(`0x7dc7164`, jump table at `0xc905b8`).

The static default in config (`0xa4b01d0` = `pes22-game.cs.konami.net`) is tagged
`" DEV1"` at `0xa4b01b8` -- a **pre-production default**, and it returns 404 on
every candidate path. So the default is not the production value; the real URL is
delivered in bootstrap data we have not yet captured.

**That single unknown is the blocker. Everything else is done.**

## Next moves (from M17's own attack vectors)

1. Find the writer to the env table at `0xa4cff68` -- search stores to page
   `0xa4cf000` whose value is a string pointer; candidates cluster in
   `0x8123xxx`-`0x814Axxx`.
2. Drive the 12-state bootstrap (`0x7dc7164`) under Unicorn with a fabricated
   session and dump the URL after **state 5** (session create, vtable
   `0x97cf020`).
3. Check whether the gRPC layer (`OnlineSystemgRPCClient.cpp`,
   `command_service.pb.cc`) reveals the target in its channel args.

Navigation gold from leaked dev paths is in the M17 file, e.g.
`OnlineSystemApiManagerVer2.cpp` `0x7afe21c`, `OnlineSystemMultipLay.cpp`,
`OnlineModeTaskMatchSession.cpp` `0x7a559a8`.

## Open questions about the wire

- `kgs.py` builds `gate_<msgid>.php` and its `CMD` map names
  `CmdCreatejoinRoom.php`; M17 calls the live-verified one `CmdLogin.php`.
  Two naming families. Which one the live server accepts is exactly what move 1
  or 2 resolves.
- The `gate_CMD_*` bodies captured in `captures/` are **encrypted**, not
  plaintext MessagePack. A first byte of `0x86` on
  `gate_CMD_GET_AGE_GATE_REQUIREMENTS.php` is a coincidence (a valid msgpack
  fixmap marker in ciphertext), **not** a decoded envelope. Do not re-derive
  that false lead.