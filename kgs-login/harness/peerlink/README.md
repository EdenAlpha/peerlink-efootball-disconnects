# PeerLink — deterministic P2P friend matches on the original eFootball engine

PeerLink runs the **untouched original eFootball ARM64 machine code**
(`libUE4.so`, ~160 MB, straight from the APK) headless under Unicorn, on
both ends of a friend match. The two ends exchange **inputs only** over
UDP and run the **same deterministic lockstep simulation** — every
simulated byte is produced by Konami's own code, identically on both
peers. No game logic is translated, rewritten, or emulated-approximated
(the "photocopy principle").

## Proof status (all reproducible from this bundle)

| # | Proof | Command | Result |
|---|-------|---------|--------|
| 1 | Ball physics bit-exact vs the game's own replay oracle | `scripts/ball_object_run.py` (M2/M4 series) | 0/296 byte diffs per tick, R0–R3 pass |
| 2 | 22/22 players built by the game's own ctors + real team data | `scripts/m13d_exit67.py` | setup sequencer 0→0x67 completes, 22/22 slots |
| 3 | Engine deterministic across independent instances | `scripts/engine_twinrun.py` (×2 + compare) | 60/60 per-tick checksums identical |
| 4 | Net layer, mini-sim, two threads | `python peerlink/demo_match.py` | **1200/1200 ticks bit-exact**, 44/44 checksums |
| 5 | Net layer, mini-sim, two processes | `python peerlink/demo_process_mode.py` | 300/300 bit-exact |
| 6 | **FULL STACK: real engine, real UDP, two processes** | `python peerlink/demo_engine_net.py --ticks 1200` | **1200/1200 ticks bit-exact**, 62 kicks via the game's installer, 44/44 checksum exchanges, zero divergence |

Proof 6 is the headline: the original engine, run twice over a real
room-code friend match, agreed on every one of 1200 ticks.

## Package layout

```
peerlink/
  transport.py    UDP transport: direct send, hole-punch burst, relay
                   fallback (RFW), lobby pass-through, pushback queue
  rooms.py         LobbyServer (rendezvous + relay) & LobbyClient;
                   6-digit numeric match IDs (like the real game)
  lockstep.py      the deterministic lockstep: input packets (56 x i32,
                   the decoded .trep field layout), per-tick acks +
                   retransmit, per-tick checksum exchange, divergence
                   abort (never resync)
  session.py       FriendMatchSession: create() -> numeric Match ID -> join() ->
                   frame(local_input) per display frame
  engine_sim.py    EngineSim: binds the Unicorn-harnessed original code
                   to the lockstep sim interface (kicks via the game's
                   own installer 0x6e93aec, ticks via 0x6e938a0)
  demo_match.py    proof 4    demo_process_mode.py    proof 5
  demo_engine_net.py  proof 6 — the full stack
  wire_debug.py    protocol diagnostic (raw socket-level logging)
  puppet/          the app path: roombot drives the GENUINE eFootball app
                   in an emulator (adb input + vision state machine) so it
                   hosts a private friendly room on its own network
                   stack; the Match ID is read off the lobby screen and
                   announced so friends on stock apps can join. The app
                   is the only network client; the puppet only reads
                   the screen and injects input. (M18)
```

## Protocol (binary, little-endian)

```
magic u32 0x504C4B | ver u16 | ptype u16 | room u64 | peer u32 | tick u32 | flags u32 | payload

PT_INPUT      tick + 56 x i32 (both pads, the .trep field decode)
PT_INPUT_ACK  per-tick ack (gap-safe: only the acked tick is retired)
PT_CHECKSUM   tick + u64 FNV-1a of the whole sim state (per-tick compare)
PT_PING       hole-punch burst          PT_BYE  graceful close
```

**Determinism rules** (each one was needed — violating any forks the worlds):
1. Inputs are handed to the sim in **canonical order** (host first) —
   never local/remote order, which differs between the two peers.
2. The lockstep gate advances tick N only when BOTH inputs are present.
3. Checksums are stored per tick and compared only for the same tick.
4. Input retransmission is retired per-tick by explicit ack only.
5. Frames read before their consumer exists are pushed back, never dropped.

## The engine side (what runs under the net layer)

- Boot: the full init cascade of `libUE4.so` under Unicorn (worklog M11).
- Ball module: constructed by the game's own ctor chain; ticked by the
  game's `ball_update_entry` at dt = 1/27 s; validated bit-exact against
  the tutorial replay oracle (`.rep`) — worklog M2–M5.
- Match setup: 109-step sequencer driven via the game's dispatcher,
  0→0x67 complete, 22/22 player slots built from `constant_team.bin`.
- Kicks: installed by the game's own kick installer (`0x6e93aec`).
- Known documented gap: kick *velocity* currently derives from the
  analog deflection (stand-in for the `.trep`→paramsB player-action
  path) — FINDINGS 10.3; replacing it with the real action processor is
  the next engine climb and does not affect the net layer.

## Running

```bash
python peerlink/demo_match.py                      # needs nothing but Python
python peerlink/demo_engine_net.py --ticks 1200     # needs the APK-extracted
                                                   # libUE4.so + scripts/ tree
python scripts/engine_twinrun.py --ticks 60 --out /tmp/A.json
python scripts/engine_twinrun.py --ticks 60 --out /tmp/B.json
python scripts/engine_twinrun.py --compare /tmp/A.json /tmp/B.json

# the app path (friends on stock apps; needs adb + tesseract + an
# emulator/device with the real game + a second account you own):
python peerlink/puppet/calibrate.py --serial <adb-serial>     # one-time setup
python peerlink/puppet/roombot.py   --serial <adb-serial>     # host a room
```
