# gatebot-oct13 — eFootball gate-bot snapshot, 2026-10-13

Two fake identities (chain3 gate-bot) driven through a real custom-room match.
Status at snapshot time: run #41 live-testing the CHEAT fix (see §23.21).

Target repo is PRIVATE (`peerlink-backup`). Nothing in here goes to a public
remote: session values are redacted, identity files and `bot_create.json` are
excluded (regenerate with `mint.py`), capture binaries (`.pcap`/`.mitm`) and
GB-scale `ghidra_*`/`adb`/`shots` dirs are excluded.

## Read first

- `POSTROOM_FLOW.md` — the whole investigation (§23.18–23.21 are current)
- `cap/flows-final.log` — the 2026-10-12 real-client capture, gate-encrypted
  (138 blocks, decoded with the static gate key via `decode_flows.py`)

## Run

- `python chain3.py` — offline check
- `python chain3.py --live` — full match (~8.5 min, log `chain3_liveNN.log`)
- Needs `../kgs-gate-cipher` on `sys.path` (`room1.py`: login, `Gate`)
  — pinned at `7e1914b`, clean, already pushed to its own repo.

## Current state (§23.21)

- `DISCONN_HB` is NOT a stamp: absent from all 138 capture blocks, already
  present pre-kickoff, from `CMD_CHECK_GAME_RESULT` which the real client
  never calls. Read `CMD_GET_GAME_RESULT` (`NO` → poll → `YES`) instead.
- Real verdict path: run #40 → `gameend=INVALID / abnormalend_reason=CHEAT`.
- `check_sum = sum(parameters) − par[59] − par[60]` (46/46 capture pairs).
  Run #41 sends it computed off both squads' real `parameters[147]`.
- `sgr_request` prints `sgr checksums: N/46` — N must be 46 in the live log.

## Key files

| file | what |
|---|---|
| `chain3.py` | the match driver (all live runs) |
| `decode_flows.py` | capture decoder (138/138 blocks) |
| `diff_commands.py` | capture commands vs chain3 coverage |
| `check_capture_stamp.py` | proves DISCONN_HB is absent from capture |
| `diff_sgr.py` / `reverse_checksum.py` / `fit_checksum.py` | check_sum reversal |
| `dtls_openssl.py` / `dtls_hold.py` / `turn_rendezvous.py` | DTLS channel (established, server silent — needs libUE4.so plaintext) |
| `probe_turn_auth*.py` / `probe_turn_time.py` | TURN: `turn_time_limit` is credential lifetime; realm sweep failed |
| `probe_appdata_brute.py` / `probe_appdata_framing.py` | 0/1280 heartbeat guesses — token required |
| `stun_keepalive.py` / `udp_punch.py` | T7 keepalive (server-correlated, kept) |
| `redact.py` / `verify_secrets.py` | credential hygiene for anything public |
| `chain3_live*.log` | run verdicts (#38–40 current) |
| `cap/cap_sgr123.json` | capture block 123 reference body (redacted) |
