doc = r"C:\Users\Administrator\Documents\Default Project\work\POSTROOM_FLOW.md"
add = """
## 10. Live findings 2026-10-11 later (the capture answers)

- **NTL service found in the z2 capture** (plaintext HTTP, never contacted by
  the bot until now): the phone POSTs to `ntl.service.konami.net`
  (35.174.175.11 / 34.193.147.150 :80):
  - `POST /ntl/api/GateInfo.php` body `req=<hex of
    {"titleCode":"PES2022","locale":"US","version":"6.0.1","extr":"",
    "apiLevel":"4"}>` -> reply `STATUS: 200 / API_STATUS: 1 / LOG_ACTIVE: 1 /
    SERVER_TIME: <unix> / PUT_LOG_URL: .../ReportLog.php`. Verified live
    2026-10-11 (raw socket, exact captured bytes).
  - `POST /ntl/api/PES2022/ReportLog.php` with urlencoded `type/prefix/ver/dat`
    where dat = hex of a `## NTLInfo / ## AppInfo` text log (libVer
    1.17.1-Android-15, ntl uid = 32-hex, opt=22011111). Types seen: pds/pde
    (p2p session open/close, bracket the punch phase) and uds/ude (udp
    session open/close, bracket the whole match, ~70-280 s apart).
  - UDP 2-byte probes to ~30 GCP IPs on :5521 at ~3.3 s cadence = hop-count /
    access-line test (HOP_COUNT_* / ACCESS_LINE_* latency names), not punch.
- **USER_DATA_SYNC / TEAM_DATA_SYNC confirmed non-gate**: chain3 run #4 --
  both `_DECODE_FAIL` HTTP 404 "Data must be padded..." (36-byte HTML); the
  11.1.0 php inventory has NO Cmd*Sync*.php. Builders stay in chain3 as
  documentation of the in-band bodies.
- **Mid-match CHECK_GAME_RESULT polling is the in-match heartbeat**
  (at_match_polling_interval_msec=30000): mapstamp run (polls after each
  phase) kept gameend=INVALID through END + battery; precheck run (no polls)
  got DISCONN 0-3 walkover stamped within 0.5 s of END. The earlier "polls
  contaminated" note was wrong -- the missing polls caused the walkover.
- **Submit body gap found**: server template match_result (CHECK reply on an
  open match) = 5 keys {abnormalend_reason, game_res, gameend_reason,
  player_data, score_data}; our serializer body = 16 root keys with none of
  gameend_reason/game_res/score_data/player_data (the 11.1.0 serializer
  FUN_07895324 never emits them -- the server derives them). Echo-template
  submit variant added (photocopier): fill the server's own 5-key template
  and send it back. Run chain3_full5_20261011.log (--poll --realorder).
- gRPC channel is NOT the submit path: one-shot probes -- heartbeat
  dispatches CMD_HEARTBEAT_GRPC, SET_GAME_RESULT and GET_GAME_RESULT both get
  CMD_END_CONNECTION (server closes the stream on non-heartbeat commands).
"""
with open(doc, "a", encoding="utf-8") as f:
    f.write(add)
print("POSTROOM_FLOW.md appended", len(add), "chars")
