doc = r"C:\Users\Administrator\Documents\Default Project\work\flow_map.md"
add = """
- **2026-10-11 evening -- the z2 capture decoded** (passthrough_capture.csv
  has 11 plaintext gate/NTL HTTP POSTs; the earlier "encrypted only" read was
  wrong for HTTP): real phone flow adds **ntl.service.konami.net** --
  GateInfo.php handshake (titleCode PES2022, version 6.0.1, apiLevel 4 ->
  STATUS/API_STATUS/LOG_ACTIVE/SERVER_TIME/PUT_LOG_URL) then ReportLog.php
  lifecycle markers (pds/pde = punch phase, uds/ude = udp session, ~70-280 s
  apart) + UDP/5521 2-byte hop-count probes to ~30 GCP IPs.  gate-side run
  #4: CMD_USER_DATA_SYNC / CMD_TEAM_DATA_SYNC = HTTP 404 _DECODE_FAIL, no
  Cmd*Sync*.php in 11.1.0 -> in-band like READY_FLAG.  Precheck vs mapstamp
  contrast settles the heartbeat question: WITHOUT mid-match CHECK polls the
  server walks over DISCONN 0-3 within 0.5 s of END; WITH them gameend stays
  INVALID (window open) -> `--poll` added to chain3 (30 s cadence both
  identities, at_match_polling_interval_msec).  Server's open-match template
  match_result = 5 keys; echo-template submit variant added; run
  chain3_full5_20261011.log.
"""
with open(doc, "a", encoding="utf-8") as f:
    f.write(add)
print("flow_map.md appended", len(add), "chars")
