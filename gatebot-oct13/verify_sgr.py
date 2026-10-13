#!/usr/bin/env python3
"""Prove chain3's rebuilt sgr_request matches the real captured body key-for-key."""
import sys

sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\work")
sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project"
                   r"\kgs-gate-cipher")
import dump_flow as df        # noqa: E402
import chain3                 # noqa: E402

blocks = df.parse(r"C:\Users\Administrator\Documents\Default Project"
                  r"\work\cap\flows-final.log")
real = None
for b in blocks:
    if b["cmd"] == "CMD_SET_GAME_RESULT":
        real, _ = df.decode(b["req_hex"])
        break
if real is None:
    raise SystemExit("no real SET_GAME_RESULT found")

mine_body = chain3.sgr_request(
    261000128932850400,
    [{"gameplayer_id": {"id": i, "serial": 101 + i}, "averaged_overall": 60}
     for i in range(23)],
    [{"gameplayer_id": {"id": 100 + i, "serial": 0}} for i in range(23)],
    1, 1, "NOERR", 822300 // 60)

for sec in ("match_result", "game_check_data", "analyst_set_game_result_info"):
    rk = list((real.get(sec) or {}).keys())
    mk = list((mine_body.get(sec) or {}).keys())
    rs, ms = set(rk), set(mk)
    print("[%s]" % sec)
    print("  real order :", rk)
    print("  mine order :", mk)
    print("  missing    :", sorted(rs - ms) or "NONE  <-- complete")
    print("  extra      :", sorted(ms - rs) or "none")
    print("  same set   :", rs == ms)
    print()

# spot-check a couple of values
rmr = real["match_result"]
mmr = mine_body["match_result"]
print("error_code        real=%r mine=%r" % (rmr["error_code"], mmr["error_code"]))
print("behind_flag       real=%r mine=%r" % (rmr["behind_flag"], mmr["behind_flag"]))
print("use_setting_multi real=%r mine=%r" % (rmr["use_setting_multi_formation"],
                                             mmr["use_setting_multi_formation"]))
print("myteam len        real=%d mine=%d" % (len(rmr["myteam_player_list"]),
                                             len(mmr["myteam_player_list"])))
print("opp list len      real=%d mine=%d" % (len(rmr["opp_gameplayer_id_list"]),
                                             len(mmr["opp_gameplayer_id_list"])))
rgc = real["game_check_data"]
mgc = mine_body["game_check_data"]
print("check list len    real=%d mine=%d" % (
    len(rgc["gameplayer_parameter_check_data_list"]),
    len(mgc["gameplayer_parameter_check_data_list"])))
print("opp check len     real=%d mine=%d" % (
    len(rgc["opponent_gameplayer_parameter_check_data_list"]),
    len(mgc["opponent_gameplayer_parameter_check_data_list"])))
