import json, re
# server template from the mapstamp FULL check (gameend=INVALID open match)
line = None
with open("chain3_mapstamp_20261011_145730.log", encoding="utf-8", errors="replace") as f:
    for l in f:
        if "FULL check:" in l:
            line = l
if line:
    j = json.loads(line.split("FULL check:", 1)[1].strip())
    ger = j.get("game_end_result") or {}
    print("game_end_result keys:", sorted(ger))
    mr = ger.get("match_result") or {}
    print("match_result keys:", sorted(mr))
    print("player_data keys:", sorted((mr.get("player_data") or {})))
    ui = (mr.get("player_data") or {}).get("user_info") or {}
    print("user_info keys:", sorted(ui))
    print("score_data:", mr.get("score_data"))
    print("game_res:", mr.get("game_res"), "| gameend:", mr.get("gameend_reason"), "| abnormal:", mr.get("abnormalend_reason"))
    print("extra_match_result keys:", sorted(ger.get("extra_match_result") or {}))
    agri = ger.get("analyst_get_game_result_info") or {}
    print("analyst_get_game_result_info keys:", sorted(agri))
