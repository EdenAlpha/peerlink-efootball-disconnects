# verify1110.py -- which of the old 121 keys are missing from the 11.1.0
# annotated disasm, and is each a real removal (absent from the binary)
# or an annotator miss (present via dump xref or direct binary read)?
import re

DIS = r"C:\Users\Administrator\Documents\Default Project\work\sgr_enc1110.dis"
DUMP = (r"C:\Users\Administrator\Documents\Default Project\work"
        r"\ghidra_sgr\full1110\fulldump_out.txt")
SO = (r"C:\Users\Administrator\Documents\Default Project\peerlink-"
      r"efootball-disconnects\efootball-apk\native1110\libUE4.so")
SO_OLD = (r"C:\Users\Administrator\Documents\Default Project\peerlink-"
          r"efootball-disconnects\efootball-apk\native\lib\arm64-v8a\libUE4.so")

OLD = """abnormalend_reason is_problem is_stun_keep_alive_failed
is_network_blocked_disconn is_background_timeout is_background_at_match
user_network_status ex_flag pk_flag error_code is_join_game oap base_value
is_man_of_the_match myteam_player_list id serial gameplayer_id rating
play_time position is_starting_member score ball_possession shots
shots_on_goal faul faul_offside corner_kick free_kick pass_success_rate
cross pass_cut tackle save match_stat_side_info_list achievement_id
progress_num achievement_progress_list use_team_style owngoal_user_list
event_record restart_num control_style total shoot pass dribble
offense_positioning duel defense_positioning coop_score behind_flag
tour_pvp_bonus achieved_num tour_pvp_bonus_result_list label condition_num
point is_rare count golazo_count_list golazo_info ml_event_match_bonus id
serial opp_gameplayer_id_list use_setting_multi_formation match_result
match_time_frame match_time_tick com_stop_info entry_check_data
ball_move_max_speed serial gameplayer_id check_sum max_speed
gameplayer_parameter_check_data_list id serial gameplayer_id check_sum
max_speed opponent_gameplayer_parameter_check_data_list id stadium_id
custom_stadium_name stadium_color1 stadium_color2 stadium_color3
stadium_color4 goalnet_pattern goalnet_color1 goalnet_color2 pitch_pattern
entrance_set bill_set pitchside_objects goal_effect1 goal_effect2
kickoff_effect has_invalid_assets custom_stadium golazo_count_list
golazo_info game_check_data match_json advice_json game_id advice_index
analyst_advice_type id serial gameplayer_id date is_new advice_info_list
advice_info_match is_invalid_advice analyst_set_game_result_info""".split()

dis = open(DIS, encoding="utf-8").read()
annot = set(re.findall(r"; STR 0x[0-9a-f]+ '([^']+)'", dis))
missing = [k for k in dict.fromkeys(OLD) if k not in annot]
print("old unique keys: %d, annotated: %d" % (len(set(OLD)), len(annot)))
print("missing from annotation: %s" % missing)

# dump xrefs: does FUN_07895324 reference each missing key?
xref = {}
pat = re.compile(r"^STR ([0-9a-f]+) (\S+) \|(.*)$")
with open(DUMP, encoding="utf-8", errors="replace") as f:
    for line in f:
        if not line.startswith("STR "):
            continue
        m = pat.match(line)
        if m and m.group(2) in missing:
            xref[m.group(2)] = "FUN_07895324" in m.group(3)
b = open(SO, "rb").read()
o = open(SO_OLD, "rb").read()
for k in missing:
    # whole-word match: not preceded by identifier chars
    rx = re.compile(b"(?<![A-Za-z0-9_])" + re.escape(k.encode()) + b"\\x00")
    print("%-14s dump-xref-in-serializer=%-5s in-1110-binary=%-5s "
          "in-old-binary=%s"
          % (k, xref.get(k), bool(rx.search(b)), bool(rx.search(o))))
