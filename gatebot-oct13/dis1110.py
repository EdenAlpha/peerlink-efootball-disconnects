# dis1110.py -- STR-annotated disasm of the 11.1.0 SGR serializer
# (FUN_07895324) + ordered key extraction + diff vs the pre-11.1.0
# 121-key list (sgr_enc.dis / sgr_keys.py).
# Ghidra addr = ELF vaddr + 0x100000; .text file offset = vaddr.
import re
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

SO = (r"C:\Users\Administrator\Documents\Default Project\peerlink-"
      r"efootball-disconnects\efootball-apk\native1110\libUE4.so")
DUMP = (r"C:\Users\Administrator\Documents\Default Project\work"
        r"\ghidra_sgr\full1110\fulldump_out.txt")
OUT = (r"C:\Users\Administrator\Documents\Default Project\work"
       r"\sgr_enc1110.dis")
START_G, END_G = 0x7895324, 0x7896fd4       # FUN_07895324 .. next function
# 11.1.0 ELF layout: .text PT_LOAD off=0x2862500 vaddr=0x2866500
# -> vaddr = file_offset + 0x4000; Ghidra addr = vaddr + 0x100000.
TEXT_DELTA = 0x4000
GHI_DELTA = 0x100000

# ---- 1. string table from the 11.1.0 dump (DATA lines are CAPPED at
# 5,000,000 -- short common strings like 'faul' fall outside; the STR
# section carries every string + its xrefs, so parse BOTH) --------------
strs = {}
pat = re.compile(rb"^DATA ([0-9a-f]+) type=string len=\d+ val=(.*)$")
pat2 = re.compile(rb"^STR ([0-9a-f]+) ([^|]+?)(?: \||$)")
n_data = 0
with open(DUMP, "rb") as f:
    for line in f:
        if line.startswith(b"DATA "):
            n_data += 1
            m = pat.match(line)
            if m:
                strs[int(m.group(1), 16)] = m.group(2).decode(
                    "utf-8", "replace").rstrip("\r\n")
        elif line.startswith(b"STR "):
            m = pat2.match(line)
            if m:
                strs.setdefault(int(m.group(1), 16), m.group(2).decode(
                    "utf-8", "replace").strip())
print("DATA lines: %d, strings: %d" % (n_data, len(strs)))

# ---- 2. disassemble + annotate ------------------------------------------
START = START_G - GHI_DELTA - TEXT_DELTA     # file offset
with open(SO, "rb") as f:
    f.seek(START)
    code = f.read(END_G - START_G)
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
page = {}
out = []
imm = re.compile(r"#(-?0x[0-9a-f]+)")
for insn in md.disasm(code, START + TEXT_DELTA):   # base = vaddr
    txt = "0x%08x  %-8s %s" % (insn.address, insn.mnemonic, insn.op_str)
    ann = ""
    pc_vaddr = insn.address
    ops = insn.op_str.split(", ")
    if insn.mnemonic == "adrp" and len(ops) == 2:
        m = imm.search(ops[1])
        if m:
            # capstone (vaddr base) prints the ABSOLUTE target page
            page[ops[0]] = int(m.group(1), 16)
    elif insn.mnemonic == "add" and len(ops) == 3:
        m = imm.search(ops[2])
        if m and ops[1] in page:
            addr = page[ops[1]] + int(m.group(1), 16) + GHI_DELTA
            if addr in strs:
                ann = "           ; STR 0x%x '%s'" % (addr, strs[addr])
    out.append(txt + ann)
open(OUT, "w", encoding="utf-8").write("\n".join(out))
print("disasm lines: %d -> %s" % (len(out), OUT))

# ---- 3. ordered key extraction + diff ------------------------------------
keys = re.findall(r"; STR 0x[0-9a-f]+ '([^']+)'", "\n".join(out))
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
print("\n11.1.0 key order (%d):" % len(keys))
for i, k in enumerate(keys):
    print("%3d %s" % (i, k))
old_set, new_set = set(OLD), set(keys)
print("\nADDED in 11.1.0:  %s" % sorted(new_set - old_set))
print("REMOVED in 11.1.0: %s" % sorted(old_set - new_set))
