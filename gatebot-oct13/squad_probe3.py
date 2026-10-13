import json, sys, time
sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\work")
from room1 import PACE, Gate, describe, login, load_capture
reqs = load_capture()[0]
g = Gate()
ok, r = login(g, reqs)
print("login ->", r.get("result") if ok else describe(r))
if not ok: raise SystemExit(1)
time.sleep(PACE)
m = g.envelope("CMD_GET_USER_SQUAD")
m["target_user_id"] = g.uid
sq = g.send(m)
fp = ((sq.get("squad_data") or {}).get("squad_gameplan") or {}).get("formation") or {}
print("formation keys:", sorted(fp) if isinstance(fp, dict) else type(fp))
print(json.dumps(fp, ensure_ascii=False, default=str)[:2200])
