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
sd = sq.get("squad_data") or {}
print("squad_data keys:", sorted(sd))
for k in sorted(sd):
    v = sd[k]
    if isinstance(v, dict):
        print("  %s: dict keys=%s" % (k, sorted(v)))
    elif isinstance(v, list):
        print("  %s: list len=%d" % (k, len(v)))
        if v and isinstance(v[0], dict):
            print("    entry0 keys:", sorted(v[0]))
    else:
        print("  %s: %r" % (k, str(v)[:80]))
# formation / lineup positions?
for k in ("formation_data", "lineup_data", "tactics_data", "order_data"):
    if k in sd:
        print("== %s ==" % k)
        print(json.dumps(sd[k], ensure_ascii=False, default=str)[:1500])
