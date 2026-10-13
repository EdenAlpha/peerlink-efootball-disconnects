import json, sys, time
sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\work")
from room1 import PACE, Gate, describe, login, load_capture
reqs = load_capture()[0]
g = Gate()
ok, r = login(g, reqs)
print("login ->", r.get("result") if ok else describe(r))
if not ok: raise SystemExit(1)
time.sleep(PACE)
m = g.envelope("CMD_GET_SERVER_ENV")
sv = g.send(m)
print("GET_SERVER_ENV ->", sv.get("result"), sv.get("errcode"))
out = {k: v for k, v in sv.items() if k not in ("msgid", "rqid")}
print(json.dumps(out, ensure_ascii=False, default=str)[:3000])
