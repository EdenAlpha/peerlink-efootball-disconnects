#!/usr/bin/env python3
"""squad_params.py -- do OUR squads carry parameters[147]? (one-off check)"""
import re

log = open(r"C:\Users\Administrator\Documents\Default Project\work\chain3_live20.log",
           encoding="utf-8", errors="replace").read()
print("parameters occurrences:", len(re.findall(r"parameters", log)))
for m in re.finditer(r"parameters.: \[(.*?)\]", log):
    body = m.group(1)
    vals = [v for v in body.split(",") if v.strip().lstrip("-").isdigit()]
    print("  len~%d head=%s" % (len(vals), vals[:8]))
    break
i = log.find("squad_data_home")
print("home head:", log[i:i + 400] if i >= 0 else "NOT FOUND")
