#!/usr/bin/env python3
"""patch_wf.py -- patch kgs-ghidra2.yml on branch ghidra-decomp2 via gh api.

Adds a `decomp_deadline` input (default 230), exports FULLDUMP_DEADLINE_MIN,
raises job timeout 340 -> 355. Keeps the local working tree (main) untouched.
"""
import base64
import json
import subprocess
import sys

REPO = "EdenAlpha/peerlink-efootball-disconnects"
BRANCH = "ghidra-decomp2"
PATH = ".github/workflows/kgs-ghidra2.yml"


def gh(*args, inp=None):
    r = subprocess.run(["gh", *args], input=inp, capture_output=True)
    if r.returncode != 0:
        sys.exit("gh failed: %s" % r.stderr.decode(errors="replace"))
    return r.stdout


meta = json.loads(gh("api", f"repos/{REPO}/contents/{PATH}?ref={BRANCH}"))
content = base64.b64decode(meta["content"]).decode("utf-8")
sha = meta["sha"]
lines = content.split("\n")

# 1. add decomp_deadline input after decomp_start block
out = []
i = 0
added_input = False
while i < len(lines):
    ln = lines[i]
    out.append(ln)
    if ln.startswith("      decomp_start:"):
        # copy the whole decomp_start block (4 lines: key, desc, required, default)
        i += 1
        while i < len(lines) and lines[i].startswith("        "):
            out.append(lines[i])
            i += 1
        out.append("      decomp_deadline:")
        out.append('        description: "Decomp phase budget in minutes (FULLDUMP_DEADLINE_MIN)"')
        out.append("        required: false")
        out.append('        default: "230"')
        added_input = True
        continue
    i += 1
if not added_input:
    sys.exit("decomp_start input not found -- aborting")

content2 = "\n".join(out)

# 2. export FULLDUMP_DEADLINE_MIN after the decomp_start export
needle = 'export FULLDUMP_DECOMP_START="${{ inputs.decomp_start }}"'
if needle not in content2:
    sys.exit("decomp_start export not found -- aborting")
content2 = content2.replace(
    needle, needle + '\n          export FULLDUMP_DEADLINE_MIN="${{ inputs.decomp_deadline }}"', 1)

# 3. raise timeout
if "timeout-minutes: 340" not in content2:
    sys.exit("timeout-minutes: 340 not found -- aborting")
content2 = content2.replace("timeout-minutes: 340", "timeout-minutes: 355", 1)

# sanity: verify all three edits landed
assert "decomp_deadline:" in content2
assert "FULLDUMP_DEADLINE_MIN=" in content2
assert "timeout-minutes: 355" in content2

payload = json.dumps({
    "message": "kgs-ghidra2: add decomp_deadline input (230 min default), raise job timeout to 355",
    "content": base64.b64encode(content2.encode("utf-8")).decode("ascii"),
    "sha": sha,
    "branch": BRANCH,
})
r = subprocess.run(["gh", "api", "-X", "PUT", f"repos/{REPO}/contents/{PATH}",
                    "--input", "-"], input=payload.encode(), capture_output=True)
if r.returncode != 0:
    sys.exit("PUT failed: %s" % r.stderr.decode(errors="replace"))
res = json.loads(r.stdout)
print("patched ok: commit", res["commit"]["sha"][:8])
