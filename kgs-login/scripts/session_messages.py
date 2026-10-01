"""Print the user messages of a session, oldest first, from opencode.db.

Recovers the real thread of a session when the live context has been
checkpointed and the opening request is no longer visible.
"""
from __future__ import annotations

import json
import sqlite3
import sys

DB = r"C:\Users\Administrator\.local\share\opencode\opencode.db"


def text_of(data: str) -> str:
    """Best-effort extraction of the visible text from a message blob."""
    try:
        obj = json.loads(data)
    except Exception:
        return data
    if isinstance(obj, dict):
        parts = obj.get("parts") or []
        out = []
        for p in parts:
            if isinstance(p, dict) and p.get("type") == "text":
                out.append(p.get("text", ""))
        if out:
            return "\n".join(out)
        for k in ("text", "content", "message"):
            if isinstance(obj.get(k), str):
                return obj[k]
    return json.dumps(obj)[:500]


def main() -> int:
    session = sys.argv[1] if len(sys.argv) > 1 else "ses_f1c2b7791ffeStOJCHgdR1C0g5"
    limit = int(sys.argv[2]) if len(sys.argv) > 2 else 400
    con = sqlite3.connect(DB)
    cur = con.cursor()
    rows = list(cur.execute(
        "select seq, type, data from session_message "
        "where session_id=? order by seq", (session,)))
    print(f"total messages: {len(rows)}")
    n = 0
    for seq, mtype, data in rows:
        if "user" not in str(mtype):
            continue
        body = text_of(data).strip()
        if not body:
            continue
        n += 1
        if n > limit:
            break
        print(f"\n===== [{seq}] {mtype} =====\n{body[:1500]}")
    print(f"\nuser messages: {n}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
