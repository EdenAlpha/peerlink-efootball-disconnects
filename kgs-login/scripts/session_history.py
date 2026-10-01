"""Dump the user-side messages of one session out of opencode.db.

Used to recover what the work actually was when the live context has been
checkpointed away and only a summary remains.
"""
from __future__ import annotations

import sqlite3
import sys

DB = r"C:\Users\Administrator\.local\share\opencode\opencode.db"


def main() -> int:
    session = sys.argv[1] if len(sys.argv) > 1 else "ses_f1c2b7791ffeStOJCHgdR1C0g5"
    con = sqlite3.connect(DB)
    cur = con.cursor()
    tables = [r[0] for r in cur.execute(
        "select name from sqlite_master where type='table'")]
    print("TABLES:", tables, file=sys.stderr)

    for t in tables:
        cols = [r[1] for r in cur.execute(f"pragma table_info({t})")]
        if "session_id" in cols or "id" in cols:
            print(f"{t}: {cols}", file=sys.stderr)

    # find the message-ish table and pull user text in order
    for t in tables:
        cols = [r[1] for r in cur.execute(f"pragma table_info({t})")]
        if "sessionID" in cols or "session_id" in cols:
            key = "sessionID" if "sessionID" in cols else "session_id"
            has_role = "role" in cols
            has_text = any(c in cols for c in ("text", "content", "body"))
            if has_role and has_text:
                textcol = next(c for c in ("text", "content", "body") if c in cols)
                q = (f"select role, {textcol} from {t} where {key}=? "
                     "order by rowid")
                rows = list(cur.execute(q, (session,)))
                print(f"--- {t}: {len(rows)} rows ---", file=sys.stderr)
                for role, text in rows:
                    if role != "user":
                        continue
                    body = text if isinstance(text, str) else str(text)
                    print(f"\n### USER:\n{body[:1200]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
