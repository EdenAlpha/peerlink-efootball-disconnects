#!/usr/bin/env python3
"""measure_report.py -- do the relay quality measurement chain3 never did.

Sequence (2026-10-12 capture blocks 35 -> 38/39/40):

  1. CMD_GET_GAMERELAY_QUALITYCHECK_LIST -> 63 regions, each with an echo
     endpoint in quality_check_data_list[i].address and a placeholder
     quality_list[i] {region, quality:0, last_update:0}.
  2. Send one datagram to each endpoint; it is reflected verbatim, so the
     round-trip time IS the quality figure (thresholds 75 / 175 ms).
  3. CMD_SET_GAMERELAY_QUALITY with the filled-in quality_list.

chain3 only ever replayed a stale captured report, which is why
game_session lands on sycom=P2P with gamerelay=NotImplement.

This script measures and reports, then reports what the gate accepted and
which region it would pick.  --n=all sends every answered region; a numeric
--n sends only the n fastest (the capture sent 3).

  python measure_report.py [--n=63] [--tag=owner]
"""
import json
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\work")
sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\kgs-gate-cipher")

from room1 import Gate, load_capture, login, PACE, describe   # noqa: E402
from room_info_shape import SENSITIVE, shape                  # noqa: E402

SENSITIVE.update({"id", "serial"})
PING = b"PINGCHAIN3QUALITYCHECK000000000000"   # opaque payload, echoed back


def show(o) -> str:
    return json.dumps(shape(o), ensure_ascii=False, default=str)


def split_addr(s):
    out = []
    for grp in s.replace("^", ",").split(","):
        for alt in grp.split("/"):
            alt = alt.strip()
            if "@" in alt:
                alt = alt.split("@", 1)[0]
            if ":" not in alt:
                continue
            host, _, port = alt.rpartition(":")
            if port.isdigit() and host:
                out.append((host, int(port)))
    return out


def rtt(host, port, timeout=1.0, tries=2):
    try:
        ip = socket.getaddrinfo(host, port, socket.AF_INET,
                                socket.SOCK_DGRAM)[0][4][0]
    except OSError:
        return None
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    best = None
    try:
        for _ in range(tries):
            t0 = time.time()
            try:
                s.sendto(PING, (ip, port))
                d, _ = s.recvfrom(2048)
            except (socket.timeout, OSError):
                continue
            if d != PING:              # not an echo -> not this protocol
                continue
            ms = int((time.time() - t0) * 1000)
            best = ms if best is None else min(best, ms)
    finally:
        s.close()
    return best


def measure(rows, workers=24):
    """rows: [(region, address)] -> [(region, rtt_ms|None)]"""

    def one(row):
        reg, addr = row
        cands = split_addr(addr)
        best = None
        for host, port in cands:
            ms = rtt(host, port)
            if ms is not None:
                best = ms if best is None else min(best, ms)
        return reg, best

    with ThreadPoolExecutor(max_workers=workers) as ex:
        return list(ex.map(one, rows))


def main() -> int:
    n = "all"
    for a in sys.argv[1:]:
        if a.startswith("--n"):
            n = a.split("=", 1)[1]

    reqs, _ = load_capture()
    g = Gate()
    ok, r = login(g, reqs)
    print("login -> %s" % (r.get("result") if ok else describe(r)))
    if not ok:
        return 1
    time.sleep(PACE)

    qc = g.send(g.envelope("CMD_GET_GAMERELAY_QUALITYCHECK_LIST"), timeout=20)
    if qc.get("result") != "NOERR":
        print("qualitycheck -> %s" % qc.get("result"))
        return 1
    cdl = qc.get("quality_check_data_list") or []
    rows = [(e.get("region", "?"), e.get("address", "")) for e in cdl]
    t0 = time.time()
    measured = measure(rows)
    hit = [(rg, ms) for rg, ms in measured if ms is not None]
    miss = [rg for rg, ms in measured if ms is None]
    print("measured %d/%d regions in %.1fs  (%d silent)"
          % (len(hit), len(rows), time.time() - t0, len(miss)))

    hit.sort(key=lambda x: x[1])
    for rg, ms in hit[:15]:
        print("    %-26s %4d ms  %s" % (rg, ms,
                                        "GOOD" if ms < 75 else
                                        ("OK" if ms < 175 else "POOR")))
    if len(hit) > 15:
        print("    ... %d more (worst %d ms)" % (len(hit) - 15, hit[-1][1]))

    # which entries to report
    if n == "all":
        pick = hit
    else:
        pick = hit[:int(n)]
    now = int(time.time())
    ql = [{"region": rg, "quality": ms, "last_update": now} for rg, ms in pick]

    m = g.envelope("CMD_SET_GAMERELAY_QUALITY")
    m["quality_list"] = ql
    sr = g.send(m, timeout=15)
    print("\nSET_GAMERELAY_QUALITY n=%d -> %s %s"
          % (len(ql), sr.get("result"), describe(sr)))
    if sr.get("result") != "NOERR":
        print("  body=%s" % show({k: v for k, v in m.items()
                                 if k not in ("msgid", "rqid", "s_keyword",
                                              "session_id", "auth_code")}))
        return 1
    print("best region reported: %s (%d ms)" % (pick[0][0], pick[0][1]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
