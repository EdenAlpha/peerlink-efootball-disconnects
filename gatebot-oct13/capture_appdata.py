#!/usr/bin/env python3
"""capture_appdata.py -- what does the DTLS server send back, and when?

Run #36 held two sessions across the whole match and got `received: 0`; the
shared-rendezvous probe got `rx 0/0` too.  The server accepts our records and
says nothing, so either it only answers real protocol messages, or it answers
only specific ones.

The capture has the answer: it records both directions of the real client's
DTLS flows.  This pairs every client record with the server records that
follow it, so the request/response shape is visible instead of guessed --
including whether the server pushes unsolicited keepalives at all.

  python capture_appdata.py
  python capture_appdata.py --flow 30650
"""
import collections
import csv
import statistics
import struct
import sys

sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\work")
import replay_clienthello as R                                     # noqa: E402
import dtls_live as D                                             # noqa: E402

GCM_OVERHEAD = 24          # 8 B explicit IV + 16 B auth tag


def load():
    rows = []
    with open(R.CAP, newline="", encoding="utf-8", errors="replace") as f:
        for row in csv.DictReader(ln for ln in f if not ln.startswith("#")):
            if (row.get("proto") or "").lower() != "udp":
                continue
            if (row.get("src") or "").startswith("8.8."):
                continue
            p = R.udp_body(row.get("payload_hex") or "")
            if not p or len(p) < 13 or p[0] not in (0x14, 0x15, 0x16, 0x17):
                continue
            rows.append((int(row["ts_ms"]), row["dir"], row["src"],
                         int(row["sport"]), row["dst"], int(row["dport"]), p))
    return rows


def flows(rows):
    """group into (client_port -> server) pairs regardless of direction"""
    out = collections.OrderedDict()
    for ts, d, s, sp, dp, dport, p in rows:
        # only DTLS record versions
        v = struct.unpack("!H", p[1:3])[0]
        if v not in (0xFEFF, 0xFEFD):
            continue
        if s.startswith("10.0.0."):                # phone -> server
            key = (sp, dp, dport)
        else:                                      # server -> phone
            key = (dport, s, sp)
        out.setdefault(key, []).append((ts, d, p))
    return out


def main() -> int:
    want = None
    if "--flow" in sys.argv:
        want = sys.argv[sys.argv.index("--flow") + 1]

    rows = load()
    fs = flows(rows)
    # pick flows that have traffic in BOTH directions and the most packets
    scored = []
    for key, pk in fs.items():
        dirs = collections.Counter(d for _, d, _ in pk)
        scored.append((dirs["t"] + dirs["r"], key, pk, dirs))
    scored.sort(reverse=True)

    print("DTLS flows: %d   (showing those with server->client traffic)\n"
          % len(fs))
    shown = 0
    for total, key, pk, dirs in scored:
        if dirs["r"] == 0:
            continue
        if want and want not in str(key[2]):
            continue
        shown += 1
        if shown > 2:
            break
        print("=== server %s:%d  client-port %d   tx=%d rx=%d ==="
              % (key[1], key[2], key[0], dirs["t"], dirs["r"]))

        # server-bound and client-bound records, in time order
        srv, cli = [], []
        for ts, d, p in pk:
            try:
                recs, _ = D.parse_records(p)
            except Exception:                                      # noqa: BLE001
                continue
            for ct, ver, ep, seq, body in recs:
                if ct != 0x17:
                    continue
                (cli if d == "t" else srv).append((ts, ep, len(body)))
        print("    appdata records: client=%d  server=%d"
              % (len(cli), len(srv)))
        if not srv:
            print("    (server sent NO appdata)\n")
            continue

        cplain = [n - GCM_OVERHEAD for _, _, n in cli]
        splain = [n - GCM_OVERHEAD for _, _, n in srv]
        print("    server plaintext sizes: %s"
              % collections.Counter(splain).most_common(12))
        print("    client plaintext sizes: %s"
              % collections.Counter(cplain).most_common(12))

        # does the server ever speak first (after the handshake)?
        t_first_cli = cli[0][0] if cli else 0
        early_srv = [t for t, _, _ in srv if t < t_first_cli]
        print("    server records BEFORE the client's first appdata: %d"
              % len(early_srv))

        # request -> response latency: nearest following server record
        lat = []
        for ts, _, _ in cli:
            after = [t - ts for t, _, _ in srv if 0 <= t - ts <= 3000]
            if after:
                lat.append(min(after))
        if lat:
            print("    client->server response latency ms: median=%.0f "
                  "mean=%.0f min=%d max=%d  (%d/%d answered)"
                  % (statistics.median(lat), statistics.mean(lat),
                     min(lat), max(lat), len(lat), len(cli)))
        # server records with no preceding client record within 3 s => push
        push = 0
        for ts, _, _ in srv:
            before = [t for t, _, _ in cli if 0 <= ts - t <= 3000]
            if not before:
                push += 1
        print("    server records with no client traffic in prior 3s "
              "(unsolicited pushes): %d/%d" % (push, len(srv)))

        # interleaving of the first 30 records
        merged = sorted([(ts, "C", n - GCM_OVERHEAD) for ts, _, n in cli]
                        + [(ts, "S", n - GCM_OVERHEAD) for ts, _, n in srv])
        t0 = merged[0][0] if merged else 0
        print("    first 30 records (t, dir, plaintext):")
        for ts, dd, n in merged[:30]:
            print("        +%6.2fs  %s  %d" % ((ts - t0) / 1000.0, dd, n))
        print()
    if not shown:
        print("no flow with server->client appdata found")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
