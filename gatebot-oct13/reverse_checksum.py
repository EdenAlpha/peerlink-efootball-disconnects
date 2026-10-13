#!/usr/bin/env python3
"""reverse_checksum.py -- recover the real check_sum function.

Run #40's verdict was gameend=INVALID, abnormalend_reason=CHEAT.  chain3's
_check_entry() sends `2000 + pid % 500` for check_sum and
`25000 + pid % 8000` for max_speed -- invented numbers, while the field is
named check_sum and the server can recompute it from the squad parameters it
stored itself.  A server that compares its own checksum against ours is
exactly a server that reports CHEAT.

The capture supplies both halves of the equation for the SAME players:
  - CMD_START_GAME carries squad_data_home.player_list[].parameters
  - block 123 carries gameplayer_parameter_check_data_list[].check_sum
so the function can be recovered by trying candidates against real pairs.

  python reverse_checksum.py
"""
import json
import sys

sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\work")
sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\kgs-gate-cipher")

import decode_flows as DF                                         # noqa: E402


def find_params(blocks):
    """{gameplayer_id_key: parameters list} from any block carrying squads"""
    out = {}

    def scan(o):
        if isinstance(o, dict):
            for k, v in o.items():
                if k in ("player_list", "squad_player_list") and \
                        isinstance(v, list):
                    for e in v:
                        if not isinstance(e, dict):
                            continue
                        gid = e.get("gameplayer_id")
                        par = e.get("parameters")
                        if isinstance(gid, dict) and isinstance(par, list):
                            key = "%s/%s" % (gid.get("id"), gid.get("serial"))
                            out[key] = par
                else:
                    scan(v)
        elif isinstance(o, list):
            for e in o:
                scan(e)

    for idx, cmd, req, resp in blocks:
        scan(req)
        scan(resp)
    return out


def find_checks(blocks):
    """{gameplayer_id_key: (check_sum, max_speed)} from SET_GAME_RESULT"""
    for idx, cmd, req, resp in blocks:
        if cmd != "CMD_SET_GAME_RESULT":
            continue
        gcd = req.get("game_check_data") or {}
        for lst in ("gameplayer_parameter_check_data_list",
                    "opponent_gameplayer_parameter_check_data_list"):
            for e in (gcd.get(lst) or []):
                gid = e.get("gameplayer_id") or {}
                key = "%s/%s" % (gid.get("id"), gid.get("serial"))
                yield idx, lst, key, e.get("check_sum"), e.get("max_speed")


def candidates(par):
    n = len(par)
    s = sum(par)
    xs = 0
    for v in par:
        xs ^= v
    return {
        "sum": s,
        "sum%65536": s % 65536,
        "sum%10000": s % 10000,
        "sum%4096": s % 4096,
        "xor": xs,
        "weighted(i*par)": sum(i * v for i, v in enumerate(par)),
        "weighted(i*par)%65536": sum(i * v for i, v in enumerate(par)) % 65536,
        "sum first 11": sum(par[:11]),
        "sum of first n": sum(par[:n]),
        "crc16-ccitt": None,
        "adler32": None,
        "fnv1a32": None,
        "sum even idx": sum(par[0::2]),
        "sum odd idx": sum(par[1::2]),
    }


def crc16(data, poly=0x1021, init=0xFFFF):
    crc = init
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ poly) & 0xFFFF if crc & 0x8000 \
                else (crc << 1) & 0xFFFF
    return crc


def adler32(data):
    a, b = 1, 0
    for v in data:
        a = (a + v) % 65521
        b = (b + a) % 65521
    return (b << 16) | a


def fnv1a(data):
    h = 2166136261
    for v in data:
        h ^= v & 0xFF
        h = (h * 16777619) & 0xFFFFFFFF
        h ^= (v >> 8) & 0xFF
        h = (h * 16777619) & 0xFFFFFFFF
    return h


def main() -> int:
    blocks = DF.load()
    params = find_params(blocks)
    print("players with a parameters array in the capture: %d" % len(params))

    pairs = list(find_checks(blocks))
    print("check_sum entries in SET_GAME_RESULT: %d" % len(pairs))
    if not pairs or not params:
        print("cannot form a pair -- nothing to reverse")
        return 1

    # join on gameplayer_id
    joined = []
    for idx, lst, key, cs, ms in pairs:
        if key in params:
            joined.append((idx, lst, key, cs, ms, params[key]))
    print("joined (same player has both parameters and check_sum): %d\n"
          % len(joined))
    if not joined:
        print("keys sample params=%s" % sorted(params)[:3])
        print("keys sample checks=%s" % [p[2] for p in pairs][:3])
        return 1

    print("=== real pairs (first 6) ===")
    for idx, lst, key, cs, ms, par in joined[:6]:
        print("  #%d %-52s check_sum=%s max_speed=%s params_len=%d"
              % (idx, key[:52], cs, ms, len(par)))
    print("\n  parameters sample (first 24): %s"
          % joined[0][5][:24])

    # score every candidate against every pair
    names = None
    scores = {}
    for idx, lst, key, cs, ms, par in joined:
        cands = candidates(par)
        cands["crc16-ccitt"] = crc16(bytes(par[i] & 0xFF for i in
                                           range(len(par))))
        cands["adler32"] = adler32(par)
        cands["fnv1a32"] = fnv1a(par)
        if names is None:
            names = sorted(cands)
            scores = {n: 0 for n in names}
        for n in names:
            if cands.get(n) == cs:
                scores[n] += 1

    print("\n=== candidate check_sum functions vs %d real pairs ==="
          % len(joined))
    for n in sorted(scores, key=lambda x: -scores[x]):
        print("  %-26s %d/%d" % (n, scores[n], len(joined)))

    # max_speed: is it a value inside parameters?
    print("\n=== max_speed (first pair) ===")
    idx, lst, key, cs, ms, par = joined[0]
    print("  target max_speed = %r" % ms)
    hits = [i for i, v in enumerate(par) if v == ms]
    print("  appears in parameters at indices: %s" % (hits[:10] or "NONE"))
    near = [(i, v) for i, v in enumerate(par) if isinstance(v, int)
            and 15000 <= v <= 35000]
    print("  parameters in 15k..35k range: %s" % (near[:10] or "NONE"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
