#!/usr/bin/env python3
"""fit_checksum.py -- solve check_sum from parameters, don't guess it.

reverse_checksum.py found: plain sum matches 3/46 pairs, everything else 0/46.
check_sum is ~2000..2500 while parameters are 147 mostly-small ints, so try a
linear model first: check_sum = a*sum + b*n + c*max + d*nz + e, solved by
least squares over all 46 pairs.  If residuals are 0 the formula is found.
If not, print the full structure that a human needs to see it.

  python fit_checksum.py
"""
import sys

sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\work")
sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\kgs-gate-cipher")

import decode_flows as DF                                         # noqa: E402
from reverse_checksum import find_params, find_checks            # noqa: E402


def solve(rows):
    """least squares for check_sum = w . features; returns w, max residual"""
    # normal equations over small ints: use float gauss elimination
    n = len(rows[0]) - 1
    A = [[0.0] * (n + 1) for _ in range(n + 1)]
    B = [0.0] * (n + 1)
    for r in rows:
        f, y = r[:-1], r[-1]
        for i in range(n + 1):
            fi = f[i] if i < n else 1.0
            B[i] += fi * y
            for j in range(n + 1):
                fj = f[j] if j < n else 1.0
                A[i][j] += fi * fj
    # gaussian elimination with partial pivot
    m = n + 1
    M = [row[:] + [B[i]] for i, row in enumerate(A)]
    for c in range(m):
        p = max(range(c, m), key=lambda r: abs(M[r][c]))
        M[c], M[p] = M[p], M[c]
        if abs(M[c][c]) < 1e-9:
            return None, None
        for r in range(m):
            if r != c:
                k = M[r][c] / M[c][c]
                for j in range(c, m + 1):
                    M[r][j] -= k * M[c][j]
    w = [M[i][m] / M[i][i] for i in range(m)]
    res = max(abs(sum((r[i] if i < n else 1.0) * w[i]
                      for i in range(m)) - r[-1]) for r in rows)
    return w, res


def main() -> int:
    blocks = DF.load()
    params = find_params(blocks)
    joined = [(key, cs, ms, params[key])
              for _i, _l, key, cs, ms in find_checks(blocks)
              if key in params]
    print("pairs: %d" % len(joined))

    # full vector view of 3 players
    for key, cs, ms, par in joined[:3]:
        print("\n--- %s  check_sum=%s max_speed=%s" % (key, cs, ms))
        print("  len=%d sum=%d max=%d nonzero=%d sumsq=%d" % (
            len(par), sum(par), max(par),
            sum(1 for v in par if v), sum(v * v for v in par)))
        print("  nonzero idx/val: %s" % [(i, v) for i, v in enumerate(par)
                                         if v][:40])

    feats = [
        ("sum", lambda p: sum(p)),
        ("len", lambda p: len(p)),
        ("max", lambda p: max(p)),
        ("nonzero", lambda p: sum(1 for v in p if v)),
        ("sumsq", lambda p: sum(v * v for v in p)),
    ]
    import itertools
    print("\n=== least-squares fits ===")
    best = []
    for r in range(1, 4):
        for combo in itertools.combinations(range(len(feats)), r):
            rows = [[feats[i][1](par) for i in combo] + [cs]
                    for _k, cs, _m, par in joined]
            w, res = solve(rows)
            if w is None:
                continue
            names = "+".join(feats[i][0] for i in combo)
            best.append((res, names, w))
    best.sort(key=lambda x: x[0])
    for res, names, w in best[:8]:
        print("  maxres=%-10.3f  %s   w=%s"
              % (res, names, ["%.4f" % x for x in w]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
