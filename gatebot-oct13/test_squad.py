#!/usr/bin/env python3
"""test_squad.py -- offline check that squad_list() now carries attributes.

Rebuilds a CMD_USER_SQUAD reply with the real structure found by
squad_probe.py (two containers: squad_data.gameplan view with ids only, and
top-level full records with parameters[147]) and asserts squad_list() emits
23 entries, each with its attributes, in gameplan order.
"""
import sys

import chain3 as c


def build(n=23, plen=147):
    """Synthetic CMD_USER_SQUAD reply matching the live structure."""
    gp, full = [], []
    for i in range(n):
        gid = {"id": 1000 + i, "serial": i}
        gp.append({"gameplayer_id": dict(gid)})          # gameplan: ids only
        full.append({"gameplayer_id": dict(gid),
                     "parameters": [i] + [0] * (plen - 1),
                     "level_info": {"level": 1},
                     "games": 0, "goal": 0})
    return {"result": "NOERR",
            "squad_data": {"player_list": gp,
                           "squad_gameplan": {"formation": [{}]}},
            "player_list": full,
            "team_data": {"base_team_id": 396, "team_name": "Sunderland RWB"}}


def main():
    sq = build()
    out = c.squad_list(sq)
    assert len(out) == 23, "expected 23 entries, got %d" % len(out)

    missing = [e for e in out if "parameters" not in e]
    assert not missing, "%d entries lost their parameters" % len(missing)

    assert all(len(e["parameters"]) == 147 for e in out), "parameter count"
    assert out[0]["parameters"][0] == 0 and out[5]["parameters"][0] == 5, \
        "gameplan order not preserved"
    assert set(out[0]) == {"gameplayer_id", "parameters"}, \
        "unexpected keys in entry: %s" % sorted(out[0])

    # ordering must follow the gameplan list, not the full-record list
    ids = [e["gameplayer_id"]["id"] for e in out]
    assert ids == sorted(ids), "order does not follow gameplan"

    print("OK  entries=%d  params_each=%d  order=preserved  keys=%s"
          % (len(out), len(out[0]["parameters"]), sorted(out[0])))

    # a squad that only has the gameplan view must still work (no crash)
    bare = c.squad_list({"result": "NOERR", "squad_data": sq["squad_data"]})
    assert len(bare) == 23 and all("parameters" not in e for e in bare)
    print("OK  degrades gracefully when attributes are absent")

    # empty squad must not crash either
    assert c.squad_list({}) == []
    assert c.squad_list({"squad_data": {}}) == []
    print("OK  empty squad handled")
    return 0


if __name__ == "__main__":
    sys.exit(main())
