#!/usr/bin/env python3
"""squad_probe.py -- do the bot identities actually HAVE a squad?

chain3.py's squad_list() reduces every player to {gameplayer_id:{id,serial}}
and discards everything else, and the server's CMD_START_GAME reply echoes
back squad_data_home = {team_id: 0, averaged_overall: 0}.  Two readings are
possible and they lead to opposite conclusions:

  (a) the bots' stored squads really are hollow, so the server correctly
      reports zeros -- and the match is judged invalid because we fielded an
      empty team; or
  (b) the stored squads are fine and chain3 strips them on the way out, so
      the zeros are an artefact of OUR transmission, not of the data.

This answers it by reading CMD_USER_SQUAD for both identities and reporting
the structure.  Read-only: one squad read per identity, no room, no match.
User ids and player ids are not printed.
"""
import json
import sys

import chain3 as c  # noqa: E402


def report(tag, sq):
    print("=" * 64)
    print("%s" % tag)
    if not sq or sq.get("result") != "NOERR":
        print("  squad read -> %s  %s"
              % ((sq or {}).get("result"), c.describe(sq or {})))
        return
    sd = sq.get("squad_data") or {}
    players = sd.get("player_list") or []
    print("  result            : NOERR")
    for k in ("team_id", "base_team_id"):
        if k in sd:
            print("  squad_data.%-13s: %r" % (k, sd[k]))
    # some responses keep the team id at the top level instead
    for k in ("team_id", "base_team_id"):
        if k in sq and k not in sd:
            print("  (root).%-16s: %r" % (k, sq[k]))
    print("  players           : %d" % len(players))

    with_params = with_overall = 0
    plen = 0
    roles = {}
    for p in players:
        prm = p.get("parameters")
        if isinstance(prm, list) and prm:
            with_params += 1
            plen = max(plen, len(prm))
        if p.get("averaged_overall"):
            with_overall += 1
        for rolekey in ("role", "position", "position_id"):
            if rolekey in p:
                roles[p[rolekey]] = roles.get(p[rolekey], 0) + 1
    print("  with parameters   : %d  (longest %d values)" % (with_params, plen))
    print("  with averaged_ovl : %d" % with_overall)
    if roles:
        print("  distinct roles    : %d  %s"
              % (len(roles), sorted(roles)[:12]))

    gp = sd.get("squad_gameplan") or {}
    form = gp.get("formation") or []
    print("  squad_gameplan.formation entries: %d" % len(form))
    if form:
        f0 = form[0]
        if isinstance(f0, dict):
            print("    formation[0] keys: %s" % ", ".join(sorted(f0)[:10]))
    mps = gp.get("match_plan_settings")
    if isinstance(mps, dict):
        print("    match_plan_settings keys: %s" % ", ".join(sorted(mps)[:10]))

    # top-level siblings of squad_data -- the real player attributes may live
    # here rather than inside squad_data, in which case chain3 is reading the
    # wrong container rather than the accounts being empty.
    for sibling in ("player_list", "team_data", "coach_list"):
        v = sq.get(sibling)
        if not isinstance(v, (list, dict)):
            continue
        if isinstance(v, list):
            print("  top-level %-12s: list of %d" % (sibling, len(v)))
            if v and isinstance(v[0], dict):
                print("      [0] keys: %s" % ", ".join(sorted(v[0])[:12]))
                prm = v[0].get("parameters")
                if isinstance(prm, list):
                    print("      [0] parameters: %d values" % len(prm))
                print("      [0] averaged_overall: %r"
                      % v[0].get("averaged_overall"))
        else:
            print("  top-level %-12s: keys=%s" % (sibling, ", ".join(sorted(v)[:12])))
            for k in ("team_id", "base_team_id", "team_name",
                      "averaged_overall", "team_overall"):
                if k in v:
                    print("      %s = %r" % (k, v[k]))

    # what chain3 would actually transmit for this squad
    transmitted = c.squad_list(sq)
    print("  squad_list() transmits: %d entries" % len(transmitted))
    if transmitted:
        print("    sample keys: %s" % ", ".join(sorted(transmitted[0])))
    print("  top-level response keys: %s"
          % ", ".join(k for k in sorted(sq)
                       if k not in ("result", "msgid", "rqid")))


def main():
    if "--live" not in sys.argv:
        print("offline check: use --live")
        return 0
    reqs = c.load_capture()[0]
    try:
        with open(c.BOT_FILE, encoding="utf-8") as fh:
            bot = json.load(fh)
    except Exception as e:                                  # noqa: BLE001
        print("bot identity unreadable: %s" % e)
        return 1

    owner = c.Gate()
    ok, r = c.login(owner, reqs)
    print("owner login -> %s" % (r.get("result") if not ok else "NOERR"))
    if not ok:
        return 1
    report("OWNER SQUAD", owner.send(c.user_squad(owner, owner.uid)))

    botg = c.Gate()
    okb, rb = c.login_bot(botg, reqs, bot)
    print("bot login   -> %s" % (rb.get("result") if not okb else "NOERR"))
    if not okb:
        return 1
    report("BOT SQUAD", botg.send(c.user_squad(botg, botg.uid)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
