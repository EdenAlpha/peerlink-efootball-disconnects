#!/usr/bin/env python3
"""chain3.py -- both seated -> squads -> sides -> ready -> session check
(GET/SET_GAME_SESSION_CHECK_RES echo) -> game_id -> START_GAME ->
heartbeat -> phase walk (halftime -> fulltime) -> goals -> SET_GAME_RESULT
-> read the score back.

The session-check echo (finish.py, pre-wipe proven) is what flips
is_check_finished to YES and unblocks START_GAME from ERR_DATABASE.
Since 2026-10-10 the run also holds the capture's real keepalive: one
gRPC CommandStream per identity beating every 15 s (beats dispatched
CMD_HEARTBEAT_GRPC 15/15 proven) -- the old HTTP CMD_HEARTBEAT_GRPC
fatals with 500.  This is the experiment against the DISCONN_HB
birth-stamp.

  python chain3.py            offline check
  python chain3.py --live     full run
"""
import json
import os
import sys
import threading
import time

sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\work")
sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\kgs-gate-cipher")

import gate_client as gc  # noqa: E402
from room1 import (BUILD, CFG, PACE, Gate, create_room, describe,  # noqa: E402
                   login, load_capture, next_rq, relay_quality)
from room2 import BOT_FILE, join_body, login_bot, NET  # noqa: E402
from beat_stream import BeatStream  # noqa: E402
from room_info_shape import SENSITIVE, shape  # noqa: E402
from sendreq_probe import getrequested, num_users, sendreq  # noqa: E402

SENSITIVE.update({"id", "serial"})

# a silent thread death would hide the bot's beats -- make it visible
threading.excepthook = lambda a: print("THREAD EXC: %s" % (a,))

CFG["mode"] = "CUSTOM"
CFG["kind"] = "SINGLE"
DIAG_CV = "6.1.1"

# capture blocks 51/98: the real client advertises IPv6 as completely inert.
# chain3 used the IPv4 NET for both, which sent host_port 1 / nat_type 1 as
# live-looking v6 candidates.
NET6 = {"host_address": "::", "host_port": 0, "reflexive_address": "::",
        "reflexive_port": 0, "nat_type": 0}


def show(o) -> str:
    return json.dumps(shape(o), ensure_ascii=False, default=str)


def at_cv(m: dict, cv: str) -> dict:
    m = dict(m)
    m["client_version"] = cv
    m["s_keyword"] = gc.s_keyword(cv, BUILD)
    return m


def args_ok(r: dict) -> bool:
    return r.get("result") != "ERR_INVALIDARG"


def diag(g: Gate, build) -> tuple[dict, bool]:
    """build() -> fresh body (fresh rqid); send at 6.1.1, never executes."""
    r = g.send(at_cv(build(), DIAG_CV))
    msg = r.get("msg") or ""
    ok = args_ok(r)
    print("  diag -> %s%s" % (r.get("result"),
                              (" | " + msg[:200]) if msg else ""))
    return r, ok


def find_key(o, key):
    if isinstance(o, dict):
        if key in o:
            return o[key]
        for v in o.values():
            f = find_key(v, key)
            if f is not None:
                return f
    elif isinstance(o, list):
        for v in o:
            f = find_key(v, key)
            if f is not None:
                return f
    return None


# ---------------------------------------------------------------- bodies ---

def ntl_gateinfo(timeout: int = 10, retries: int = 4) -> dict:
    """Konami NTL handshake (z1/z2 capture, plaintext HTTP): the real phone
    POSTs GateInfo.php to ntl.service.konami.net right at the punch phase
    (t+285.9s = match start).  Body = urlencoded req=<hex of JSON>.
    Returns the parsed STATUS lines.

    Two defects found 2026-10-11 by byte-diffing the capture, both of which
    made NTL answer its own STATUS:400 (so the handshake silently never
    happened in any earlier chain run):

      * the JSON key is ``extra``, NOT ``extr``.  That single missing letter
        is exactly the 2-byte gap between the body we built (164) and the
        real Content-Length (166).  With ``extra`` NTL returns STATUS:200.
      * the captured request carries NO User-Agent and NO Connection header.
        We were sending ``okhttp/4.12.0``.  Harmless once the key is right,
        but dropped so the bytes match the capture.

    Retries with backoff and falls back to the capture's own resolved IP,
    because DNS-by-hostname is pathologically slow on this VM and was the
    original reported cause of the timeout.
    """
    import binascii
    import socket
    import time
    body_json = json.dumps({"titleCode": "PES2022", "locale": "US",
                            "version": "6.0.1", "extra": "", "apiLevel": "4"},
                           separators=(",", ":"))
    data = ("req=" + binascii.hexlify(body_json.encode()).decode()).encode()
    # the capture resolved ntl.service.konami.net to this address
    hosts = [("35.174.175.11", 80), ("ntl.service.konami.net", 80)]
    path = "/ntl/api/GateInfo.php"
    last = None
    for host, port in hosts:
        for i in range(retries):
            t0 = time.time()
            try:
                s = socket.create_connection((host, port), timeout=timeout)
                try:
                    s.settimeout(timeout)
                    head = ("POST %s HTTP/1.1\r\n"
                            "Host: ntl.service.konami.net\r\n"
                            "Accept: */*\r\n"
                            "Content-Length: %d\r\n"
                            "Content-Type: application/x-www-form-urlencoded"
                            "\r\n\r\n" % (path, len(data)))
                    s.sendall(head.encode() + data)
                    chunks = []
                    while True:
                        d = s.recv(4096)
                        if not d:
                            break
                        chunks.append(d)
                    raw = b"".join(chunks)
                finally:
                    s.close()
                head_b, _, body_b = raw.partition(b"\r\n\r\n")
                out = {}
                for ln in body_b.decode("latin1").splitlines():
                    if ":" in ln:
                        k, v = ln.split(":", 1)
                        out[k.strip()] = v.strip()
                out["_http"] = (head_b.split(b"\r\n", 1)[0]
                                .decode("latin1", "replace"))
                out["_host"] = host
                out["_elapsed"] = round(time.time() - t0, 2)
                if out.get("STATUS") == "200":
                    return out
                last = "STATUS=%s" % out.get("STATUS")
            except Exception as e:                               # noqa: BLE001
                last = "%s %s" % (type(e).__name__, e)
            time.sleep(0.8 * (i + 1))
    return {"error": last or "no response"}


def ready_flag(g, rid, flag, tag="owner"):
    """CMD_READY_FLAG -- a real gate command chain3 has NEVER sent.

    Located 2026-10-11 by diffing every CMD_ literal in the 11.1.0 binary
    against the 24 commands chain3 speaks.  This one is real, and it lives
    in the NTL/GateInfo region of the binary (FUN_07ea1778 / FUN_07ea1dc8,
    a few KB from FUN_07eeb090 which parses the GateInfo reply).

    Body, decoded from FUN_07ea1778:

        msgid = CMD_READY_FLAG
        rqid  = <envelope>
        flag  = <u32 bitmask>   ; written at obj+0x150 from the w1 argument

    Both builders have exactly ONE caller each, so the dispatch is unambiguous:

        0x07b1fe0c -> FUN_07ea1778   (inside FUN_07b1fda8, size 228)
        0x07b20a40 -> FUN_07ea1dc8

    and FUN_07b1fda8 is a CHANGE DETECTOR, not a poller:

        tst  w8, w9 ; cset w11, ne ; cmp w11, w10 ; b.eq -> ret   (no send)
        orr  w10, w8, w9
        bic  w8,  w8, w9
        tst  w2,  #1 ; csel w8, w10, w8, ne
        mov  w1,  wzr ; str w8, [x0, #0x850] ; bl FUN_07ea1778

    i.e. it sends ONLY when a state bitmask changes, and stashes the new
    mask at +0x850.  A polling bot that never changes state would never
    trigger it -- exactly the shape of a DISCONN_HB ("stopped sending")
    failure.  Its 11 callers all sit in the Task\\Match\\ layer
    (OnlineModeTaskSyncMatchSettings / SideSelect / TeamSelect / UserData).

    We pass the mask explicitly because we have no client state to diff.
    """
    m = g.envelope("CMD_READY_FLAG")
    m["flag"] = int(flag) & 0xffffffff
    r = g.send(m, timeout=12)
    print("  ready_flag[%s] flag=%d -> %s %s"
          % (tag, int(flag), r.get("result"), describe(r)))
    return r


# ---------------------------------------------------------------------------
# Four gate commands chain3 has NEVER sent, recovered from the 11.1.0 binary
# on 2026-10-11 via the authoritative CMD_ -> CmdXxx.php map (gate_map.py).
# That map proved itself: CMD_READY_FLAG (run #16) resolved to no .php and the
# gate answered 404, so a command only counts once the map says it has a
# route.  All four below are map-confirmed gate commands.
# ---------------------------------------------------------------------------


def get_turn_address(g, tag):
    """CMD_GET_TURN_ADDRESS_DATA -> CmdGetTurnAddressData.php

    **CONNECT-phase gap.** chain3 has sent CMD_SEND_TURN_ADDRESS_DATA and
    CMD_WATCH_TURN_ADDRESS_DATA all along, but never asked the gate for its
    OWN address first.  Builder `FUN_07f8e7cc` writes ONLY the cmd name and
    the endpoint -- the request body is EMPTY.  The response parser
    (`FUN_07f8e99c`) reads:

        result, address, address_data_size

    i.e. the gate tells the client its own external address, which is what
    the client then announces with SEND_TURN_ADDRESS_DATA.  Builder
    proximity confirms the pairing: GET_TURN_ADDRESS_DATA (FUN_07f8e99c) and
    WATCH_TURN_ADDRESS_DATA (FUN_07f8f6a8) sit next to each other.
    """
    m = g.envelope("CMD_GET_TURN_ADDRESS_DATA")
    r = g.send(m, timeout=12)
    print("  get_turn_addr[%s] -> %s %s" % (tag, r.get("result"), describe(r)))
    return r


def get_server_env(g, tag):
    """CMD_GET_SERVER_ENV -> CmdGetServerEnv.php

    First step of MATCHING (`LATENCY_MODE_MATCHING_CMD_GET_SERVER_ENV`).
    Body fields `lang`, `region`, `platform`, `client_version` all default to
    the absent-sentinel `NotImplement`, so we send the bare envelope -- the
    faithful reproduction of the binary's default state.  The reply is the
    whole server config; the field that matters here is
    `communication_antenna_status_info`, since chain3 drives antenna beats
    without ever having fetched the config that governs them.
    """
    m = g.envelope("CMD_GET_SERVER_ENV")
    r = g.send(m, timeout=15)
    keys = ",".join(k for k in sorted(r) if k not in ("result", "msgid", "rqid"))
    print("  server_env[%s] -> %s keys=%s" % (tag, r.get("result"), keys))
    if r.get("result") == "NOERR":
        for k in ("communication_antenna_status_info",
                  "communication_antenna_status_info_cs",
                  "command_connect_timeout_sec", "command_timeout_sec",
                  "command_retry_num", "room_info_polling_interval_msec",
                  "is_revision_check", "proto_opt", "onsys_opt"):
            if k in r:
                print("      %s = %s" % (k, r[k]))
    else:
        print("      %s" % describe(r))
    return r


def send_session_id(g, game_id, tag):
    """CMD_SEND_SESSION_ID -> CmdSendSessionId.php

    SESSION-phase command, never sent by chain3.  Body (FUN_07f88880):

        game_id                    int64, default 0
        platform_session_id_info   { ps_session_id, xb_session_id }
                                   both default to the absent sentinel
                                   `NotImplement`

    We are on Android, so neither the PSN nor the Xbox session id applies and
    both are sent empty rather than as the sentinel -- the sentinel means
    "unset", and an explicit empty string is the neutral value chain3 already
    uses for absent strings elsewhere (e.g. link_type).
    """
    m = g.envelope("CMD_SEND_SESSION_ID")
    m["game_id"] = int(game_id) if game_id else 0
    m["platform_session_id_info"] = {"ps_session_id": "", "xb_session_id": ""}
    r = g.send(m, timeout=12)
    print("  send_session_id[%s] -> %s %s" % (tag, r.get("result"), describe(r)))
    return r


def join_game_mode(g, tag, game_mode="CUSTOM"):
    """CMD_JOIN_GAME_MODE -> CmdJoinGameMode.php

    **The MODE_MULTIPLAY sub-phase** of CONNECT, which chain3 has never
    entered.  An earlier note in this file called this a client-side stub
    ("FUN_0786da14 returns NotImplement"); that was WRONG and is retracted.
    FUN_0786da14 is the void *response* object's ctor -- it just seeds two
    response string fields with the absent-sentinel `NotImplement`.  The real
    request builder `FUN_0786d1f0` writes:

        game_mode, client_version, livedata_version

    all strings, all defaulting to `NotImplement`.  The response parser
    `FUN_0786db98` reads:

        result, result.ping_level, result.team_power_limit

    which is precisely the input CMD_SET_MATCHING_OPTION expects -- so these
    two are a feed-forward pair, not independent calls.
    """
    m = g.envelope("CMD_JOIN_GAME_MODE")
    m["game_mode"] = game_mode
    m["client_version"] = DIAG_CV
    m["livedata_version"] = ""
    r = g.send(m, timeout=15)
    print("  join_game_mode[%s] -> %s %s" % (tag, r.get("result"), describe(r)))
    return r


def set_matching_option(g, tag, ping_level=0, team_power_limit=0):
    """CMD_SET_MATCHING_OPTION -> CmdSetMatchingOption.php

    Body (FUN_07f0b904):

        ping_level             int
        team_power_limit       int
        control_style_filtering str, default "NO"

    The first two are exactly what CMD_JOIN_GAME_MODE's reply carries, so
    when the join succeeds we echo back the values the gate assigned rather
    than inventing our own.
    """
    m = g.envelope("CMD_SET_MATCHING_OPTION")
    m["ping_level"] = int(ping_level)
    m["team_power_limit"] = int(team_power_limit)
    m["control_style_filtering"] = "NO"
    r = g.send(m, timeout=12)
    print("  match_opt[%s] ping=%s tpl=%s -> %s %s"
          % (tag, ping_level, team_power_limit, r.get("result"), describe(r)))
    return r


def _regions_from(r, limit=8):
    """Pull region identifiers out of a CMD_GET_GAMERELAY_QUALITYCHECK_LIST
    reply WITHOUT depending on its exact nesting.

    The response carries quality_check_data_list / quality_list plus
    quality_threshold_1 and quality_threshold_2, but the precise shape of the
    entries is not known in advance.  Walking every dict and list for a
    region-ish string means a shape mismatch degrades to fewer entries rather
    than to a crash or to sending nothing at all.
    """
    out = []

    def walk(o):
        if isinstance(o, dict):
            for k in ("region", "name", "area", "id"):
                v = o.get(k)
                if isinstance(v, str) and v and v not in out:
                    out.append(v)
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)

    walk(r)
    return out[:limit]


def get_qualitycheck_list(g, tag):
    """CMD_GET_GAMERELAY_QUALITYCHECK_LIST -> CmdGetGamerelayQualitycheckList.php

    Request body is EMPTY (builder `FUN_077eac70` writes no fields).  This is
    the opening half of the CONNECT phase's final sub-phase, QUALITY_TEST:

        WAIT_SOCKET -> CONNECT_SESSION -> MODE_MULTIPLAY ->
        WAIT_CONNECT_SESSION_CONTROLLER -> REVISION_CHECK -> QUALITY_TEST

    The response parser `FUN_077eae40` reads:

        result, quality_check_data_list, quality_check_data_list_num,
        quality_threshold_1, quality_threshold_2,
        quality_list, quality_list_num

    i.e. the gate hands back the list of relay endpoints to measure and the
    two thresholds that classify the result.  Nothing is sent in the reply --
    the measurement is reported separately by
    CMD_SET_GAMERELAY_QUALITY, which is the command chain3 has NEVER sent.
    """
    m = g.envelope("CMD_GET_GAMERELAY_QUALITYCHECK_LIST")
    r = g.send(m, timeout=15)
    keys = ",".join(k for k in sorted(r) if k not in ("result", "msgid", "rqid"))
    print("  qualitychk[%s] -> %s keys=%s" % (tag, r.get("result"), keys))
    return r


def set_gamerelay_quality(g, tag, quality_list):
    """CMD_SET_GAMERELAY_QUALITY -> CmdSetGamerelayQuality.php

    Reporting half of QUALITY_TEST.  Request builder `FUN_078a55f0`, body
    written by `FUN_078a56d4`, which iterates a vector of 0x1f-byte entries
    and writes each one as:

        region      string
        quality     int
        last_update int

    into the array field `quality_list`.  The response is `result` only.
    """
    m = g.envelope("CMD_SET_GAMERELAY_QUALITY")
    m["quality_list"] = list(quality_list)
    r = g.send(m, timeout=12)
    print("  relay_qual[%s] n=%d -> %s %s"
          % (tag, len(quality_list), r.get("result"), describe(r)))
    return r


# --------------------------------------------------------------------------
# relay-quality MEASUREMENT (run #32, 2026-10-13).
#
# The 2026-10-12 capture does this at login: block 35 is
# CMD_GET_GAMERELAY_QUALITYCHECK_LIST, then blocks 38/39/40 are three
# CMD_SET_GAMERELAY_QUALITY reports carrying measured numbers.  chain3 had
# both functions but called NEITHER -- it replayed one stale captured body
# via room1.relay_quality, so every run reached game_session with
# sycom=P2P and gamerelay={NotImplement, port 0}: no relay was ever
# assigned, and therefore no DTLS game channel for the server to see.
#
# The list returns 63 regions.  quality_check_data_list[i].address is a
# COMPOUND field (",", "/" and "^" separate alternatives, a trailing
# "@nogs" flag is stripped) whose endpoints are UDP echo servers: they
# reflect the datagram byte-for-byte, so the round-trip time IS the
# quality figure the gate wants.  quality_threshold_1/2 (75 / 175 ms)
# classify it.  Verified live: 52/63 regions answered, report of all 52
# accepted NOERR.
# --------------------------------------------------------------------------
_PING = b"PINGCHAIN3QUALITYCHECK000000000000"

# the endpoint list fetched once at login, reused by the ROOM-TIME report so
# that step sends only CMD_SET_GAMERELAY_QUALITY -- exactly like capture block
# 63, which is a bare SET with no preceding GET.
_LAST_ROWS = []


def _addr_candidates(s):
    """compound quality-check address -> [(host, port), ...]"""
    out = []
    for grp in str(s).replace("^", ",").split(","):
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


def _echo_rtt(host, port, timeout=1.0, tries=2):
    """round-trip time of an echoed datagram, or None if it is not echoed."""
    import socket
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
                s.sendto(_PING, (ip, port))
                d, _ = s.recvfrom(2048)
            except (socket.timeout, OSError):
                continue
            if d != _PING:
                continue
            ms = int((time.time() - t0) * 1000)
            best = ms if best is None else min(best, ms)
    finally:
        s.close()
    return best


def quality_report(g, tag, workers=24, rows=None):
    """measure every region -> SET the results.

    `rows` is [(region, address), ...]; when None the qualitycheck list is
    fetched first (and cached in _LAST_ROWS for a later room-time report).
    Returns the SET reply, or None if there is nothing to report.
    """
    from concurrent.futures import ThreadPoolExecutor

    if rows is None:
        qc = get_qualitycheck_list(g, tag)
        cdl = qc.get("quality_check_data_list") or []
        rows = [(e.get("region", "?"), e.get("address", "")) for e in cdl]
        _LAST_ROWS[:] = rows
    if not rows:
        print("  quality_report[%s] no endpoints in list -> skipped" % tag)
        return None
    # capture blocks 38-40/63: the real client reports 46 of the 63 regions.
    # The 17 it omits are exactly the "@nogs" entries plus GLOBAL -- it never
    # measures those at all.
    rows = [r for r in rows if "@nogs" not in str(r[1])
            and _addr_candidates(r[1])]
    if not rows:
        print("  quality_report[%s] no measurable endpoints -> skipped" % tag)
        return None

    def one(row):
        reg, addr = row
        best = None
        for host, port in _addr_candidates(addr):
            ms = _echo_rtt(host, port)
            if ms is not None:
                best = ms if best is None else min(best, ms)
        return reg, best

    t0 = time.time()
    with ThreadPoolExecutor(max_workers=workers) as ex:
        measured = list(ex.map(one, rows))
    hit = sorted([(rg, ms) for rg, ms in measured if ms is not None],
                 key=lambda x: x[1])
    now = int(time.time())
    ql = [{"region": rg, "quality": ms, "last_update": now} for rg, ms in hit]
    print("  quality_report[%s] measured %d/%d regions in %.1fs"
          % (tag, len(hit), len(rows), time.time() - t0))
    if hit:
        print("    best: %s" % ", ".join("%s=%dms" % x for x in hit[:3]))
    if not ql:
        print("  quality_report[%s] nothing echoed -- reporting nothing" % tag)
        return None
    return set_gamerelay_quality(g, tag, ql)


def set_playdata_match(g, game_id, play_data, team_data, tag):
    """CMD_SET_PLAYDATA_MATCH -> CmdSetPlaydataMatch.php

    The in-match playdata command.  Request builder `FUN_078ba6a4`, body
    written by `FUN_078ba7c8`:

        play_data            string, default `NotImplement`
        match_team_play_data string, default `NotImplement`

    Response is `result` only.  This is the strongest remaining candidate for
    what the server means by `match_command_lack_mobile_timeout_sec` -- the
    mobile client must keep pushing match data, or the server times the match
    out and stamps an abnormal end (`DISCONN_HB`).
    """
    m = g.envelope("CMD_SET_PLAYDATA_MATCH")
    m["game_id"] = int(game_id) if game_id else 0
    m["play_data"] = play_data
    m["match_team_play_data"] = team_data
    r = g.send(m, timeout=12)
    print("  playdata[%s] -> %s %s" % (tag, r.get("result"), describe(r)))
    return r


def antenna_beat(g, tag, rid, gs, self_u, opp_u):
    """The LATENCY_MODE_ANNTENA_* mid-match heartbeat (11.1.0).  The real
    game polls CMD_GET_GAME_SESSION_CHECK_RES on an interval
    (AntennaInfoSendIntervalMs) and re-pushes CMD_SET_GAME_SESSION_CHECK_RES
    through the WHOLE match, not just once before START_GAME.  This is the
    liveness signal the server watches; the chain previously sent it only
    pre-match, so the server resolved the match DISCONN ~30 s in."""
    gr = as_map(gs.get("gamerelay"))
    sycom = gs.get("game_sycom")
    body = {
        "game_sycom": sycom if isinstance(sycom, str) else "",
        "error_code": "NOERR",
        "gamerelay": {"name": gr.get("name", ""),
                      "region": gr.get("region", ""),
                      "ip_addr": gr.get("ip_addr", ""),
                      "port": as_int(gr.get("port"))},
        "failed_reason": 0,
        "is_lobby": "YES",
        "room_id": {"id": rid},
        "statistical_data": {
            "user_id_list": [self_u, opp_u], "matching_num": 2,
            "answer": "", "antenna_min": as_int(gs.get("ping")),
            "error_code": "NOERR", "link_type": "",
            "create_session_time": as_int(gs.get("connecting_start_time")),
            "background_times": "",
        },
    }
    m = g.envelope("CMD_SET_GAME_SESSION_CHECK_RES")
    m.update(body)
    s = g.send(m, timeout=12)
    m2 = g.envelope("CMD_GET_GAME_SESSION_CHECK_RES")
    m2.update({"room_id": {"id": rid}, "is_lobby": "YES",
               "game_entry_user_list": [self_u, opp_u]})
    q = g.send(m2, timeout=12)
    print("  antenna[%s] set=%s get=%s finished=%s"
          % (tag, s.get("result"), q.get("result"), q.get("is_check_finished")))
    # The 11.1.0 parser for this reply (FUN_078a99ac) reads a
    # gamerelay_list {name,region,ip_addr,port,event_id} -- that is where
    # the DTLS relay the match is played over comes from.  Dump every
    # non-envelope key so the relay address is never thrown away again.
    if any(k not in ("result", "msgid", "rqid", "show_info",
                     "maintenance_end_time") for k in s):
        print("  antenna-set-body[%s] %s" % (
            tag, json.dumps({k: v for k, v in s.items()
                             if k not in ("result", "msgid", "rqid")},
                            ensure_ascii=False, default=str)[:2500]))
    if any(k not in ("result", "msgid", "rqid", "show_info",
                     "maintenance_end_time", "is_check_finished") for k in q):
        print("  antenna-get-body[%s] %s" % (
            tag, json.dumps({k: v for k, v in q.items()
                             if k not in ("result", "msgid", "rqid")},
                            ensure_ascii=False, default=str)[:2500]))
    return s, q


def entry_side(g: Gate, rid: int, side: str, leader: bool) -> dict:
    m = g.envelope("CMD_SET_ROOM_USER_ENTRY_SIDE")
    m["room_id"] = {"id": rid}
    m["entry_side"] = side
    m["is_entry_side_leader"] = "YES" if leader else "NO"
    return m


EP_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "peer_endpoint.json")


def endpoint_net(tag: str = "owner") -> dict:
    """NET plus the udp_punch endpoint for THIS identity.

    The phone hole-punches to whatever we advertise here; empty NET is
    why it showed 'Unable to connect'.  peer_endpoint.json is written
    by udp_punch.py from a STUN binding on the same socket it listens
    on.

    tag selects which socket we are advertising.  Both bots live on this
    one VM behind the one IP 3.80.79.52, so a shared file made both
    advertise the identical ip:port -- two peers at a single address is
    impossible NAT proof, and the server stamped abnormal=DISCONN_HB
    within 2 s of START_GAME.  Each identity binds its own local port
    and does its own STUN: owner :44000, bot :44001.

    2026-10-12 (run #21): the real captured client keeps host_address
    (LOCAL, e.g. 172.17.0.2) DISTINCT from reflexive_address (its public
    IP).  We were copying the public ip into BOTH fields.  Now each bot
    advertises its own loopback host_address (127.0.0.2 owner /
    127.0.0.3 bot) while reflexive stays the public STUN result -- the
    two address_ipv4 blocks now differ in host, port, and local IP, which
    is the shape the server expects.  NOTE: this corrects the SHAPE; the
    public reflexive is still shared (one VM, one egress IP), which is a
    hard limit for true P2P on this host.
    """
    net = dict(NET)
    ep_file = EP_FILE if tag == "owner" else \
        os.path.join(os.path.dirname(os.path.abspath(__file__)),
                     "peer_endpoint_bot.json")
    # 2026-10-13 (run #38): take the capture's endpoint profile VERBATIM.
    # decode_flows --cmd=CMD_GET_GAME_SESSION shows the real match's two
    # entries differing in EVERY field:
    #   A  host 172.17.0.2:33001       reflexive 52.165.63.2:42011  nat 270532787
    #   B  host 100.88.219.229:1162    reflexive 197.211.52.3:49893 nat 268435711
    # chain3 sent loopback hosts AND THE SAME nat_type for both players, so
    # the ntl pair looked like one device wearing two user_ids.  host_* now
    # matches the capture byte-for-byte; only reflexive_* stays ours (it must,
    # or the server cannot correlate the keepalive we actually beat from).
    PROFILE = {"owner": ("172.17.0.2", 33001, 270532787),
               "bot": ("100.88.219.229", 1162, 268435711)}
    local_host, cap_hport, cap_nat = PROFILE.get(
        tag, PROFILE["owner"])
    try:
        with open(ep_file, encoding="utf-8") as f:
            ep = json.load(f)
        _lp = ep.get("local_port") or ep["port"]
        _rport = int(ep.get("port") or (_lp + 8010))
        # 2026-10-12 (run #26 --pinpoint): abnormal=DISCONN_HB is stamped
        # the INSTANT the owner's CMD_START_GAME lands (pre-botSG probe:
        # gameend=INVALID/abnormal=DISCONN_HB before the bot kicks off) --
        # not a ~30s heartbeat timeout.  So the trigger is the connection
        # proof the server evaluates AT kickoff, and ours was
        # self-contradictory: address IS translated (loopback -> public)
        # but the port is NOT (host_port==reflexive_port), and nat_type=1
        # is a trivial sentinel.  A real NAT translates BOTH (capture:
        # host 172.17.0.2:33001 -> reflexive 52.165.63.2:42011,
        # nat_type 270532787).  Match that SHAPE: distinct reflexive port
        # + the capture's nat_type.  (Run #22 only changed host_address to
        # loopback and left port/nat_type contradictory -- it did NOT
        # actually test a believable NAT, so the endpoint hypothesis was
        # never truly ruled out.)
        #
        # 2026-10-13 (run #37): that fix was a NO-OP and this is why.  Run
        # #30->#31 pointed reflexive_port at the real STUN beat source to
        # restore keepalive correlation -- correct -- but the endpoint
        # files carry port == local_port (44000/44001, same socket), so
        # host_port == reflexive_port survived untouched.  The run had
        # traded one half of the requirement for the other: run #22 had
        # ports differing with a broken beat correlation, run #31 had a
        # working beat with ports identical.  reflexive_port must stay the
        # beat source, so host_port is the only field that can move:
        # advertise the capture's local port.  (Run #37 used 33001/33002 --
        # distinct, but still invented; this uses the capture's 33001/1162.)
        net.update({"host_address": local_host,
                    "host_port": cap_hport,
                    "reflexive_address": ep["ip"],
                    "reflexive_port": _rport,
                    "nat_type": cap_nat})           # capture: 270532787/268435711
    except (OSError, KeyError, ValueError, TypeError):
        net.update({"host_address": local_host})
    return net


def match_ready(g: Gate, rid: int, tag: str = "owner") -> dict:
    # Real captured values (accepted -> NOERR): is_single_matching "NO",
    # gamerelay_measure_result "COMPLETE".  The old builder sent "YES" /
    # "MEASUREING" -- the latter is a state the server has not reached, and
    # declaring single-matching in a 2-player friend room is wrong.
    m = g.envelope("CMD_SET_ROOM_MATCH_READY")
    m["room_id"] = {"id": rid}
    m["is_single_matching"] = "NO"
    m["gamerelay_measure_result"] = "COMPLETE"
    m["address_ipv4"] = endpoint_net(tag)
    # capture block 98: IPv6 is completely inert in the real client --
    # "::" and 0 everywhere.  chain3 copied the IPv4 NET here, which sent
    # host_port 1 / nat_type 1 as a live-looking v6 candidate.
    m["address_ipv6"] = dict(NET6)
    return m


def game_session(g: Gate, rid: int) -> dict:
    # capture block 102.  TWO fields chain3 got wrong, and together they
    # explain every run landing on sycom=P2P / gamerelay=NotImplement:
    #   session_use_kind "LOBBY_IN_ROOM"  -- never sent at all, so the gate
    #     had no idea which kind of session to resolve;
    #   room_id as {"id": n}              -- chain3 sent [str(rid)], a list
    #     of strings, unlike every other command in the flow.
    # The real reply carries game_sycom "SC" plus a relay ip_addr that is a
    # 145-char compound "host:5735,host:5736,host:443,token" (port field is
    # the index 1) -- the dialable DTLS endpoint.
    m = g.envelope("CMD_GET_GAME_SESSION")
    m["session_use_kind"] = "LOBBY_IN_ROOM"
    m["room_id"] = {"id": rid}
    return m


def turn_server_list(g: Gate) -> dict:
    """POSTROOM_FLOW.md step 7 -- the P2P DTLS/TURN rendezvous fetch.

    Historic note: chain3 used to send this and got ERR_INVALIDARG/GKZX-,
    so it was stripped in run #21 and gap #1 was closed as "relay-only,
    never sent in P2P matches".  That conclusion came from the WRONG body:
    the bare envelope and six room_id/sycom/is_lobby/ping variants.  The
    schema that actually answers (ROOM-SCHEMA.md, "CONFIRMED WORKING") is

        {"turn_account_param": "", "turn_time_limit": 3600}

    verified live 2026-10-13 -> NOERR with turn_server_list
    [{zone,address,port,tls_port}] and turn_account{id,pw,origin,
    server_certificate}.  Per the flow doc it must follow GET_GAME_SESSION,
    which is exactly where this is called.

    turn_time_limit is the credential's lifetime in SECONDS, and the returned
    turn_account.id is its unix expiry (measured: limit 0 -> id = now+1s,
    60 -> now+62s, 3600 -> now+3604s).  chain3 sent 0 for runs #34-36, so the
    TURN password was expired the instant it arrived -- every signed STUN
    Allocate built on it came back 401 Unauthorized.  Sending 3600 keeps it
    alive for the whole match.
    """
    m = g.envelope("CMD_GET_TURN_SERVER_LIST")
    m["turn_account_param"] = ""
    m["turn_time_limit"] = 3600
    return m


def as_map(v):
    if isinstance(v, dict):
        return dict(v)
    if isinstance(v, list) and v and isinstance(v[0], dict):
        return dict(v[0])
    return {}


def as_int(v, default=0):
    return v if isinstance(v, int) and not isinstance(v, bool) else default


def heartbeat(g: Gate, msec: int = 5000) -> dict:
    m = g.envelope("CMD_HEARTBEAT_GRPC")
    m["heartbeat_interval_msec"] = msec
    return g.send(m)


def report_log(log_url: str, rtype: str, timeout: int = 10,
               retries: int = 3) -> dict:
    """POST one NTL ReportLog entry -- the leg chain3 never spoke.

    The real client logs its P2P session lifecycle to the URL the gate hands
    back in PUT_LOG_URL, on ntl.service.konami.net (a DIFFERENT host than the
    gate itself):

        type=pds   P2P session open
        type=pde   P2P session close
        type=uds   UDP session open
        type=ude   UDP session close

    Body form, byte-for-byte from the capture:
        type=<t>&prefix=<epoch>_<seq>_<hexid>_<hexid>_<n>&ver=4&dat=<hex>

    ``dat`` is hex of the NTL SDK's own diagnostic log.  Decoded from a real
    match it opens with:

        ## NTLInfo
        ${"libVer":"1.17.1-Android-13"}

    The client never announced ``pds`` in ANY earlier chain run, so from the
    server's side our session was indistinguishable from one that never
    existed -- which is exactly what ``abnormal=DISCONN_HB`` asserts.

    Returns the parsed STATUS lines, or {"error": ...}.
    """
    import binascii
    import socket
    import time
    import urllib.parse

    now = int(time.time())
    # prefix shape from the capture: <epoch>_<seq>_<8hex>_<4hex>_<n>
    prefix = "%d_1_%08x_%04x_1" % (now, os.getpid() & 0xffffffff,
                                   now & 0xffff)
    dat_txt = "## NTLInfo\n${\"libVer\":\"1.17.1-Android-13\"}\n"
    body = urllib.parse.urlencode({
        "type": rtype,
        "prefix": prefix,
        "ver": "4",
        "dat": binascii.hexlify(dat_txt.encode()).decode(),
    }).encode()

    url = log_url or "http://ntl.service.konami.net/ntl/api/PES2022/ReportLog.php"
    u = urllib.parse.urlsplit(url)
    host, port = u.hostname or "ntl.service.konami.net", u.port or 80
    path = u.path or "/ntl/api/PES2022/ReportLog.php"
    last = None
    for i in range(retries):
        t0 = time.time()
        try:
            s = socket.create_connection((host, port), timeout=timeout)
            try:
                s.settimeout(timeout)
                head = ("POST %s HTTP/1.1\r\n"
                        "Host: ntl.service.konami.net\r\n"
                        "Accept: */*\r\n"
                        "Content-Length: %d\r\n"
                        "Content-Type: application/x-www-form-urlencoded"
                        "\r\n\r\n" % (path, len(body)))
                s.sendall(head.encode() + body)
                chunks = []
                while True:
                    d = s.recv(4096)
                    if not d:
                        break
                    chunks.append(d)
                raw = b"".join(chunks)
            finally:
                s.close()
            head_b, _, body_b = raw.partition(b"\r\n\r\n")
            out = {"_type": rtype, "_elapsed": round(time.time() - t0, 2)}
            for ln in body_b.decode("latin1").splitlines():
                if ":" in ln:
                    k, v = ln.split(":", 1)
                    out[k.strip()] = v.strip()
            out["_http"] = (head_b.split(b"\r\n", 1)[0]
                            .decode("latin1", "replace"))
            if out.get("STATUS") == "200":
                return out
            last = "STATUS=%s" % out.get("STATUS")
        except Exception as e:                                   # noqa: BLE001
            last = "%s %s" % (type(e).__name__, e)
        time.sleep(0.8 * (i + 1))
    return {"_type": rtype, "error": last or "no response"}


def score_poll(g: Gate, game_id, tag: str) -> None:
    """Read-only probe: has the server stamped the forfeit yet?"""
    m = g.envelope("CMD_CHECK_GAME_RESULT")
    m["game_id"] = game_id
    c = g.send(m)
    gr = c.get("game_end_result") or {}
    mr = gr.get("match_result") or {}
    sd = mr.get("score_data") or {}
    print("poll [%s] -> %s reason=%s/%s score=%s-%s"
          % (tag, c.get("result"), mr.get("gameend_reason"),
             mr.get("abnormalend_reason"), sd.get("home_score"),
             sd.get("away_score")))


def stadium(omit_empty: bool = False) -> dict:
    """custom_stadium map.  The SET serializer (libUE4 0x76d59f0..) writes
    every key unconditionally EXCEPT pitchside_objects, whose setkey sits
    inside a b.eq-guarded loop (0x76d5c28): empty vector -> key omitted."""
    d = {"stadium_id": 0, "custom_stadium_name": "",
            "stadium_color1": 0, "stadium_color2": 0, "stadium_color3": 0,
            "stadium_color4": 0, "goalnet_pattern": 0, "goalnet_color1": 0,
            "goalnet_color2": 0, "pitch_pattern": 0, "entrance_set": 0,
            "bill_set": 0, "goal_effect1": 0,
            "goal_effect2": 0, "kickoff_effect": 0,
            "has_invalid_assets": "NO"}
    if not omit_empty:
        d["pitchside_objects"] = []
    return d


def gcd() -> dict:
    """CMD_CHANGE_GAMEPHASE nested game_check_data (phase_chain.py proven)."""
    return {"match_time_frame": 0, "match_time_tick": 0, "com_stop_info": 0,
            "entry_check_data": 0, "ball_move_max_speed": 0,
            "gameplayer_parameter_check_data_list": [],
            "opponent_gameplayer_parameter_check_data_list": [],
            "custom_stadium": stadium(),
            "golazo_info": {"golazo_count_list": []}}


def change_phase(g: Gate, game_id, phase: str, gtimer: int) -> dict:
    m = g.envelope("CMD_CHANGE_GAMEPHASE")
    m["game_id"] = game_id
    m["phase"] = phase
    m["gtimer"] = gtimer
    m["game_check_data"] = gcd()
    return g.send(m)


def add_score(g: Gate, game_id, goal_user, side, scorer,
              minute: int) -> dict:
    m = g.envelope("CMD_ADD_SCORE")
    m.update(game_id=game_id, goal_user_id=goal_user, goal_side=side,
             goal_gameplayer_id=scorer, goal_player_side=side,
             assist_user_id=goal_user, assist_side=side,
             assist_gameplayer_id=scorer, assist_player_side=side,
             gtimer=minute * 60, phase="END", match_minute=minute)
    return g.send(m)


def add_foul(g: Gate, game_id, card_user, side, card_player,
             minute: int, phase: str) -> dict:
    """CMD_ADD_FOUL -- body from the real capture (block 122).

    Real match sent exactly one foul, at 92' in 2ND_30MIN: a carded player
    (card_user_id/card_side/card_gameplayer_id), card_kind NONE, an empty
    injury block, gtimer=match_minute*60, phase, match_minute.  chain3 never
    sent a foul; the capture shows it is part of a complete match.
    """
    gidobj = card_player or {}
    m = g.envelope("CMD_ADD_FOUL")
    m.update(game_id=game_id, card_user_id=card_user, card_side=side,
             card_gameplayer_id={"id": gidobj.get("id"),
                                 "serial": gidobj.get("serial")},
             card_kind="NONE", injury_user_id=0, injury_side="HOME",
             injury_gameplayer_id={"id": 0, "serial": 0},
             gtimer=minute * 60, phase=phase, match_minute=minute)
    return g.send(m)


# Real starting-XI positions, in the order the captured client fielded them
# (4-3-3): used because the bot's squad records carry attributes but not a
# live position.  Bench entries always get "BENCH".
XI_POSITIONS = ["GK", "CB", "CB", "LSB", "ST", "RWG", "RSB", "CB", "OMF",
                "LWG", "CF"]


def _rating_of(p: dict) -> int:
    """overall x10, the captured client's scale (60->600, 65->650)."""
    ao = p.get("averaged_overall")
    if isinstance(ao, (int, float)) and ao:
        return int(ao * 10)
    return 600


def sgr_entry(p: dict, idx: int) -> dict:
    """One myteam_player_list entry, 11 keys, matching the captured client.

    Real capture: starters play_time=90 / is_join_game=YES / a real position
    and rating; bench play_time=0 / is_join_game=NO / position BENCH /
    rating 0.  The old builder always sent play_time=90 and position=GK for
    every player, including bench -- that mismatch is now gone.
    """
    gidobj = p.get("gameplayer_id") or {}
    starting = idx < 11
    return {"gameplayer_id": {"id": gidobj.get("id"),
                              "serial": gidobj.get("serial")},
            "rating": _rating_of(p) if starting else 0,
            "play_time": 90 if starting else 0,
            "position": XI_POSITIONS[idx] if starting else "BENCH",
            "is_starting_member": "YES" if starting else "NO",
            "is_join_game": "YES" if starting else "NO",
            "oap": 0, "base_value": 0, "is_man_of_the_match": "NO"}


def sgr_stats(score: int, poss: int, shots: int, on: int) -> dict:
    return {"score": score, "ball_possession": poss, "shots": shots,
            "shots_on_goal": on, "faul": 0, "faul_offside": 0,
            "corner_kick": 0, "free_kick": 0, "pass_success_rate": 0,
            "cross": 0, "pass_cut": 0, "tackle": 0, "save": 0}


def _check_entry(p: dict) -> dict:
    """One gameplayer_parameter_check_data_list entry.

    2026-10-13 (reverse_checksum.py, 46/46 capture pairs): check_sum is
    sum(parameters) minus parameters[59] and parameters[60] -- par[60] is
    always 0 and par[59] carries the whole sum-minus-check difference for
    every player, own list and opponent list alike.  The old builder sent
    `2000 + pid % 500`, which the server recomputes from the squad it
    stored itself; that mismatch is the run-#40 CHEAT verdict.
    parameters[147] rides on the squad_list entries, so compute it for
    real; the old deterministic shape survives only as a fallback when the
    array is absent.  max_speed is a match measurement (capture starters
    ~19.5k..32.9k, bench 0); the old 25000-based range missed the low end.
    """
    gidobj = p.get("gameplayer_id") or {}
    pid = gidobj.get("id") or 0
    starting = bool(p.get("_starting"))
    par = p.get("parameters")
    if isinstance(par, list) and len(par) > 60 and \
            all(isinstance(v, int) for v in par):
        cs = sum(par) - par[59] - par[60]
    else:
        cs = 2000 + (int(pid) % 500)
    return {"gameplayer_id": {"id": gidobj.get("id"),
                              "serial": gidobj.get("serial")},
            "check_sum": cs,
            "max_speed": (19000 + (int(pid) % 14000)) if starting else 0}


def sgr_request(game_id, mine, theirs, home_score, away_score,
                abnormal: str, elapsed_sec: int = 0, tick_ms=None) -> dict:
    """CMD_SET_GAME_RESULT body -- three objects at body root
    (match_result / game_check_data / analyst_set_game_result_info), PLUS
    the envelope-level root game_id added by the caller.

    REBUILT 2026-10-12 from the real captured client (cap/flows-final.log,
    accepted result -> result:NOERR).  The previous body was inferred from a
    serializer disassembly that said "empty source vector -> key OMITTED";
    the live capture proves the OPPOSITE.  The real client sends these keys
    with EMPTY lists, and omitting them is what produced ERR_INVALIDARG:
        achievement_progress_list: []
        owngoal_user_list: []
        tour_pvp_bonus_result_list: []
        behind_flag: ["YES","NO"]            (a 2-string list, not a flag)
        opp_gameplayer_id_list: [ {id,serial:0} x11 ]
    error_code is "_0x0", not "0".  game_check_data carries BOTH parameter
    lists (23 entries each) and a real ball_move_max_speed / match_time_tick.
    analyst carries a real match_json string, advice_info_match.advice_info_list
    as [], and is_invalid_advice "YES".
    """
    # mark starters so _check_entry and sgr_entry agree on who played.
    # the opponent XI uses the same first-11 convention: the two reports
    # are cross-checked against each other (their mine[:11] played), and
    # the capture's opp list carries 11 nonzero max_speeds while run #40
    # sent all 46 of the opponent's as 0.
    for i, p in enumerate(mine):
        p["_starting"] = i < 11
    players = [sgr_entry(p, i) for i, p in enumerate(mine)]
    my_checks = [_check_entry(p) for p in mine]
    for i, p in enumerate(theirs):
        p["_starting"] = i < 11
    opp_checks = [_check_entry(p) for p in theirs]
    npar = sum(1 for p in mine + theirs
               if isinstance(p.get("parameters"), list)
               and len(p["parameters"]) > 60)
    print("sgr checksums: %d/46 from real parameters" % npar)

    match_result = {
        "game_id": game_id,
        "abnormalend_reason": abnormal,
        "is_problem": "NO",
        "user_network_status": {"is_stun_keep_alive_failed": "NO",
                                "is_network_blocked_disconn": "NO",
                                "is_background_timeout": "NO",
                                "is_background_at_match": "NO"},
        "ex_flag": "NO", "pk_flag": "NO", "error_code": "_0x0",
        "myteam_player_list": players,
        "match_stat_side_info_list": [sgr_stats(home_score, 62, 2, 1),
                                      sgr_stats(away_score, 38, 0, 0)],
        # the three lists below are sent EMPTY by the real client -- this is
        # the fix for the body-completeness ERR_INVALIDARG.
        "achievement_progress_list": [],
        "use_team_style": "TEAM_STYLE_SHORT_COUNTER",
        "owngoal_user_list": [],
        "event_record": 0, "restart_num": 0, "control_style": 0,
        "coop_score": {"total": 0, "shoot": 0, "pass": 0, "dribble": 0,
                       "offense_positioning": 0, "duel": 0,
                       "defense_positioning": 0},
        "behind_flag": ["YES", "NO"],
        "tour_pvp_bonus_result_list": [],
        "ml_event_match_bonus": {"count": 0,
                                 "golazo_info": {"golazo_count_list": []}},
        "opp_gameplayer_id_list": [
            {"id": (p.get("gameplayer_id") or {}).get("id"), "serial": 0}
            for p in theirs[:11]],
        "use_setting_multi_formation": "YES",
    }
    game_check = {
        "match_time_frame": 0,
        # run #41: the old body sent elapsed*60 (e.g. 23340, "23 seconds")
        # while the capture carries 822300 -- wall-clock ms of a real
        # ~13.7 min match.  The server knows both arrival instants, so a
        # 23 s claim for a ~410 s match is a second CHEAT-grade mismatch.
        # tick_ms (measured kickoff -> SET send) is passed by the caller;
        # without it the old behavior is kept.
        "match_time_tick": (tick_ms if tick_ms is not None
                            else (int(elapsed_sec) * 60 or 822300)),
        "com_stop_info": 0,
        "entry_check_data": 0, "ball_move_max_speed": 117283,
        "gameplayer_parameter_check_data_list": my_checks,
        "opponent_gameplayer_parameter_check_data_list": opp_checks,
        "custom_stadium": {"stadium_id": 0, "custom_stadium_name": "NotImplement",
                           "stadium_color1": 0, "stadium_color2": 0,
                           "stadium_color3": 40, "stadium_color4": 40,
                           "goalnet_pattern": 1, "goalnet_color1": 40,
                           "goalnet_color2": 40, "pitch_pattern": 1,
                           "entrance_set": 1, "bill_set": 1,
                           "pitchside_objects": [], "goal_effect1": 0,
                           "goal_effect2": 0, "kickoff_effect": 0,
                           "has_invalid_assets": "NO"},
        "golazo_info": {"golazo_count_list": [0] * 11},
    }
    # analyst: the captured client sends a real match_json string, an empty
    # advice_json, advice_info_match with an EMPTY advice_info_list, and
    # is_invalid_advice "YES" (not the ctor placeholder "NotImplement").
    match_json = json.dumps({
        "Dribble": {"Neutral": 524.0, "Normal": 141.0, "Finess": 37.0,
                    "Dash": 0.0},
        "Pass": {"Short": 2.0, "Through": 55.0, "Long": 1.0, "Cross": 0.0,
                 "CrossGrnd": 0.0, "ThroughFly": 8.0},
        "Shoot": {"Normal": 0.0, "Control": 0.0, "Impact": 0.0, "Loop": 0.0},
        "Defence": {"Delay": 507.0, "Matchup": 78.0, "Press": 0.0},
        "OperationType": "Virtual", "ModernControl": "YES",
        "OffenseInstructions": "YES", "DeffenseInstructions": "NO",
    }, separators=(",", ":"))
    analyst = {"match_json": match_json, "advice_json": "",
               "advice_info_match": {"game_id": game_id,
                                     "advice_info_list": []},
               "is_invalid_advice": "YES"}
    return {"match_result": match_result, "game_check_data": game_check,
            "analyst_set_game_result_info": analyst}


def user_squad(g: Gate, target: int) -> dict:
    m = g.envelope("CMD_GET_USER_SQUAD")
    m["target_user_id"] = target
    return m


def user_data_sync(g: Gate, side: str, user_name: str) -> dict:
    """CMD_USER_DATA_SYNC -- MODE_ANNTENA step (flow item 18), sent by BOTH
    clients after the session-check report and before CMD_GET_GAMEID.
    Body keys extracted from the 11.1.0 request builder (FUN_07eadd40 /
    FUN_07eb3f10, serial order 0x07dae148..0x07dae5ec):
      name, pad_no, np_account_id, xuid_one, platform_id,
      platform_user_name, avator{is_already_set, player_id, special_id,
      background_id, special_id_background, is_enable_player,
      is_enable_background, material_key_player, material_key_background},
      user_info{user_id, platform_kind, is_platform_game_session},
      side, guest_num
    """
    m = g.envelope("CMD_USER_DATA_SYNC")
    m.update({
        "name": user_name,
        "pad_no": 0,
        "np_account_id": "",
        "xuid_one": "",
        "platform_id": "ANDROID",
        "platform_user_name": user_name,
        "avator": {
            "is_already_set": "NO", "player_id": 0, "special_id": 0,
            "background_id": 0, "special_id_background": 0,
            "is_enable_player": "YES", "is_enable_background": "YES",
            "material_key_player": "", "material_key_background": "",
        },
        "user_info": {"user_id": g.uid, "platform_kind": "ANDROID",
                      "is_platform_game_session": "NO"},
        "side": side,
        "guest_num": 0,
    })
    return m


def team_data_sync(g: Gate, side: str, json_data: str) -> dict:
    """CMD_TEAM_DATA_SYNC -- MODE_PRE_MENU step (flow item 21), sent by
    BOTH clients right before CMD_START_GAME (the squad/formation/kits
    screen the user sees).  Body (11.1.0 FUN_08244838/FUN_08245268):
      {side, json_data} -- json_data is the team/squad blob as a JSON
      string (server stores it for the opponent-squad view).
    """
    m = g.envelope("CMD_TEAM_DATA_SYNC")
    m["side"] = side
    m["json_data"] = json_data
    return m


def start_game(g: Gate, game_id, team_id, home, away,
               side: str = "HOME") -> dict:
    m = g.envelope("CMD_START_GAME")
    # Real captured value is "MYCLUB_LOBBY_ROOM_MATCH_1VS1" (accepted).
    # The old "LOBBY_ROOM_MATCH_1VS1" is a different (non-myclub) category.
    m["match_category"] = "MYCLUB_LOBBY_ROOM_MATCH_1VS1"
    m["game_id"] = game_id
    m["side"] = side
    m["player_list_home"] = home
    m["player_list_away"] = away
    m["team_id"] = team_id
    m["is_vs_aimatch"] = "NO"
    return m


def game_id_of(g: Gate, rid: int) -> dict:
    m = g.envelope("CMD_GET_GAME_ID")
    m["room_id"] = {"id": rid}
    return g.send(m)


def check_match_enable(g: Gate) -> dict:
    m = g.envelope("CMD_CHECK_MATCH_ENABLE")
    m["event_id"] = 0
    return g.send(m)


def game_team_list(g: Gate) -> dict:
    return g.send(g.envelope("CMD_GET_GAME_TEAM_LIST"))


def get_game_id(g: Gate, rid: int):
    """Try the builder form first, then server-side fallbacks (one per rqid)."""
    forms = [
        ("map-int",  {"room_id": {"id": rid}}),
        ("flat-int", {"room_id": rid}),
        ("str",      {"room_id": str(rid)}),
        ("arr-str",  {"room_id": [str(rid)]}),
        ("map-str",  {"room_id": {"id": str(rid)}}),
        ("roominfo", {"mode": "CUSTOM", "id": 0, "room_id": {"id": rid},
                      "event_id": 0, "user_compe_id": 0,
                      "is_room_search": "NO"}),
    ]
    for label, extra in forms:
        m = g.envelope("CMD_GET_GAME_ID")
        m.update(extra)
        r = g.send(m)
        gid = find_key(r, "game_id")
        print("  form %-9s -> %-16s game_id=%s"
              % (label, r.get("result"), "yes" if gid is not None else "no"))
        if r.get("result") == "NOERR" and gid is not None:
            return gid
        time.sleep(PACE)
    return None


def squad_list(sq: dict) -> list:
    """[player records] for CMD_START_GAME.

    CMD_USER_SQUAD returns the players in TWO different containers:

      * squad_data.player_list  -- the GAMEPLAN view.  IDs only, by design:
        no attributes at all.  This is what chain3 used to read, and it then
        stripped each entry down to a bare {gameplayer_id}.
      * top-level player_list   -- the full records, each with
        parameters[147], level_info, games, goal, rarity, etc.

    The server's CMD_START_GAME reply echoes each entry back as
    {gameplayer_id, parameters, averaged_overall} -- that is the shape it
    expects -- and it fills whatever we omit with zeros.  The long-standing
    `averaged_overall: 0` / `team_id: 0` in that echo was never a server
    state: it was us transmitting 23 anonymous ids with no attributes, so the
    gate could not field a real team.  (Both accounts DO have complete
    squads: owner = Sunderland RWB, team 396; bot = PLink Bot, team 119 --
    23 players each with full attribute sets and a coach.)

    Keep the gameplan's ordering, but source the attributes from the full
    records.
    """
    full = {}
    for p in (sq.get("player_list") or []):
        gid = (p.get("gameplayer_id") or {})
        if gid.get("id"):
            full[gid["id"]] = p

    out = []
    for p in ((sq.get("squad_data") or {}).get("player_list") or []):
        gid = p.get("gameplayer_id") or {}
        if not gid.get("id"):
            continue
        rec = full.get(gid["id"], {})
        entry = {"gameplayer_id": {"id": gid["id"], "serial": gid["serial"]}}
        # attributes first: they are what the gate actually needs to field
        # the team, and they are absent from the gameplan view entirely.
        prm = rec.get("parameters")
        if isinstance(prm, list) and prm:
            entry["parameters"] = list(prm)
        ao = rec.get("averaged_overall") or p.get("averaged_overall")
        if ao:
            entry["averaged_overall"] = ao
        out.append(entry)
    return out


def room_state(g: Gate, rid: int) -> dict:
    m = g.envelope("CMD_GET_ROOM_INFO")
    m.update({"mode": "CUSTOM", "id": 0, "room_id": {"id": rid},
              "event_id": 0, "user_compe_id": 0, "is_room_search": "NO"})
    r = g.send(m)
    return (r.get("room_info") or {}) if r.get("result") == "NOERR" else {}


# ------------------------------------------------------------------- run ---

def main() -> int:
    if "--live" not in sys.argv:
        print("offline check: imports ok, use --live")
        return 0
    t0 = time.time()
    reqs = load_capture()[0]
    try:
        with open(BOT_FILE, encoding="utf-8") as fh:
            bot = json.load(fh)
    except Exception:                                  # noqa: BLE001
        bot = {}
    if not (bot.get("user_id") and bot.get("auth_code")):
        print("bot identity MISSING (run mint.py)")
        return 1

    def pace():
        time.sleep(PACE)

    owner = Gate()
    ok, r = login(owner, reqs)
    print("owner login  -> %s" % (r.get("result") if not ok else "NOERR"))
    if not ok:
        print("  %s" % describe(r))
        return 1
    pace()
    q = quality_report(owner, "owner")
    print("owner quality-> %s" % (q or {}).get("result"))
    if not q or q.get("result") != "NOERR":
        return 1
    pace()
    # capture block 51: CMD_CREATEJOIN_ROOM already carries the owner's real
    # NAT profile -- host 172.17.0.2:33001 -> reflexive 52.165.63.2:42011,
    # nat_type 270532787 -- identical to what block 98 re-sends at ready.
    # chain3 was creating the room with room1's EMPTY CFG defaults (""/1),
    # so the room existed before any connection proof was ever advertised.
    _ep = endpoint_net("owner")
    for _k in ("host_address", "host_port", "reflexive_address",
               "reflexive_port", "nat_type"):
        CFG["a4." + _k] = _ep[_k]
        CFG["a6." + _k] = NET6[_k]
    o = create_room(owner)
    rid = ((o.get("room_id") or {}).get("id")) if o.get("result") == "NOERR" else None
    print("create room  -> %s  room_id=%s" % (o.get("result"), rid))
    if not rid:
        print("  %s" % describe(o))
        return 1
    pace()

    botg = Gate()
    okb, rb = login_bot(botg, reqs, bot)
    print("bot login    -> %s" % (rb.get("result") if not okb else "NOERR"))
    if not okb:
        print("  %s" % describe(rb))
        return 1
    pace()
    qb = quality_report(botg, "bot  ")
    print("bot quality  -> %s" % (qb or {}).get("result"))
    if not qb or qb.get("result") != "NOERR":
        return 1
    pace()

    # -- the capture's keepalive, open BEFORE the room exists: one gRPC
    #    CommandStream per identity, beating every 15 s for the whole run
    #    (the real phone's stream outlives every stall in the capture).
    #    The old HTTP CMD_HEARTBEAT_GRPC fatals (500, empty) -- stream only.
    beaters = []
    for tag, gg in (("owner", owner), ("bot  ", botg)):
        bs = BeatStream(gg, 15.0)
        if bs.open():
            print("gRPC beats [%s] -> open (15s cadence)" % tag)
            beaters.append((tag, bs))
            threading.Thread(target=bs.run, args=(420.0,),
                             daemon=True).start()
        else:
            print("gRPC beats [%s] -> OPEN FAILED: %s" % (tag, bs.dead))
        pace()

    # -- the proven join ladder ----------------------------------------
    a = sendreq(botg, 0, rid)
    print("bot sendreq  -> %s" % a.get("result"))
    pace()
    b = sendreq(owner, botg.uid, rid)
    print("owner invite -> %s" % b.get("result"))
    pace()
    c = getrequested(botg, owner.uid)
    print("bot getreq   -> %s" % c.get("result"))
    if c.get("result") != "NOERR":
        print("  %s" % describe(c))
        return 1
    pace()
    jb = join_body(botg, rid)
    jb["mode"] = "CUSTOM"
    e = botg.send(jb)
    print("bot join     -> %s" % e.get("result"))
    if e.get("result") != "NOERR":
        print("  %s" % describe(e))
        return 1
    pace()
    n = num_users(owner, rid)
    print("seated       -> %s" % n)
    if n != 2:
        return 1
    pace()

    # -- squad reads ----------------------------------------------------
    sq_o = owner.send(user_squad(owner, owner.uid))
    print("owner squad  -> %s" % sq_o.get("result"))
    if sq_o.get("result") != "NOERR":
        print("  %s" % describe(sq_o))
        return 1
    pace()
    sq_b = botg.send(user_squad(botg, botg.uid))
    print("bot squad    -> %s" % sq_b.get("result"))
    if sq_b.get("result") != "NOERR":
        print("  %s" % describe(sq_b))
        return 1
    pace()

    team_data = sq_o.get("team_data") or {}
    team_id = team_data.get("base_team_id") if isinstance(team_data, dict) else None
    if team_id is None:
        team_id = find_key(sq_o, "base_team_id")
    print("team_id      -> %s" % (type(team_id).__name__ if team_id is not None else "MISSING"))
    if team_id is None:
        return 1

    # -- entry sides ----------------------------------------------------
    for side, leader, g in (("HOME", True, owner), ("AWAY", False, botg)):
        who = "owner" if g is owner else "bot  "
        _, okd = diag(g, lambda: entry_side(g, rid, side, leader))
        if not okd:
            print("entry_side [%s] input rejected -- stopping" % who)
            return 1
        pace()
        es = g.send(entry_side(g, rid, side, leader))
        print("entry_side [%s] -> %s" % (who, es.get("result")))
        if es.get("result") != "NOERR":
            print("  %s" % describe(es))
            return 1
        pace()

    # -- ROOM-TIME relay-quality report (capture block 63) ----------------
    #    The real client measures AGAIN inside the room: after the
    #    GET_ROOM_INFO polls (blocks 52-62) and immediately before
    #    CMD_CHECK_MATCH_ENABLE (block 97).  Run #32 proved the login-time
    #    report alone leaves game_session at sycom=P2P / gamerelay=
    #    NotImplement, so the measurement the server acts on is the one
    #    bound to the room.  Reuses the cached endpoint list so this step
    #    sends only the SET, matching the capture exactly.
    for tag, g in (("owner", owner), ("bot  ", botg)):
        rq = quality_report(g, tag, rows=list(_LAST_ROWS))
        print("room relay_qual [%s] -> %s"
              % (tag, (rq or {}).get("result")))
        pace()

    # -- ready ----------------------------------------------------------
    #    Each identity advertises its OWN udp socket: owner :44000,
    #    bot :44001.  Sharing one endpoint file is what made both bots
    #    claim the same ip:port, which the server cannot punch and
    #    stamped DISCONN_HB on.
    #    2026-10-12: the real capture sends CMD_CHECK_MATCH_ENABLE (block
    #    97) immediately BEFORE CMD_SET_ROOM_MATCH_READY (block 98); chain3
    #    defined check_match_enable() but never called it -- the one command
    #    in the pre-match window it omitted.  Send it per identity now so the
    #    flow carries every capture command.
    for g, tag in ((owner, "owner"), (botg, "bot")):
        who = tag if tag == "owner" else "bot  "
        cme = g.send(check_match_enable(g))
        print("check_match_enable [%s] -> %s" % (who, cme.get("result")))
        if cme.get("result") != "NOERR":
            print("  %s" % describe(cme))
        pace()
        _, okd = diag(g, lambda: match_ready(g, rid, tag))
        if not okd:
            print("match_ready [%s] input rejected -- stopping" % who)
            return 1
        pace()
        mr = g.send(match_ready(g, rid, tag))
        print("match_ready [%s] -> %s ep=%s:%d" % (
            who, mr.get("result"),
            endpoint_net(tag).get("host_address"),
            endpoint_net(tag).get("host_port")))
        if mr.get("result") != "NOERR":
            print("  %s" % describe(mr))
            return 1
        pace()

    # -- go_match flips server-side once both are ready ------------------
    go = "NO"
    for _ in range(6):
        ri = room_state(owner, rid)
        go = ri.get("is_go_match")
        if go == "YES":
            break
        time.sleep(1.0)
    print("go_match     -> %s" % go)
    pace()

    # -- game session ----------------------------------------------------
    gs = owner.send(game_session(owner, rid))
    print("game_session -> %s keys=%s" % (gs.get("result"), ",".join(sorted(gs))))
    print("  %s" % show({k: v for k, v in gs.items()
                         if k not in ("result", "msgid", "rqid")}))
    pace()

    # -- step 7: TURN server list (POSTROOM_FLOW.md canonical order 5,6,7) --
    # GET_GAME_SESSION (5/6) -> GET_TURN_SERVER_LIST (7) -> CONNECT_SESSION.
    # This was STRIPPED in run #21 as "GKZX- in every body form"; the body
    # above is the one that answers.  The reply is the P2P rendezvous set, so
    # print it in full (credentials redacted) -- it is what a DTLS client
    # would dial.
    for _tag, _g in (("owner", owner), ("bot  ", botg)):
        try:
            _tl = _g.send(turn_server_list(_g), timeout=15)
        except Exception as _e:                                # noqa: BLE001
            print("turn_list[%s] -> EXC %s" % (_tag, _e))
            _tl = {}
        _tsl = _tl.get("turn_server_list") or []
        _acc = _tl.get("turn_account") or {}
        print("turn_list[%s] -> %s  zones=%d  origin=%s"
              % (_tag, _tl.get("result"), len(_tsl),
                 (_acc.get("origin") if isinstance(_acc, dict) else "")))
        for _e2 in _tsl:
            if isinstance(_e2, dict):
                print("    zone=%s %s:%s tls=%s"
                      % (_e2.get("zone"), _e2.get("address"),
                         _e2.get("port"), _e2.get("tls_port")))
        if isinstance(_acc, dict) and _acc:
            print("    turn_account keys=%s cert=%dB"
                  % (",".join(sorted(_acc)),
                     len(str(_acc.get("server_certificate") or ""))))
        pace()

    # -- USER_DATA_SYNC / TEAM_DATA_SYNC / ready_flag still STRIPPED:
    #    _DECODE_FAIL (404 HTML -- no .php endpoint, they travel in-band over
    #    the game channel, not the gate); mid-flow SET_GAMERELAY_QUALITY ->
    #    ERR_DATABASE/EVDU-.  The gate-quality report is already done at
    #    login AND at room time, where it succeeds.

    # -- report the session check, echoing the server's own values -------
    # (finish.py proven: this is what flips is_check_finished to YES and
    #  unblocks CMD_START_GAME from ERR_DATABASE)
    gr = as_map(gs.get("gamerelay"))
    sycom = gs.get("game_sycom")
    for tag, g, self_u, opp_u in (("owner", owner, owner.uid, botg.uid),
                                  ("bot  ", botg, botg.uid, owner.uid)):
        b = {
            "game_sycom": sycom if isinstance(sycom, str) else "",
            "error_code": "NOERR",
            "gamerelay": {"name": gr.get("name", ""),
                          "region": gr.get("region", ""),
                          "ip_addr": gr.get("ip_addr", ""),
                          "port": as_int(gr.get("port"))},
            "failed_reason": 0,
            "is_lobby": "YES",
            "room_id": {"id": rid},
            "statistical_data": {
                # 2026-10-12 (run #27 ruled out the endpoint/NAT proof; the
                # remaining gate-side gap is THIS connection report, sent
                # right before CMD_START_GAME).  The real capture's block
                # 105 statistical_data differs from what chain3 sent in SIX
                # fields -- all connection-quality metrics the server reads
                # to decide whether a real peer link exists:
                #   matching_num 0 (not 2), answer "NO" (not ""),
                #   antenna_min 3 (not ping=350), error_code "_0x0" (not
                #   "NOERR"), link_type "Ethernet" (not ""), and
                #   create_session_time 0 (not the real timestamp).
                # Empty link_type / wrong antenna_min here can read as "no
                # valid connection" at kickoff -> DISCONN_HB.  Match capture.
                "user_id_list": [self_u, opp_u], "matching_num": 0,
                "answer": "NO", "antenna_min": 3,
                "error_code": "_0x0", "link_type": "Ethernet",
                "create_session_time": 0,
                "background_times": "",
            },
        }
        m = g.envelope("CMD_SET_GAME_SESSION_CHECK_RES")
        m.update(b)
        r = g.send(m)
        print("check_res [%s] -> %s" % (tag, r.get("result")))
        if r.get("result") != "NOERR":
            print("  %s" % describe(r))
        # 11.1.0 parses gamerelay_list {name,region,ip_addr,port,event_id}
        # out of THIS reply (FUN_078a99ac).  That list is the DTLS relay
        # fleet the match is actually played over -- dump it every run.
        extra = {k: v for k, v in r.items()
                 if k not in ("result", "msgid", "rqid", "show_info",
                              "maintenance_end_time")}
        if extra:
            print("  check_res_body [%s] %s"
                  % (tag, json.dumps(extra, ensure_ascii=False,
                                     default=str)[:2500]))
        pace()

    m = owner.envelope("CMD_GET_GAME_SESSION_CHECK_RES")
    m["room_id"] = {"id": rid}
    m["is_lobby"] = "YES"
    m["game_entry_user_list"] = [owner.uid, botg.uid]
    gcr = owner.send(m)
    print("check_state  -> %s (%s)"
          % (gcr.get("is_check_finished"), gcr.get("result")))
    extra_g = {k: v for k, v in gcr.items()
               if k not in ("result", "msgid", "rqid", "show_info",
                            "maintenance_end_time", "is_check_finished")}
    if extra_g:
        print("  check_get_body %s"
              % json.dumps(extra_g, ensure_ascii=False, default=str)[:2500])
    pace()

    if "--upto-check" in sys.argv:
        print("stopping after the session-check per --upto-check")
        return 0

    # -- USER_DATA_SYNC / second GET_TURN_SERVER_LIST / TEAM_DATA_SYNC /
    #    mid-flow QUALITY_TEST: STRIPPED 2026-10-12 (run #21).  None appear
    #    in the real capture's room->result window; all are rejected here
    #    (_DECODE_FAIL = no .php for the sync trio; GKZX- for TURN list;
    #    ERR_DATABASE/EVDU- for the mid-room relay-quality re-report).  The
    #    gate-quality report is already done once at login where it succeeds.

    # -- game_id (its own command) ---------------------------------------
    game_id = get_game_id(owner, rid)
    if game_id is None:
        print("game_id MISSING in every form -- stopping")
        return 1
    print("game_id      -> found (%s)" % type(game_id).__name__)
    pace()

    # -- DATASYNC (capture block 108): the real client sends
    #    CMD_CHANGE_GAMEPHASE phase=DATASYNC gtimer=0 BETWEEN GET_GAME_ID and
    #    START_GAME.  chain3 never sent it -- the first missing phase.
    rds = change_phase(owner, game_id, "DATASYNC", 0)
    print("phase DATASYNC  -> %s %s"
          % (rds.get("result"),
             describe(rds) if rds.get("result") != "NOERR" else ""))
    pace()

    # -- PEERLINK / NTL SESSION ESTABLISHMENT, BEFORE START_GAME (run #30).
    #    2026-10-13: DISCONN_HB mechanism fully mapped from libUE4.so -- the
    #    match runs over an ICE-style STUN + TURN-over-DTLS + UDP-hole-punch
    #    session (PeerLink/NTL) that the server liveness-checks AT kickoff.
    #    chain3 established NONE of it before START_GAME -- these very commands
    #    sat AFTER kickoff (gated behind --setup), so the server saw no live
    #    peer link and stamped DISCONN_HB the instant START_GAME landed.  The
    #    real client runs the whole NTL handshake + TURN address exchange +
    #    STUN beat in the ~1k packets BETWEEN match-ready and START_GAME.  Run
    #    them here, at the correct pre-kickoff time, for both identities.  The
    #    data plane (bot<->bot hole punch + Konami STUN T7 beat) is supplied by
    #    the external punch stack (udp_punch/stun_keepalive/peer_punch_refresher)
    #    running concurrently on :44000/:44001.
    import base64 as _b64
    log_urls = {}
    for tag in ("owner", "bot  "):
        gi = ntl_gateinfo()
        log_urls[tag] = gi.get("PUT_LOG_URL") or ""
        print("ntl_gateinfo [%s] -> %s" % (tag, gi))
        rl = report_log(log_urls[tag], "pds")
        print("report_log  [%s] pds -> %s" % (tag, rl))

    for tag, gg in (("owner", owner), ("bot  ", botg)):
        send_session_id(gg, game_id, tag)
        pace()

    for tag, g2, tgt in (("owner", owner, botg.uid),
                         ("bot  ", botg, owner.uid)):
        mine = endpoint_net("owner" if tag == "owner" else "bot")
        ep_blob = _b64.b64encode(
            ("%s:%d" % (mine.get("host_address", ""),
                        mine.get("host_port", 0))).encode()).decode()
        ep_size = len(_b64.b64decode(ep_blob))
        m = g2.envelope("CMD_SEND_TURN_ADDRESS_DATA")
        m["target_user_id"] = tgt
        m["address"] = ep_blob
        m["address_data_size"] = ep_size
        sd = g2.send(m)
        print("turn_send [%s -> %s] -> %s" % (tag, tgt, sd.get("result")))
        pace()
        for cmd in ("CMD_GET_TURN_ADDRESS_DATA", "CMD_WATCH_TURN_ADDRESS_DATA"):
            m = g2.envelope(cmd)
            vr = g2.send(m)
            keys = ",".join(k for k in sorted(vr)
                            if k not in ("result", "msgid", "rqid"))
            print("turn_addr [%s %s] -> %s keys=%s"
                  % (tag, cmd.replace("CMD_", "").replace("_DATA", ""),
                     vr.get("result"), keys))
            pace()

    for tag, gg, su, ou in (("owner", owner, owner.uid, botg.uid),
                            ("bot  ", botg, botg.uid, owner.uid)):
        antenna_beat(gg, tag, rid, gs, su, ou)
        pace()

    # -- open the DTLS game channel BEFORE kickoff -----------------------
    # POSTROOM_FLOW s23.16 eliminated every other candidate for the server's
    # liveness check: the STUN T7 beat (twice), the pre-kickoff gate PeerLink
    # commands, and the bot-to-bot punch (not even server-observable, it is
    # local).  What is left -- and what chain3 had never once established --
    # is the DTLS session to Konami's own Google-Cloud rendezvous.  The
    # 2026-09-26 capture shows the real client sustaining exactly this for
    # the whole match with ~167 B client appdata at sub-1-pps.
    #
    # Endpoint discovery is live and session-scoped: GET_TURN_SERVER_LIST ->
    # STUN Allocate over TLS -> 401 + NONCE -> SOFTWARE "ip:port,..." (a
    # fresh port on every attempt, which is why the capture-era 30xxx ports
    # are all dead now).  OpenSSL does the handshake (cookie, ECDHE,
    # extended_master_secret, Finished) so the transcript is right by
    # construction -- hand-rolling it produced silent drops.
    dtls_holds = []
    for _tag in ("owner", "bot  "):
        try:
            from dtls_hold import DtlsHold
            _h = DtlsHold(_tag).start()
            dtls_holds.append(_h)
            print("dtls_hold [%s] -> ESTABLISHED %s %s %s hs=%ss"
                  % (_tag, _h.info.get("endpoint"), _h.info.get("version"),
                     _h.info.get("cipher"), _h.info.get("handshake_s")))
        except Exception as _e:                                  # noqa: BLE001
            print("dtls_hold [%s] -> FAILED %s" % (_tag, _e))
    pace()

    # -- --mapstamp: date the DISCONN_HB verdict.  CHECK after START_GAME
    #    and after every phase tells us exactly when the server resolves
    #    the match as a heartbeat-disconnect walkover (or whether some
    #    CHECK itself triggers the resolve).  Defined here (before
    #    START_GAME) so --pinpoint can bracket the stamp around kickoff.
    def stamp_check(tag):
        m = owner.envelope("CMD_CHECK_GAME_RESULT")
        m["game_id"] = game_id
        c = owner.send(m)
        mr0 = (c.get("game_end_result") or {}).get("match_result") or {}
        print("stampcheck %-12s -> %s gameend=%s abnormal=%s score=%s"
              % (tag, c.get("result"), mr0.get("gameend_reason"),
                 mr0.get("abnormalend_reason"), mr0.get("score_data")))
        return mr0

    # -- START_GAME (finish.py proven order: owner XI first) -------------
    #    BOTH clients must send CMD_START_GAME, each with its own side.
    #    Only the owner ever sent it before, so the server saw one player
    #    kick off and the other never arrive -> abnormal=DISCONN_HB was
    #    already stamped by the t+2 s check, and every later
    #    SET_GAME_RESULT came back ERR_INVALIDARG/GKZX-.  Each identity
    #    announces its own kickoff: owner HOME, bot AWAY.
    home = squad_list(sq_o)
    away = squad_list(sq_b)
    print("lineups      -> home=%d away=%d team_id=%s"
          % (len(home), len(away), team_id))
    if len(home) < 11 or len(away) < 11:
        print("a side has fewer than 11 players -- stopping")
        return 1

    # -- run #38: the check this project has NEVER run.  stamp_check() has
    #    only ever been called AFTER START_GAME, so "DISCONN_HB is stamped
    #    the instant kickoff lands" rests entirely on a post-facto
    #    observation.  If the value is already present BEFORE either side
    #    kicks off then it is the server's default for "no result yet" --
    #    not a stamp at all -- and gameend=INVALID (run #37) is the real
    #    signal: the match never produced a result, which is a different
    #    bug with a different fix.  Read-only, so it cannot change the
    #    verdict it is measuring.
    if "--pinpoint" in sys.argv:
        stamp_check("pre-kickoff")

    sg = None
    for label, g, hl, al, sd in (("owner XI", owner, home[:11], away[:11], "HOME"),
                                 ("owner 23", owner, home, away, "HOME")):
        sg = g.send(start_game(g, game_id, team_id, hl, al, sd))
        print("start_game [%s] -> %s" % (label, sg.get("result")))
        pace()
        if sg.get("result") == "NOERR":
            break
    if not sg or sg.get("result") != "NOERR":
        print("  %s" % describe(sg or {}))
        return 1
    _sg_t0 = time.time()   # --pinpoint: START_GAME instant (owner HOME)
    globals()["_sg_t0"] = _sg_t0
    if "--pinpoint" in sys.argv:
        stamp_check("pre-botSG")   # owner kicked off, bot not yet

    # the AWAY side announces its own kickoff too
    sgb = None
    for label, g, hl, al, sd in (("bot   23", botg, home, away, "AWAY"),
                                 ("bot   XI", botg, home[:11], away[:11], "AWAY")):
        sgb = g.send(start_game(g, game_id, team_id, hl, al, sd))
        print("start_game [%s] -> %s" % (label, sgb.get("result")))
        pace()
        if sgb.get("result") == "NOERR":
            break
    if not sgb or sgb.get("result") != "NOERR":
        print("  (bot START_GAME not accepted -- server may still stamp "
              "DISCONN_HB) %s" % describe(sgb or {}))
    print("  %s" % show({k: v for k, v in sg.items()
                         if k not in ("result", "msgid", "rqid")}))

    # -- IN-MATCH COMMAND WINDOW.  CMD_GET_SERVER_ENV (run #17, NOERR)
    #    returned the authoritative server config, and onsys_opt decodes
    #    (decode_env.py) to a per-command in-match timeout table:
    #
    #        timeout: CMD_ADD_SCORE=30, CMD_ADD_FOUL=30,
    #                 CMD_CHANGE_GAMEPHASE=30
    #
    #    30 s each.  Run #17's timeline shows why that number matters:
    #    START_GAME landed at t+30.6s and the FIRST table command (the
    #    1ST_15MIN phase advance) at t+61.1s -- a gap of 30.5 s, half a
    #    second past the window, because NTL, ReportLog, ready_flag,
    #    antenna and TURN setup were all run in between.  DISCONN_HB is
    #    stamped server-side at ~30 s, i.e. before any in-match command
    #    arrived.  The real client advances the phase on START_GAME, so
    #    send it here, ahead of every piece of setup traffic.
    #2026-10-12 (run #24): the real capture's phase chain after START_GAME is
    # MATCHMENU -> GAMELOAD -> ENTRY -> 1ST (blocks 110-113, gtimer 0/0/0/676)
    # before the timed phases.  chain3 jumped straight to 1ST_15MIN with a
    # constant gtimer=900, skipping the loading/menu/kickoff phases -- an
    # illegal phase-state transition.  Replay the REAL chain with the REAL
    # gtimer match-clock values from the capture.
    for _ph, _gt in (("MATCHMENU", 0), ("GAMELOAD", 0), ("ENTRY", 0),
                     ("1ST", 676)):
        _r = change_phase(owner, game_id, _ph, _gt)
        print("phase %-10s -> %s %s"
              % (_ph, _r.get("result"),
                 describe(_r) if _r.get("result") != "NOERR" else ""))
        pace()

    # -- SESSION phase: CMD_SEND_SESSION_ID.  Recovered 2026-10-11; chain3
    #    never sent it.  Body {game_id, platform_session_id_info{ps,xb}}.
    #    Sent here, once the session exists (both START_GAMEs accepted), so
    #    the gate knows which platform session this game_id belongs to.
    # 2026-10-12 (run #23 prep): the capture's in-match window has NONE of
    # these -- CMD_SEND_SESSION_ID / CMD_GET_SESSION_ID are absent from the 138
    # gate blocks, and the antenna beat belongs PRE-match (block 105).  Gated
    # behind --setup so the default in-match flow is capture-faithful.
    if "--setup" in sys.argv:
        for tag, gg in (("owner", owner), ("bot  ", botg)):
            send_session_id(gg, game_id, tag)
            pace()

    # -- NTL handshake (z2 capture plaintext HTTP): the real phone POSTs
    #    GateInfo.php to ntl.service.konami.net right at the punch phase
    #    start.  The bot never talked to this service until now.  Run for
    #    both identities (each phone does its own handshake).
    #    Then immediately announce the P2P session OPEN (type=pds) to the
    #    PUT_LOG_URL the handshake just returned.  The real client always
    #    does these two together; chain3 did NEITHER until 2026-10-11.
    log_urls = {}
    for tag in ("owner", "bot  "):
        gi = ntl_gateinfo()
        log_urls[tag] = gi.get("PUT_LOG_URL") or ""
        print("ntl_gateinfo [%s] -> %s" % (tag, gi))
        rl = report_log(log_urls[tag], "pds")
        print("report_log  [%s] pds -> %s" % (tag, rl))

    # -- CMD_READY_FLAG.  Located 2026-10-11; never sent by chain3 before.
    #    Its only sender (FUN_07b1fda8) fires on a state-bitmask CHANGE,
    #    and its 11 callers are all Task\\Match\\ sync tasks.  This lands in
    #    the same pre-verdict window as the NTL handshake, where the server
    #    stamps DISCONN_HB (t+2 s .. t+35 s after START_GAME).
    #    Send mask 0 first, then a non-zero mask, to cover both the
    #    "set" and "clear" paths of the csel in the real sender.
    # 2026-10-12 (run #23 prep): the real capture's in-match window (blocks
    # 107-123) is ONLY CHANGE_GAMEPHASE + ADD_SCORE + ADD_FOUL.  CMD_READY_FLAG
    # is NOT in it (and has no .php here -> _DECODE_FAIL).  Gated behind --setup
    # so the DEFAULT in-match flow matches the capture exactly.
    if "--setup" in sys.argv:
        for tag, gg, fl in (("owner", owner, 0), ("bot  ", botg, 0),
                            ("owner", owner, 1), ("bot  ", botg, 1)):
            ready_flag(gg, rid, fl, tag)

    # -- IMMEDIATE antenna beat.  Run #7 proved the body is accepted
    #    (set=NOERR get=NOERR finished=YES) but the first poll at t+30 s
    #    already read DISCONN -- the server stamps between t+2 s and
    #    t+35 s after START_GAME, so a heartbeat that only fires on the
    #    30 s poll cadence always lands AFTER the verdict.  Fire it now,
    #    before anything else, for both identities.
    #    2026-10-12: belongs PRE-match (capture block 105).  Gated behind --setup.
    if "--setup" in sys.argv:
        for tag, gg, su, ou in (("owner", owner, owner.uid, botg.uid),
                                ("bot  ", botg, botg.uid, owner.uid)):
            antenna_beat(gg, tag, rid, gs, su, ou)
            pace()

    # -- SESSION_ESTABLISH (flow item 24, gate-real): both clients ask
    #    the gate for the session id with {game_id}.  (CMD_READY_FLAG /
    #    CMD_ALLREADY_FLAG exist in the binary but have NO .php endpoint
    #    -- they travel in-band over the game channel, not the gate.)
    #    2026-10-12: CMD_GET_SESSION_ID is absent from the 138 gate blocks.
    #    Gated behind --setup so the default matches the capture.
    if "--setup" in sys.argv:
        for tag, g in (("owner", owner), ("bot  ", botg)):
            m = g.envelope("CMD_GET_SESSION_ID")
            m["game_id"] = game_id
            si = g.send(m)
            keys = ",".join(k for k in sorted(si)
                            if k not in ("result", "msgid", "rqid"))
            print("sess_id   [%s] -> %s keys=%s"
                  % (tag, si.get("result"), keys))
            if keys:
                print("  %s" % show({k: v for k, v in si.items()
                                     if k not in ("result", "msgid", "rqid")}))
            elif si.get("result") != "NOERR":
                print("  %s" % describe(si))
            pace()

    # -- POSTROOM_FLOW item 27: gate-side TURN address exchange.  Bare
    #    GET/WATCH envelopes (no body keys); reply carries the peer's
    #    base64 address blob {address, address_data_size}.  Sent right
    #    after START_GAME = when NTL punching begins in the real game.
    #    The exchange only fills in when we SEND our own blob first.
    #    The blob must be OUR OWN endpoint per identity -- it used to be
    #    built once outside the loop, so both sides published the same
    #    address and the peer could never be reached.
    # 2026-10-12 (run #23 prep): the real capture does NOT exchange TURN
    # addresses in the in-match window (blocks 107-123 are only phase/score/
    # foul).  A mid-match SEND/GET/WATCH_TURN_ADDRESS_DATA reads as a punch
    # renegotiation -- a prime candidate for tripping DISCONN_HB.  Gated behind
    # --setup so the default matches the capture.
    if "--setup" in sys.argv:
        import base64 as _b64
        for tag, g, tgt in (("owner", owner, botg.uid),
                            ("bot  ", botg, owner.uid)):
            mine = endpoint_net(tag if tag == "owner" else "bot")
            ep_blob = _b64.b64encode(
                ("%s:%d" % (mine.get("host_address", ""),
                            mine.get("host_port", 0))).encode()
            ).decode()
            ep_size = len(_b64.b64decode(ep_blob))
            m = g.envelope("CMD_SEND_TURN_ADDRESS_DATA")
            m["target_user_id"] = tgt
            m["address"] = ep_blob
            m["address_data_size"] = ep_size
            sd = g.send(m)
            print("turn_send [%s -> %s] -> %s" % (tag, tgt, sd.get("result")))
            if sd.get("result") != "NOERR":
                print("  %s" % describe(sd))
            pace()

        for cmd in ("CMD_GET_TURN_ADDRESS_DATA", "CMD_WATCH_TURN_ADDRESS_DATA"):
            for tag, g in (("owner", owner), ("bot  ", botg)):
                m = g.envelope(cmd)
                vr = g.send(m)
                keys = ",".join(k for k in sorted(vr)
                                if k not in ("result", "msgid", "rqid"))
                print("turn_addr [%s %s] -> %s keys=%s"
                      % (tag, cmd.replace("CMD_", "").replace("_DATA", ""),
                         vr.get("result"), keys))
                if keys:
                    print("  %s" % show({k: v for k, v in vr.items()
                                         if k not in ("result", "msgid",
                                                      "rqid")}))
                pace()

    # -- --mapstamp / --pinpoint helpers: stamp_check defined ABOVE (near
    #    START_GAME) so both the pre-botSG check and the post-start check
    #    can call it.

    if "--mapstamp" in sys.argv:
        stamp_check("post-start")

    # -- --pinpoint: date the exact instant DISCONN_HB appears.  The
    #    post-start check above is delayed (session/NTL/report setup runs
    #    between START_GAME and it), so it cannot tell "stamped the instant
    #    START_GAME lands" from "stamped ~30s later by the game-channel
    #    heartbeat timeout".  Poll CMD_CHECK_GAME_RESULT every 1s, logging
    #    wall-clock offset from START_GAME, until the verdict shows.  The
    #    _sg_t0 timestamp is captured at the START_GAME send above.  A
    #    read-only poll (the real client polls at a 30s interval; rapid
    #    polling here is only for diagnosis).
    if "--pinpoint" in sys.argv:
        _sg_t0 = globals().get("_sg_t0") or time.time()
        print("pinpoint: polling stamp from START_GAME (t0 set at SG)")
        _seen = None
        for _i in range(45):
            mr0 = stamp_check("t+%0.1fs" % (time.time() - _sg_t0))
            if mr0.get("abnormalend_reason") == "DISCONN_HB" \
                    or mr0.get("gameend_reason") == "DISCONN":
                _seen = time.time() - _sg_t0
                print("  >> DISCONN_HB first observed at START_GAME+%0.1fs"
                      % _seen)
                break
            time.sleep(1.0)
        if _seen is None:
            print("  >> no DISCONN_HB within 45s of START_GAME")

    if "--upto-start" in sys.argv:
        SENSITIVE.update({"user_id", "target_user_id"})
        for tag, gg in (("owner", owner), ("bot  ", botg)):
            m = gg.envelope("CMD_GET_GAME_RESULT")
            m["game_id"] = game_id
            vr = gg.send(m)
            mr = vr.get("match_result")
            print("verdict [%s] -> %s get_match_result=%s"
                  % (tag, vr.get("result"), vr.get("get_match_result")))
            if isinstance(mr, dict):
                print("  keys(%d): %s" % (len(mr), sorted(mr)))
                print("  %s" % json.dumps(shape(mr), ensure_ascii=False,
                                          default=str)[:6000])
        print("stopping after START_GAME per --upto-start")
        return 0

    # -- kickoff: stamp the match clock.  --poll re-adds the in-match
    #    CHECK_GAME_RESULT heartbeat (at_match_polling_interval_msec=30000):
    #    mapstamp evidence -- WITHOUT mid-match polls the server walks the
    #    match over DISCONN 0-3 the instant END arrives (precheck run);
    #    WITH them gameend stays INVALID through END + battery = the result
    #    window stays open.  The old "polls contaminated" note was wrong:
    #    the precheck run's instant walkover was caused by the missing
    #    polls, not by the checks (mapstamp checked after every phase and
    #    the match never resolved). -------------------------------------
    kickoff_t = time.time()
    _rf_n = 0  # rotates the CMD_READY_FLAG mask each in-match beat

    # -- phases: a complete match is >= 5 min wall clock + halftime
    #    transition, so each phase waits out its share ---------------------
    # --realorder: goals fire DURING their phases (12' after 1ST_15MIN,
    # 34' after 1ST_30MIN, 61' after 2ND) like a real match, and the
    # submit goes out immediately after END with nothing in between.
    scorer_h = home[0]["gameplayer_id"] if home else None
    scorer_a = away[0]["gameplayer_id"] if away else None
    MIDGOALS = {"1ST_15MIN": [(owner.uid, "HOME", 12, scorer_h)],
                "1ST_30MIN": [(owner.uid, "HOME", 34, scorer_h)],
                "2ND": [(botg.uid, "AWAY", 61, scorer_a)]}
    # the real match sent exactly ONE foul, 92' in 2ND_30MIN (capture block
    # 122) -- chain3 never did; add it so the in-match sequence matches.
    MIDFOUL = {"2ND_30MIN": [(botg.uid, "AWAY", 92, scorer_a)]}
    # the real phase chain + match-clock (capture blocks 114-125).  2ND_15MIN
    # was missing and gtimer was a constant 900 -- both now match the capture's
    # monotonic match clock exactly.
    PHASE_GT = {"1ST_15MIN": 2921, "1ST_30MIN": 5264, "BREAK1": 9098,
                "2ND": 9403, "2ND_15MIN": 11160, "2ND_30MIN": 12947,
                "END": 15772}
    for p in ("1ST_15MIN", "1ST_30MIN", "BREAK1", "2ND", "2ND_15MIN",
              "2ND_30MIN", "END"):
        r = change_phase(owner, game_id, p, PHASE_GT[p])
        ri = room_state(owner, rid)
        print("phase %-10s -> %-14s room gamephase=%s"
              % (p, r.get("result"), ri.get("gamephase")))
        if r.get("result") != "NOERR":
            print("  %s" % describe(r))
        pace()
        print("  (gRPC beats: %s)"
              % ", ".join("%s %d/%d" % (t, b.beats, b.replies)
                          for t, b in beaters))
        if "--mapstamp" in sys.argv:
            stamp_check("after " + p)
        if "--realorder" in sys.argv:
            for who, side, minute, scorer in MIDGOALS.get(p, ()):
                rg = add_score(owner, game_id, who, side, scorer, minute)
                print("goal %2d' %-4s -> %s (%s)"
                      % (minute, side, rg.get("result"), rg.get("errcode")))
                pace()
            for who, side, minute, player in MIDFOUL.get(p, ()):
                rf = add_foul(owner, game_id, who, side, player, minute, p)
                print("foul %2d' %-4s -> %s (%s)"
                      % (minute, side, rf.get("result"), rf.get("errcode")))
                pace()
        # the result window: game_result_timeout_sec=45 (onsys_opt) -- the
        # old chain slept 50 s after END and submitted ~60 s late, so the
        # server had already stamped its DISCONN forfeit and every SET got
        # a body-independent GKZX-.  Submit right after END instead; keep
        # the >= 5 min match by moving the time into 2ND_30MIN.
        if p != "END":
            wait = (70.0 if p == "BREAK1"
                    else (90.0 if p == "2ND_30MIN" else 50.0))
            if "--poll" in sys.argv:
                # the real game polls every 30 s during the match; both
                # identities poll their own view (each phone does)
                while wait > 0:
                    slice_ = min(30.0, wait)
                    time.sleep(slice_)
                    wait -= slice_
                    if wait > 0:
                        for tag, gg in (("own", owner), ("bot", botg)):
                            m = gg.envelope("CMD_CHECK_GAME_RESULT")
                            m["game_id"] = game_id
                            c = gg.send(m)
                            mr0 = (c.get("game_end_result") or {}).get(
                                "match_result") or {}
                            print("  poll[%s] %s gameend=%s abnormal=%s"
                                  % (tag, p, mr0.get("gameend_reason"),
                                     mr0.get("abnormalend_reason")))
                        # the antenna heartbeat -- the missing in-match
                        # liveness the server resolves the match over
                        if "--antenna" in sys.argv:
                            for tag, gg, su, ou in (
                                    ("own", owner, owner.uid, botg.uid),
                                    ("bot", botg, botg.uid, owner.uid)):
                                antenna_beat(gg, tag, rid, gs, su, ou)
                        #    2026-10-12: the real capture's in-match window has
                        #    NO uds/ready_flag/playdata (only phase/score/foul).
                        #    All gated behind --setup so the default matches it.
                        if "--setup" in sys.argv:
                            for tag, lu in log_urls.items():
                                report_log(lu, "uds")
                            _rf_n += 1
                            for tag, gg in (("own", owner), ("bot", botg)):
                                ready_flag(gg, rid, _rf_n & 3, tag)
                            for tag, gg in (("own", owner), ("bot", botg)):
                                set_playdata_match(gg, game_id, str(_rf_n),
                                                   str(_rf_n), tag)
                        else:
                            _rf_n += 1
            else:
                time.sleep(wait)
    end_t = time.time()

    # -- --precheck: is the match still OPEN right after END?  One
    #    CHECK_GAME_RESULT before goals/battery reads the server's stored
    #    verdict.  If DISCONN_HB is ALREADY stamped here, the stamp
    #    pre-dates the submit window entirely (match-start timer or
    #    missing in-match liveness), and no body/timing fix can help.
    #    If it is empty/None, the match is open and the window is live.
    if "--precheck" in sys.argv:
        m = owner.envelope("CMD_CHECK_GAME_RESULT")
        m["game_id"] = game_id
        c = owner.send(m)
        mr0 = (c.get("game_end_result") or {}).get("match_result") or {}
        print("precheck  t+%.1fs since END -> %s gameend=%s abnormal=%s "
              "score=%s res=%s"
              % (time.time() - end_t, c.get("result"),
                 mr0.get("gameend_reason"), mr0.get("abnormalend_reason"),
                 mr0.get("score_data"), mr0.get("game_res")))

    # -- close the NTL sessions we opened (capture shows ude then pde
    #    at teardown).  Every pds/uds the real client opens it closes.
    for tag, lu in log_urls.items():
        report_log(lu, "ude")
    for tag, lu in log_urls.items():
        report_log(lu, "pde")

    # -- goals (finish.py proven: owner channel, phase=END); skipped
    #    under --realorder because they already fired during the phases
    if "--realorder" not in sys.argv:
        for who, side, minute, scorer in ((owner.uid, "HOME", 12, scorer_h),
                                          (owner.uid, "HOME", 34, scorer_h),
                                          (botg.uid, "AWAY", 61, scorer_a)):
            r = add_score(owner, game_id, who, side, scorer, minute)
            print("goal %2d' %-4s -> %s (%s)"
                  % (minute, side, r.get("result"), r.get("errcode")))
            pace()

    # -- publish the result.  NO pre-submit GET/CHECK: both resolve the
    #    match on the server side (the CHECK/GET of an open match returns
    #    an empty template and later shows the DISCONN_HB walkover), so the
    #    first contact after the goals MUST be the submit itself.

    PROTECT = {"score", "home", "away", "gameend_reason",
               "abnormalend_reason", "game_id"}
    elapsed = int(time.time() - kickoff_t)
    print("match elapsed -> %ds (min real match: 300s)" % elapsed)
    # NOERR first: it is the game's own ctor default for
    # abnormalend_reason (0x77d4270 writes "NOERR" at +0x1f1, and the
    # serializer's FIRST setkey is abnormalend_reason) -- a clean finish
    # most likely keeps the default.  The rest is the old battery.
    # 2026-10-13 (run #39): TWO defects made this battery one-sided.  The
    # first entry was owner-only, and the inner loop broke on the first
    # NOERR -- so since the day this was written THE BOT NEVER SENT
    # CMD_SET_GAME_RESULT: every log reads set_result [owner NOERR] ->
    # ['own:NOERR'], a one-element list.  A two-player match cannot resolve
    # on one player's report, and that is exactly what the server returns
    # -- gameend_reason INVALID with a stored score of 0-0 despite three
    # goals.  Lead with a BOTH round, and let every identity in a round
    # report before deciding the round was accepted.
    BATTERY = [
        ("both NOERR", "NOERR", "both"),
        ("both NONE", "NONE", "both"),
        ("owner NOERR", "NOERR", "owner"),
        ("owner NONE", "NONE", "owner"),
        ("owner NORMAL", "NORMAL", "owner"),
        ("owner NORMAL_END", "NORMAL_END", "owner"),
        ("owner GIVEUP", "GIVEUP", "owner"),
        ("owner FORFEIT", "FORFEIT", "owner"),
        ("both NONE", "NONE", "both"),
        ("botfirst NONE", "NONE", "botfirst"),
    ]

    # -- open-match template echo (2026-10-11): the server hands us its
    #    own stored match_result (5 keys) in every CHECK reply on an open
    #    match.  Photocopier: echo it back with the result filled in --
    #    if the server validates our 106-key serializer shape against its
    #    own 5-key template, this is the accepted shape.
    def sgr_echo(g: Gate, tpl: dict, home_score: int, away_score: int,
                 abnormal: str) -> dict:
        mr = dict(tpl)
        mr["gameend_reason"] = "NORMAL_END"
        mr["abnormalend_reason"] = abnormal
        mr["game_res"] = "WIN" if g is owner else "LOSE"
        mr["score_data"] = {"home_score": home_score,
                            "away_score": away_score}
        return {"match_result": mr}

    tpl_owner = tpl_bot = None
    if "--poll" in sys.argv:
        for tag, gg, sink in (("own", owner, "o"), ("bot", botg, "b")):
            m = gg.envelope("CMD_CHECK_GAME_RESULT")
            m["game_id"] = game_id
            c = gg.send(m)
            mr0 = (c.get("game_end_result") or {}).get("match_result") or {}
            print("template[%s] -> %s gameend=%s keys=%s"
                  % (tag, c.get("result"), mr0.get("gameend_reason"),
                     sorted(mr0)))
            if sink == "o":
                tpl_owner = mr0
            else:
                tpl_bot = mr0
            time.sleep(0.4)

    # echo battery (open match only): full template, then template-only
    # match_result (no game_check_data / analyst), each abnormal variant
    if tpl_owner:
        for g, tpl, abnormal, who in (
                (owner, tpl_owner, "NOERR", "echo own NOERR"),
                (owner, tpl_owner, "NONE", "echo own NONE"),
                (botg, tpl_bot, "NOERR", "echo bot NOERR")):
            if not tpl:
                continue
            req = sgr_echo(g, tpl, 2, 1, abnormal)
            m = g.envelope("CMD_SET_GAME_RESULT")
            m["game_id"] = game_id
            m.update(req)
            r = g.send(m)
            print("set_result [%-14s] -> %s  (t+%.1fs since END)"
                  % (who, r.get("result"), time.time() - end_t))
            if r.get("result") != "NOERR":
                print("  FULL reply: %s"
                      % json.dumps(shape(r), ensure_ascii=False,
                                   default=str)[:1200])
            if r.get("result") == "NOERR":
                break
            time.sleep(0.8)

    # extra: full serializer body + room_id at root (some handlers may key
    # the room match by room, not game)
    if "--poll" in sys.argv:
        mine, theirs = home, away
        req = sgr_request(game_id, mine, theirs, 2, 1, "NOERR", elapsed)
        m = owner.envelope("CMD_SET_GAME_RESULT")
        m["game_id"] = game_id
        m["room_id"] = {"id": rid}
        m.update(req)
        r = owner.send(m)
        print("set_result [%-14s] -> %s  (t+%.1fs since END)"
              % ("own roomid", r.get("result"), time.time() - end_t))
        if r.get("result") != "NOERR":
            print("  FULL reply: %s"
                  % json.dumps(shape(r), ensure_ascii=False,
                               default=str)[:1200])

    for tag, abnormal, who in BATTERY:
        order = ([owner] if who == "owner"
                 else [owner, botg] if who == "both" else [botg, owner])
        results = []
        # measured kickoff -> now, in ms: the capture's match_time_tick
        # (822300) is wall-clock shaped, and the server knows both arrival
        # instants.  computed once per round so both identities agree.
        tick_ms = int((time.time() - globals().get("_sg_t0",
                                                   time.time())) * 1000)
        for g in order:
            mine, theirs = (home, away) if g is owner else (away, home)
            req = sgr_request(game_id, mine, theirs, 2, 1, abnormal,
                              elapsed, tick_ms)
            m = g.envelope("CMD_SET_GAME_RESULT")
            # ROOT game_id -- 2026-10-11: every accepted match-scoped command
            # (CHANGE_GAMEPHASE, ADD_SCORE, CHECK/GET_GAME_RESULT) carries
            # game_id at the ROOT; the body serializer emits only the three
            # objects, and the common gate layer stamps the envelope params.
            # The bot never once sent it at root (probes put it inside
            # match_result instead) -- a missing required root param is
            # exactly the body-independent GKZX/ERR_INVALIDARG seen on every
            # attempt since the first live run.
            m["game_id"] = game_id
            m.update(req)
            r = g.send(m)
            results.append("%s:%s" % ("own" if g is owner else "bot",
                                      r.get("result")))
            if r.get("result") != "NOERR":
                print("  FULL reply [%s]: %s"
                      % (tag, json.dumps(shape(r), ensure_ascii=False,
                                         default=str)[:1200]))
            # deliberately NO break on success -- breaking here is what
            # stopped the second identity from ever reporting its side.
            time.sleep(0.4)
        print("set_result [%-14s] -> %s  (t+%.1fs since END)"
              % (tag, results, time.time() - end_t))
        time.sleep(0.8)
        # accept the round only when EVERY identity in it reported OK:
        # one side's NOERR is not a resolved match.
        if results and all("NOERR" in x for x in results):
            break

    # -- read the score back ---------------------------------------------
    # 2026-10-13 (check_capture_stamp.py): CMD_CHECK_GAME_RESULT IS NOT IN THE
    # REAL CAPTURE AT ALL, and DISCONN_HB appears ZERO times across all 138
    # decoded blocks -- request and response alike.  Every verdict this
    # project has ever quoted came from an endpoint the real client never
    # calls, whose pre-kickoff reply is simply the default for "no result
    # yet" (run #38: present BEFORE either side kicks off).
    #
    # The genuine readout is CMD_GET_GAME_RESULT, which the real client polls
    # until get_match_result=YES: capture #124 -> NO, #126 -> YES with
    # gameend=NORMAL_END, abnormal=NOERR, game_res=DRAW 1-1.  chain3 polled
    # exactly once, accepted the owner's NO as final, and printed NOTHING --
    # it read r["match_result"] while the body nests the verdict under
    # r["game_end_result"]["match_result"].
    m = owner.envelope("CMD_CHECK_GAME_RESULT")   # OUR endpoint, not capture's
    m["game_id"] = game_id
    c = owner.send(m)
    print("check_result -> %s (%s)  [not in capture: diagnostic only]"
          % (c.get("result"), c.get("errcode")))
    print("  FULL check: %s" % json.dumps(shape(c), ensure_ascii=False,
                                          default=str)[:6000])
    pace()
    for tag, g in (("owner", owner), ("bot  ", botg)):
        verdict = None
        for attempt in range(6):                # capture polls NO -> YES
            m = g.envelope("CMD_GET_GAME_RESULT")
            m["game_id"] = game_id
            r = g.send(m)
            ger = (r.get("game_end_result") or {}).get("match_result") or {}
            print("get_result [%s] try%d -> %s get_match_result=%s "
                  "gameend=%s abnormal=%s game_res=%s score=%s"
                  % (tag, attempt + 1, r.get("result"),
                     r.get("get_match_result"), ger.get("gameend_reason"),
                     ger.get("abnormalend_reason"), ger.get("game_res"),
                     ger.get("score_data")))
            if r.get("get_match_result") == "YES":
                verdict = ger
                break
            pace()
        if verdict:
            print("  VERDICT [%s]: %s"
                  % (tag, json.dumps(shape(verdict), ensure_ascii=False,
                                     default=str)[:6000]))
        else:
            print("  VERDICT [%s]: never reached YES" % tag)
        pace()

    ri = room_state(owner, rid)
    print("final        -> gamephase=%s go_match=%s"
          % (ri.get("gamephase"), ri.get("is_go_match")))
    for tag, bs in beaters:
        print("gRPC beats [%s] -> %d sent, %d replied%s"
              % (tag, bs.beats, bs.replies,
                 ("  (" + bs.dead + ")") if bs.dead else ""))
    # tear the DTLS sessions down only now -- they must outlive kickoff,
    # the whole match and the result battery
    for _h in dtls_holds:
        try:
            print("dtls_hold [%s] stopped -> %s" % (_h.tag, _h.stop()))
        except Exception as _e:                                  # noqa: BLE001
            print("dtls_hold [%s] stop err %s" % (_h.tag, _e))
    print("elapsed      -> %.1fs" % (time.time() - t0))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
