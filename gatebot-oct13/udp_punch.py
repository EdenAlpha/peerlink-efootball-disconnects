#!/usr/bin/env python3
"""udp_punch.py -- the bot's network endpoint for the phone's P2P kickoff.

The phone, at match start, hole-punches to the address the opponent
advertised in the room.  Our bot advertised nothing -> "Unable to
connect".  This script:

  1. binds ONE UDP socket on a fixed port,
  2. asks a public STUN server (from that same socket) for our
     reflexive address (ip:port as the internet sees it),
  3. answers incoming STUN binding requests (so the phone's punch
     gets a reply), and logs EVERY packet to work\\peer_listen.log,
  4. writes work\\peer_endpoint.json {ip, port} for lobby_hold.py to
     inject into the ready body (address_ipv4 / port_ipv4).

  python udp_punch.py            # foreground; Ctrl-C to stop
"""
import json
import os
import socket
import struct
import sys
import time

WORK = os.path.dirname(os.path.abspath(__file__))
PORT = int(os.environ.get("PEER_PORT", "44000"))
# Two PeerLink bots run on this ONE VM, so they share a public IP.  If
# both advertise the same ip:port the NAT proof is self-contradictory --
# the server cannot punch between two peers at one address, which is
# what stamped abnormal=DISCONN_HB within 2 s of CMD_START_GAME.  Each
# identity therefore binds its OWN local port and gets its own file:
#   :44000 -> peer_endpoint.json   (owner)
#   :44001 -> peer_endpoint_bot.json (bot)
EP_FILE = os.path.join(WORK, "peer_endpoint.json" if PORT == 44000
                       else "peer_endpoint_bot.json")
LOG = os.path.join(WORK, "peer_listen.log" if PORT == 44000
                   else "peer_listen_%d.log" % PORT)

STUN = [("stun.l.google.com", 19302),
        ("stun1.l.google.com", 19302),
        ("stun.cloudflare.com", 3478)]

MAGIC = 0x2112A442
BIND_REQ, BIND_OK = 0x0001, 0x0101
PUNCH_EVERY = 0.5          # seconds between outbound punches
LOG_EVERY = 60.0           # seconds between repeated inbound log lines


def log(msg):
    line = "%s %s" % (time.strftime("%H:%M:%S"), msg)
    print(line)
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def stun_msg(mtype, txid, attrs=b""):
    return struct.pack(">HHI", mtype, len(attrs), MAGIC) + txid + attrs


def parse_binding(data):
    """-> (mtype, txid) if this is a STUN message else None"""
    if len(data) < 20:
        return None
    mtype, length, cookie = struct.unpack(">HHI", data[:8])
    if cookie != MAGIC:
        return None
    return mtype, data[8:20]


def xor_addr(data, off):
    """XOR-MAPPED-ADDRESS at off -> (ip, port)"""
    fam = data[off + 1]
    port = struct.unpack(">H", data[off + 2:off + 4])[0] ^ (MAGIC >> 16)
    if fam == 0x01:
        raw = bytes(a ^ b for a, b in zip(data[off + 4:off + 8],
                                          struct.pack(">I", MAGIC)))
        return socket.inet_ntoa(raw), port
    raw = bytes(a ^ b for a, b in zip(
        data[off + 4:off + 20],
        struct.pack(">IIII", MAGIC, MAGIC, MAGIC, MAGIC)))
    return socket.inet_ntop(socket.AF_INET6, raw), port


def mapped_addr(data):
    """find XOR-MAPPED-ADDRESS (0x0020) or MAPPED-ADDRESS (0x0004)"""
    off = 20
    while off + 4 <= len(data):
        atype, alen = struct.unpack(">HH", data[off:off + 4])
        if atype in (0x0020, 0x0004) and alen >= 8:
            if atype == 0x0020:
                return xor_addr(data, off + 4)
            fam = data[off + 5]
            port = struct.unpack(">H", data[off + 6:off + 8])[0]
            if fam == 0x01:
                return socket.inet_ntoa(data[off + 8:off + 12]), port
            return socket.inet_ntop(socket.AF_INET6,
                                    data[off + 8:off + 24]), port
        off += 4 + ((alen + 3) & ~3)
    return None


TARGET_FILE = os.path.join(WORK, "peer_target.json" if PORT == 44000
                           else "peer_target_bot.json")


def load_target():
    """the opponent's punch target (holder writes it from the session)"""
    try:
        with open(TARGET_FILE, encoding="utf-8") as f:
            t = json.load(f)
        if time.time() - t.get("seen", 0) < 120:
            ip = t["ip"]
            # carrier/CGNAT private ranges are unreachable from here --
            # punching them is wasted (and the phone being in one is
            # exactly why the server assigns a relay instead)
            if ip.startswith(("10.", "192.168.", "172.",
                              "169.254.", "100.")):
                return None
            return (ip, int(t["port"]))
    except (OSError, KeyError, ValueError, TypeError):
        pass
    return None


def stun_reflexive(sock):
    """binding query from OUR socket -> (ip, port) the internet sees"""
    for host, port in STUN:
        txid = os.urandom(12)
        try:
            sock.sendto(stun_msg(BIND_REQ, txid), (host, port))
            sock.settimeout(2.5)
            while True:
                data, _ = sock.recvfrom(2048)
                m = parse_binding(data)
                if m and m[1] == txid and m[0] == BIND_OK:
                    ep = mapped_addr(data)
                    if ep:
                        sock.settimeout(None)
                        return ep
        except (OSError, socket.timeout):
            continue
    sock.settimeout(None)
    return None


def main() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", PORT))
    log("bound udp :%d" % PORT)

    ep = stun_reflexive(sock)
    if ep:
        log("STUN reflexive -> %s:%d" % ep)
        ep_ip, ep_port = ep
        # advertise the PUBLIC reflexive address (honest source-IP
        # match; the server relays it to the opponent).  The tailnet
        # address was tried and gave zero packets -- private range,
        # likely stripped server-side or bypassed by the game socket.
        ts_note = ""
        try:
            import subprocess
            ts = subprocess.check_output(
                ["tailscale", "ip", "-4"], text=True,
                timeout=5).strip().splitlines()[0]
            ts_note = ts
        except Exception:                                   # noqa: BLE001
            pass
        with open(EP_FILE, "w", encoding="utf-8") as f:
            json.dump({"ip": ep_ip, "port": ep_port,
                       "local_port": PORT, "tailscale_ip": ts_note},
                      f)
        log("wrote %s (tailnet recorded: %s)" % (EP_FILE, ts_note or "-"))
    else:
        log("STUN failed on all servers -- endpoint NOT written "
            "(plan B: Tailscale on the phone)")

    log("listening for the phone (STUN punches + any packet)...")
    sent = 0
    last_target = None
    next_punch = 0.0        # monotonic pacing for outbound punches
    seen_peer = set()       # peers we already announced "path is open"
    quiet_peer = {}         # per-peer log throttle for inbound requests
    while True:
        # ---- outbound punch: the phone's address comes from the game
        # session (holder writes peer_target.json).  AWS security
        # groups are STATEFUL: our outbound packet opens the return
        # path, so the phone's punch then gets through.  This is what
        # real clients do (START_UDP_HOLE_PUNCHING_* in NTL).
        tgt = load_target()
        if tgt and tgt != last_target:
            log("punch target -> %s:%d" % tgt)
            last_target = tgt
        if tgt:
            # Pace outbound punches.  Without this the loop is a
            # positive feedback engine: an inbound binding request
            # falls through to `continue`, which sends another punch,
            # which is answered instantly -- thousands of packets per
            # second and the log eats the disk.  Real clients punch at
            # a fixed cadence (START_UDP_HOLE_PUNCHING_COMPLETE /
            # KEEP_UDP_HOLE_PUNCHING_COMPLETE in the game).
            now = time.monotonic()
            if now >= next_punch:
                next_punch = now + PUNCH_EVERY
                txid = os.urandom(12)
                try:
                    sock.sendto(stun_msg(BIND_REQ, txid), tgt)
                    sent += 1
                    if sent % 20 == 1:
                        log("punch #%d -> %s:%d" % (sent, tgt[0], tgt[1]))
                except OSError as e:
                    log("punch send failed: %s" % e)
        # NEVER block indefinitely: the original instance wedged in a
        # blocking recvfrom (settimeout(None)) before its target file
        # existed and never re-checked.  Always wake up and re-read.
        sock.settimeout(0.5)
        try:
            data, addr = sock.recvfrom(4096)
        except socket.timeout:
            continue
        except OSError as e:
            log("recv reset: %s (still listening)" % e)
            continue
        m = parse_binding(data)
        if m:
            mtype, txid = m
            peer = "%s:%d" % (addr[0], addr[1])
            # A confirmed path is announced ONCE per peer, and inbound
            # request lines are throttled -- the previous version logged
            # every packet, which under two responders looping on each
            # other wrote 27 MB in a minute.  Any binding reply from the
            # peer proves the path; matching our own txid exactly is
            # brittle because answers can outlive the txid we stored.
            if mtype == BIND_OK and peer not in seen_peer:
                seen_peer.add(peer)
                log("PUNCH ANSWERED by %s -- path is open" % peer)
            last_log = quiet_peer.get(peer, 0.0)
            now = time.monotonic()
            if mtype == BIND_REQ and now - last_log >= LOG_EVERY:
                quiet_peer[peer] = now
                log("STUN binding-req from %s (answering)" % peer)
            if mtype == BIND_REQ:
                # answer with THEIR view of us + our reflexive as xor
                body = b""
                # XOR-MAPPED-ADDRESS of the requester (v4)
                raw = bytes(a ^ b for a, b in zip(
                    socket.inet_aton(addr[0]), struct.pack(">I", MAGIC)))
                body += struct.pack(">HH", 0x0020, 8)
                body += struct.pack(">BBH", 0, 0x01,
                                    addr[1] ^ (MAGIC >> 16)) + raw
                sock.sendto(stun_msg(BIND_OK, txid, body), addr)
        else:
            now = time.monotonic()
            peer = "%s:%d" % (addr[0], addr[1])
            if now - quiet_peer.get(peer, 0.0) >= LOG_EVERY:
                quiet_peer[peer] = now
                log("DATA %d bytes from %s: %s"
                    % (len(data), peer, data[:64].hex()))
            # not STUN -- could be the match protocol; keep listening
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        log("stopped")
