#!/usr/bin/env python3
"""probe_relay_dtls.py -- parse the qualitycheck addresses properly and probe.

The gate's quality_check_data_list[i].address is a COMPOUND field, not a
single host:port.  Observed structure:

    a:5521,b:5521                       alternatives  (",")
    host/a:10000,b:10000                second group  ("/")
    ec2-x.ec2...:5521^ec2-y...:5521     elb members   ("^")
    host:50000@nogs                     trailing flag ("@nogs")

Ports seen: 5521, 30000, 50000, 443, 10000.  Each candidate is probed with
(a) the real client's DTLS 1.0 cookie ClientHello over UDP and (b) a TCP
connect, so we learn which transport each flavour of endpoint answers on.

  python probe_relay_dtls.py [--n 63] [--timeout 1.2]
"""
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\work")
sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\kgs-gate-cipher")

from room1 import Gate, load_capture, login, PACE        # noqa: E402

CH_BODY = bytes.fromhex(
    "010000aa00000000000000aafefd2ce000aae7c834630cfa8c0d48d28b2e1a4a5560"
    "a8b8750fbb4255563fd68db200000032c02cc030009fc02bc02f009ec024c028006b"
    "c023c0270067c00ac0140039c009c0130033009d009c003d003c0035")

HS = {2: "server_hello", 3: "hello_verify", 11: "cert", 12: "srv_key_ex",
      14: "srv_hello_done", 20: "finished"}
CT = {20: "CCS", 21: "alert", 22: "hs", 23: "appdata"}


def record(hs_type, body, version=0xfeff):
    hs = (bytes([hs_type]) + len(body).to_bytes(3, "big")
          + (0).to_bytes(2, "big") + (0).to_bytes(3, "big") + body)
    return (bytes([22]) + version.to_bytes(2, "big") + b"\x00\x00"
            + (0).to_bytes(6, "big") + len(hs).to_bytes(2, "big") + hs)


def label(p):
    out, i = [], 0
    while i + 13 <= len(p):
        ct = p[i]
        if ct not in CT:
            break
        ln = int.from_bytes(p[i + 11:i + 13], "big")
        if i + 13 + ln > len(p):
            break
        b = p[i + 13:i + 13 + ln]
        n = CT[ct]
        if ct == 22 and len(b) >= 4:
            n += "/" + HS.get(b[0], "hs%d" % b[0])
            if b[0] == 3 and len(b) > 6:
                n += " cookie=%d" % len(b[6:])
        out.append(n)
        i += 13 + ln
    return ",".join(out) or "raw%d" % len(p)


def split_addr(s):
    """compound address field -> [(host, port, flag), ...]"""
    out, groups = [], []
    for grp in s.replace("^", ",").split(","):
        for alt in grp.split("/"):
            alt = alt.strip()
            if alt:
                groups.append(alt)
    for g in groups:
        flag = ""
        if "@" in g:
            g, flag = g.split("@", 1)
            flag = "@" + flag
        if ":" not in g:
            continue
        host, _, port = g.rpartition(":")
        if port.isdigit() and host:
            out.append((host, int(port), flag))
    return out


def probe_udp(host, port, timeout):
    try:
        ip = socket.getaddrinfo(host, port, socket.AF_INET,
                                socket.SOCK_DGRAM)[0][4][0]
    except OSError as e:
        return "dns", str(e)[:40], ""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(record(1, CH_BODY), (ip, port))
        t0 = time.time()
        d, _ = s.recvfrom(2048)
        return "udp", "%s %dms" % (label(d), int((time.time() - t0) * 1000)), ip
    except socket.timeout:
        return "udp", "timeout", ip
    except OSError as e:
        return "udp", "err %s" % e, ip
    finally:
        s.close()


def probe_tcp(host, port, timeout):
    try:
        ip = socket.getaddrinfo(host, port, socket.AF_INET,
                                socket.SOCK_STREAM)[0][4][0]
    except OSError as e:
        return "tcp", "dns %s" % str(e)[:30], ""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        t0 = time.time()
        r = s.connect_ex((ip, port))
        if r == 0:
            return "tcp", "OPEN %dms" % int((time.time() - t0) * 1000), ip
        return "tcp", "closed(%d)" % r, ip
    except (socket.timeout, OSError) as e:
        return "tcp", "to" if isinstance(e, socket.timeout) else str(e)[:30], ip
    finally:
        s.close()


def main() -> int:
    n, timeout = 63, 1.2
    for a in sys.argv[1:]:
        if a.startswith("--n"):
            n = int(a.split("=", 1)[1])
        elif a.startswith("--timeout"):
            timeout = float(a.split("=", 1)[1])

    reqs, _ = load_capture()
    g = Gate()
    ok, r = login(g, reqs)
    print("login -> %s" % (r.get("result") if ok else r))
    if not ok:
        return 1
    time.sleep(PACE)

    resp = g.send(g.envelope("CMD_GET_GAMERELAY_QUALITYCHECK_LIST"), timeout=20)
    if resp.get("result") != "NOERR":
        print("qualitycheck -> %s" % resp.get("result"))
        return 1
    cdl = resp.get("quality_check_data_list") or []
    rows = [(e.get("region", "?"), e.get("address", "")) for e in cdl[:n]]
    print("qualitycheck -> NOERR %d regions\n" % len(rows))

    print("=== raw address shapes ===")
    for reg, addr in rows:
        print("  %-26s %s" % (reg, addr))

    # collect unique (host, port)
    cands = []
    for reg, addr in rows:
        for host, port, flag in split_addr(addr):
            if (host, port) not in cands:
                cands.append((host, port))
    print("\n=== %d unique host:port candidates ===" % len(cands))

    def job(hp):
        host, port = hp
        u = probe_udp(host, port, timeout)
        t = probe_tcp(host, port, timeout)
        return hp, u, t

    t0 = time.time()
    with ThreadPoolExecutor(max_workers=20) as ex:
        res = list(ex.map(job, cands))
    print("probed in %.1fs\n" % (time.time() - t0))

    print("%-46s %-6s %-30s %-24s" % ("host", "port", "UDP/DTLS", "TCP"))
    print("-" * 110)
    for (host, port), u, t in sorted(res, key=lambda x: (x[0][1], x[0][0])):
        print("%-46s %-6d %-30s %-24s"
              % (host[:46], port, "%s %s" % (u[0], u[1]), "%s %s" % (t[0], t[1])))

    live = [x for x in res if not x[1][1].startswith(("timeout", "dns"))
            and x[1][1] not in ("",)]
    print("\nUDP answered: %d/%d" % (len(live), len(res)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
