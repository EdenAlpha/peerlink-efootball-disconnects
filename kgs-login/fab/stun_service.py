#!/usr/bin/env python3
"""TPROXY STUN service for the two-phone lane.

Runs on the container host, one instance per phone:
  python3 stun_service.py --fab-ip 197.210.53.1 --listen-port 47000 --mode answer

 - receives the game's STUN via TPROXY (original destination intact),
 - answers with a raw datagram whose source is the exact server identity the
   fabricator logic demands (partner ip:port for CHANGE-* requests),
 - reports (fab_ip, the game's own source port) as the mapped address,
 - re-injects anything it refuses byte-for-byte, so nothing is eaten.

modes:
  passthrough  log-only (enumerate phase): every datagram forwarded untouched
  answer       proven profile for the cluster list; generic profile for an
               enumerated non-cluster STUN destination (with --generic);
               anything unparseable is re-injected + logged
"""

import argparse
import selectors
import socket
import struct
import sys
import time

import fabricator as F

SOL_IP = 0
IP_TRANSPARENT = 19
IP_RECVORIGDSTADDR = 20
SOL_SOCKET = 1
SO_MARK = 36

# cluster addresses carried in the TPROXY intercept set (matches the fabricator)
TARGET_IPS = sorted({ip for c in F.CLUSTERS for ip in c})


class RawSender:
    def __init__(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                               socket.IPPROTO_RAW)
        self.s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    def send(self, pkt, dst_ip, _dst_port=0):
        # for IP_HDRINCL sockets the packet carries its own ports
        self.s.sendto(pkt, (dst_ip, 0))


def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def build_listeners(listen_port, skb_mark, extra_ips=()):
    """One transparent UDP socket per interceptable original address.

    The tproxy socket lookup happens against the packet's original
    destination address, so a wildcard bind does NOT receive; each cluster
    IP is bound explicitly (IP_TRANSPARENT makes the bind possible).
    """
    sel = selectors.DefaultSelector()
    for ip in sorted(set(list(TARGET_IPS) + list(extra_ips))):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_IP, IP_TRANSPARENT, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setsockopt(socket.SOL_SOCKET, SO_MARK, skb_mark)
        s.setsockopt(socket.SOL_IP, IP_RECVORIGDSTADDR, 1)
        try:
            s.bind((ip, listen_port))
        except OSError as exc:
            log(f"bind {ip}:{listen_port} failed: {exc}")
            raise
        sel.register(s, selectors.EVENT_READ, ip)
        log(f"listening on {ip}:{listen_port}")
    return sel


def recv_one(sel):
    for key, _events in sel.select(timeout=2):
        listener = key.fileobj
        data, anc, _fl, src = listener.recvmsg(4096, 512)
        return data, anc, src
    return None, None, None


def find_orig_dst(anc):
    for level, ctype, cdata in anc:
        if level == SOL_IP and ctype == IP_RECVORIGDSTADDR:
            return cdata
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--fab-ip", required=True)
    ap.add_argument("--listen-port", type=int, required=True)
    ap.add_argument("--mode", choices=("passthrough", "answer"),
                    default="answer")
    ap.add_argument("--generic", action="store_true",
                    help="also answer STUN to non-cluster destinations")
    ap.add_argument("--skb-mark", type=int, default=1,
                    help="socket mark matching the TPROXY fwmark")
    ap.add_argument("--extra-bind", default="",
                    help="comma-separated extra ORIGINAL dst IPs to bind")
    args = ap.parse_args()

    sel = build_listeners(args.listen_port, args.skb_mark,
                          [x.strip() for x in args.extra_bind.split(",")
                           if x.strip()])
    sender = RawSender()
    log(f"stun service up mode={args.mode} fab={args.fab_ip} "
        f"listen=:{args.listen_port} generic={args.generic} "
        f"targets={len(TARGET_IPS)}")

    while True:
        data, anc, src = recv_one(sel)
        if not data:
            continue
        orig_dst = find_orig_dst(anc)
        if orig_dst is None or len(orig_dst) < 8 or len(data) < 8:
            continue
        dst_ip = socket.inet_ntoa(orig_dst[4:8])
        dst_port = struct.unpack(">H", orig_dst[2:4])[0]
        src_port = struct.unpack(">H", data[0:2])[0]

        if args.mode == "passthrough":
            pkt = F.build_ipv4_udp(src[0], dst_ip, src[1], dst_port, data,
                                   check_udp=False)
            sender.send(pkt, dst_ip)
            log(f"PASSTHR udp {src[0]}:{src[1]} -> {dst_ip}:{dst_port} "
                f"({len(data)}B)")
            continue

        body = data[8:]
        p = F.parse_stun_request(body)
        if p is None:
            pkt = F.build_ipv4_udp(src[0], dst_ip, src[1], dst_port, data,
                                   check_udp=False)
            sender.send(pkt, dst_ip)
            log(f"REJECT/unparseable re-injected {src[0]}:{src[1]} -> "
                f"{dst_ip}:{dst_port}")
            continue

        cluster = F.cluster_for(dst_ip)
        generic = False
        if cluster is None:
            if not args.generic or dst_port not in F.SERVER_PORTS:
                # keep the original packet moving; do not eat the game's STUN
                pkt = F.build_ipv4_udp(src[0], dst_ip, src[1], dst_port, data,
                                       check_udp=False)
                sender.send(pkt, dst_ip)
                log(f"NO-PROFILE passthrough {src[0]}:{src[1]} -> "
                    f"{dst_ip}:{dst_port}")
                continue
            generic = True

        fab_port = src_port
        if cluster is not None:
            rsource = F.response_source(dst_ip, dst_port, p, cluster)
            payload = F.build_stun_response(p.txn, args.fab_ip, fab_port,
                                            rsource, cluster, p.konami_ext)
            spoof_ip, spoof_port = rsource[0], rsource[1]
        else:
            alt = F.SERVER_PORTS[1] if dst_port == F.SERVER_PORTS[0] \
                else F.SERVER_PORTS[0]
            rsource = (dst_ip, dst_port, dst_ip, dst_port, dst_ip, alt)
            payload = F.build_stun_response(p.txn, args.fab_ip, fab_port,
                                            rsource,
                                            (dst_ip, dst_ip, dst_ip),
                                            p.konami_ext)
            spoof_ip, spoof_port = dst_ip, dst_port

        reply_port = F.response_destination_port(p, src_port)
        pkt = F.build_ipv4_udp(spoof_ip, src[0], spoof_port, reply_port,
                               payload)
        sender.send(pkt, src[0])
        log(f"STUN[{F.TYPE_NAMES[F.classify_request(p)]}] "
            f"from {spoof_ip}:{spoof_port} -> {src[0]}:{reply_port} "
            f"mapped={args.fab_ip}:{fab_port}"
            + (" (generic)" if generic else ""))


if __name__ == "__main__":
    sys.exit(main())
