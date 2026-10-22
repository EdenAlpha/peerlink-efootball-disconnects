#!/usr/bin/env python3
"""AF_PACKET STUN service for the two-phone lane (one instance per phone).

Architecture (deterministic, no tproxy socket-lookup folklore):
  - nft drops STUN between the phones' bridge and the Konami cluster IPs
    (nothing real reaches the games, nothing leaves the host),
  - this instance TAPS the bridge with AF_PACKET (like tcpdump),
  - frames whose INNER source is its own phone and whose inner destination
    is a cluster IP:parse are answered with a raw datagram whose SOURCE is
    the exact server identity the fabricator demands (partner ip:port for
    CHANGE-*), mapping the game to (fab_ip, the game's own source port),
  - unparseable cluster-bound frames are re-injected byte-for-byte.

The phone's UDP source port is never altered - the P2P NAT (nft) rewrites
only IPs, so every punch lands on the socket the game itself opened.
"""

import argparse
import socket
import struct
import sys
import time

import fabricator as F

ETHERTYPE_IPV4 = 0x0800
TARGET_IPS = sorted({ip for c in F.CLUSTERS for ip in c})


class RawSender:
    def __init__(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                               socket.IPPROTO_RAW)
        self.s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    def send(self, pkt, dst_ip):
        self.s.sendto(pkt, (dst_ip, 0))


class Tap:
    def __init__(self, bridge, phone_ip):
        self.s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                               socket.ntohs(0x0003))
        self.s.bind((bridge, 0x0003))
        self.phone_ip = phone_ip

    def frames(self):
        while True:
            frame = self.s.recv(65535)
            if len(frame) < 34 or (frame[12] << 8) | frame[13] != 0x0800:
                continue
            ip = frame[14:]
            if len(ip) < 20 or (ip[0] >> 4) != 4:
                continue
            total = (ip[2] << 8) | ip[3]
            ip = ip[:total]
            if total > len(frame) - 14 or (ip[6] << 8 | ip[7]) & 0x3FFF:
                continue                      # fragmented or malformed
            if ip[9] != 17:
                continue
            src = ".".join(str(b) for b in ip[12:16])
            dst = ".".join(str(b) for b in ip[16:20])
            if src != self.phone_ip:
                continue                      # not this phone's frame
            udp = ip[20:]
            if len(udp) < 8:
                continue
            yield udp, src, dst


def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def re_inject(sender, udp, src_ip, dst_ip):
    """Rebuild the original datagram untouched (forward-chain ate it)."""
    sport, dport = struct.unpack(">HH", udp[0:4])
    pkt = F.build_ipv4_udp(src_ip, dst_ip, sport, dport, udp[8:],
                           check_udp=False)
    sender.send(pkt, dst_ip)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bridge", required=True)
    ap.add_argument("--phone-ip", required=True)
    ap.add_argument("--fab-ip", required=True)
    ap.add_argument("--mode", choices=("passthrough", "answer"),
                    default="answer")
    ap.add_argument("--generic", action="store_true",
                    help="also answer STUN to non-cluster destinations")
    args = ap.parse_args()
    if args.mode == "passthrough":
        log("passthrough mode: tap is idle (use tcpdump for enumeration)")
        while True:
            time.sleep(3600)

    tap = Tap(args.bridge, args.phone_ip)
    sender = RawSender()
    log(f"stun service up mode={args.mode} fab={args.fab_ip} "
        f"tap={args.bridge} phone={args.phone_ip} generic={args.generic}")

    for udp, src_ip, dst_ip in tap.frames():
        sport, dport = struct.unpack(">HH", udp[0:4])
        if dst_ip not in TARGET_IPS or dport not in F.SERVER_PORTS:
            continue
        body = udp[8:]
        p = F.parse_stun_request(body)
        if p is None:
            re_inject(sender, udp, src_ip, dst_ip)
            log(f"unparseable cluster-bound request re-injected "
                f"{src_ip}:{sport} -> {dst_ip}:{dport}")
            continue

        cluster = F.cluster_for(dst_ip)
        if cluster is None:
            if not args.generic:
                re_inject(sender, udp, src_ip, dst_ip)
                log(f"NO-PROFILE re-injected {src_ip}:{sport} -> "
                    f"{dst_ip}:{dport} (add --generic or extend the set)")
                continue
            alt = F.SERVER_PORTS[1] if dport == F.SERVER_PORTS[0] \
                else F.SERVER_PORTS[0]
            rsource = (dst_ip, dport, dst_ip, dport, dst_ip, alt)
            payload = F.build_stun_response(p.txn, args.fab_ip, sport,
                                            rsource,
                                            (dst_ip, dst_ip, dst_ip),
                                            p.konami_ext)
            spoof_ip, spoof_port = dst_ip, dport
            tag = "generic"
        else:
            rsource = F.response_source(dst_ip, dport, p, cluster)
            payload = F.build_stun_response(p.txn, args.fab_ip, sport,
                                            rsource, cluster, p.konami_ext)
            spoof_ip, spoof_port = rsource[0], rsource[1]
            tag = F.TYPE_NAMES[F.classify_request(p)]

        reply_port = F.response_destination_port(p, sport)
        pkt = F.build_ipv4_udp(spoof_ip, src_ip, spoof_port, reply_port,
                               payload)
        sender.send(pkt, src_ip)
        log(f"STUN[{tag}] from {spoof_ip}:{spoof_port} -> "
            f"{src_ip}:{reply_port} mapped={args.fab_ip}:{sport}")


if __name__ == "__main__":
    sys.exit(main())
