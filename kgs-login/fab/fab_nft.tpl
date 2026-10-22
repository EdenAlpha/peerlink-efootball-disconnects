#!/usr/bin/env nft -f
/* Fab rules: TPROXY STUN interception + port-preserving P2P NAT.
 * Parameters are substituted by the caller (smoke_test.sh / lane arm):
 *   BRIDGE   interface the two phones' traffic enters on
 *   IPA/IPB  the two phones' real IPs on that bridge
 *   FA       fabricated IP of phone A (197.210.53.1)
 *   FB       fabricated IP of phone B (197.210.53.2)
 *   TA/TB    this instance's tproxy listen ports (47000 / 47001)
 *   KLIST    the STUN cluster address list, comma separated
 *   EXPIRED  ports the game sends STUN to (3478, 3479 unless enumeration
 *            proved otherwise)
 *
 * Port rule everywhere: DNAT/SNAT rewrite IPs only; ports pass untouched.
 * Every game socket port is the one the game itself bound, and the only
 * address that changes is the fabricated pair.
 */

table ip fab {
    set konamistun {
        type ipv4_addr
        flags interval
        elements = { KLIST }
    }

    chain pre {
        type filter hook prerouting priority mangle; policy accept;
        # phone A STUN -> fabricator instance A
        iifname "BRIDGE" ip saddr IPA ip daddr @konamistun \
            udp dport { EXPIRED } meta mark set 1 counter tproxy ip to :TA
        # phone B STUN -> fabricator instance B
        iifname "BRIDGE" ip saddr IPB ip daddr @konamistun \
            udp dport { EXPIRED } meta mark set 1 counter tproxy ip to :TB
    }

    chain natpre {
        type nat hook prerouting priority dstnat; policy accept;
        # A's game -> B's game (dst port preserved: the punch lands on the
        # exact socket B advertised through its gate session)
        iifname "BRIDGE" ip saddr IPA ip daddr FB meta l4proto udp \
            counter dnat ip to IPB
        # B's game -> A's game
        iifname "BRIDGE" ip saddr IPB ip daddr FA meta l4proto udp \
            counter dnat ip to IPA
    }

    chain natpost {
        type nat hook postrouting priority srcnat; policy accept;
        # mask the real source: each game sees only the fabricated peer
        oifname "BRIDGE" ip saddr IPA ip daddr IPB meta l4proto udp \
            counter snat ip to FA
        oifname "BRIDGE" ip saddr IPB ip daddr IPA meta l4proto udp \
            counter snat ip to FB
    }
}
