#!/usr/bin/env python3
"""addr_keys.py -- find the real key names of CMD_SET_ROOM_MATCH_READY's
address maps (address_ipv4 / address_ipv6) in libUE4.so.

The NET constant we send ({host_address, host_port, reflexive_address,
reflexive_port, nat_type}) was hand-invented from an EMPTY capture.  If
any key name is wrong, the server stores nothing and the phone has no
address to punch -> "Unable to connect" with zero packets at the
listener (observed 2026-10-11).

Method: find 'address_ipv4' setkey context in the binary, then print the
STR literals nearby in the same function region -- sibling keys of the
same serializer.
"""
import re
import sys

SO = (r"C:\Users\Administrator\Documents\Default Project"
      r"\peerlink-efootball-disconnects\efootball-apk"
      r"\native1110\libUE4.so")

data = open(SO, "rb").read()
strs = [(m.start(), m.group().decode())
        for m in re.finditer(rb"[ -~]{3,40}", data)]

for needle in ("address_ipv4", "address_ipv6"):
    idx = [i for i, (_, s) in enumerate(strs) if s == needle]
    print("\n%s hits: %d" % (needle, len(idx)))
    for i in idx[:4]:
        print("  == at 0x%x ==" % strs[i][0])
        for j in range(max(0, i - 30), min(len(strs), i + 31)):
            off, s = strs[j]
            mark = ">>" if j == i else "  "
            print("  %s 0x%08x %s" % (mark, off, s))

# also list every string containing these stem words anywhere
print("\nall strings with address/port/nat stems:")
stems = ("host_address", "host_port", "reflexive", "nat_type",
         "ip_addr", "relay_address", "local_address")
seen = set()
for _, s in strs:
    for st in stems:
        if st in s and s not in seen:
            seen.add(s)
            print("  %s" % s)
