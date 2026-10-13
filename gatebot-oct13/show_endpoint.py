#!/usr/bin/env python3
"""Show the address_ipv4 block each bot will now advertise."""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import chain3  # noqa: E402

for tag in ("owner", "bot"):
    net = chain3.endpoint_net(tag)
    print("%-6s host_address=%s:%s  reflexive=%s:%s  nat_type=%s" % (
        tag, net["host_address"], net["host_port"],
        net["reflexive_address"], net["reflexive_port"], net["nat_type"]))
