#!/usr/bin/env python3
"""diff_commands.py -- what does the real client send that chain3 never does?

chain3 replays the capture's command sequence and runs gRPC 28/28 clean, but
the server still stamps DISCONN_HB.  Rather than keep guessing which channel
the watchdog reads, enumerate the commands actually present in the 2026-10-12
capture and mark which ones chain3.py never mentions at all.  A command the
real client sends and we do not is a candidate for the missing step.

  python diff_commands.py
  python diff_commands.py --unmatched     only the ones we never send
"""
import re
import sys

sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\work")
sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\kgs-gate-cipher")

import decode_flows as DF                                         # noqa: E402

CHAIN3 = r"C:\Users\Administrator\Documents\Default Project\work\chain3.py"


def main() -> int:
    only = "--unmatched" in sys.argv
    blocks = DF.load()
    chain = open(CHAIN3, encoding="utf-8", errors="replace").read()

    order = []
    for idx, cmd, req, resp in blocks:
        if cmd not in order:
            order.append(cmd)

    # "mentioned" = the string appears anywhere (comments count);
    # "enveloped" = actually passed to Gate.envelope(), i.e. really sent
    direct = set(re.findall(r'envelope\(\s*"(CMD_[A-Z0-9_]+)"', chain))
    dynamic = set(re.findall(r"envelope\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)",
                             chain))

    print("capture: %d blocks, %d distinct commands" % (len(blocks), len(order)))
    print("chain3:  %d envelope() literals, %d dynamic (%s)\n"
          % (len(direct), len(dynamic), ", ".join(sorted(dynamic)) or "-"))
    missing, sent = [], []
    for cmd in order:
        hit = cmd in direct or cmd in chain
        env = cmd in direct
        (sent if hit else missing).append(cmd)
        if only and hit:
            continue
        tag = "OK  " if env else ("MENT" if hit else "MISS")
        print("  %s  %s" % (tag, cmd))

    never = [c for c in order if c not in chain]
    mentioned = [c for c in order
                 if c in chain and c not in direct and c not in dynamic]
    print("\n=== chain3 mentions %d/%d, envelope()s %d/%d ==="
          % (len(order) - len(never), len(order),
             len([c for c in order if c in direct]), len(order)))
    if never:
        print("\nNEVER MENTIONED IN chain3.py:")
        for c in never:
            print("  %s" % c)
    if mentioned:
        print("\nMENTIONED BUT NEVER PASSED TO envelope():")
        for c in mentioned:
            print("  %s" % c)
    if not never and not mentioned:
        print("\n  every capture command is actually sent by chain3")

    # commands chain3 sends that the capture never had
    chain_cmds = sorted(set(re.findall(r"CMD_[A-Z0-9_]+", chain)))
    extra = [c for c in chain_cmds if c not in order]
    print("\nchain3-only commands (%d):" % len(extra))
    for c in extra:
        print("  %s" % c)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
