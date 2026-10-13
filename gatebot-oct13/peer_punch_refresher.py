#!/usr/bin/env python3
"""peer_punch_refresher.py -- keep the two PeerLink bots punching EACH OTHER.

udp_punch.load_target() ignores a target file older than 120 s, so the two
instances need their target rewritten continuously.  Each bot advertises a
DISTINCT endpoint (owner :44000, bot :44001) because they share the one
public IP; a shared target file would aim both of them at the same socket.

This establishes the LATENCY_MODE_CONNECT layer (WAIT_SOCKET ->
CONNECT_SESSION) that chain3.py never performed: before this, neither bot
had ever received a single packet from the other, so no data plane existed
at all and the server stamped abnormal=DISCONN_HB within 2 s of START_GAME.

  python peer_punch_refresher.py     # foreground; rewrites every 20 s
"""
import json
import os
import time

WORK = os.path.dirname(os.path.abspath(__file__))

# owner socket <- punches from bot, and vice versa
TARGETS = {
    "peer_target.json":     ("3.80.79.52", 44001),   # owner aims at bot
    "peer_target_bot.json": ("3.80.79.52", 44000),   # bot aims at owner
}


def main() -> int:
    while True:
        for name, (ip, port) in TARGETS.items():
            path = os.path.join(WORK, name)
            try:
                with open(path, "w", encoding="utf-8") as f:
                    json.dump({"ip": ip, "port": port, "seen": time.time()}, f)
            except OSError as e:
                print("write %s failed: %s" % (name, e))
        time.sleep(20)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        pass
