#!/usr/bin/env python3
"""q2.py -- query a fulldump2_out.txt (DECOMP-only region dump).

  python q2.py <dumpfile> <hexaddr>        print the block containing hexaddr
  python q2.py <dumpfile> find <regex>     print block headers matching regex
  python q2.py <dumpfile> head <n>         first n block headers
"""
import re
import sys


def blocks(path):
    cur = None
    buf = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if line.startswith("==== "):
                if cur:
                    yield cur, "".join(buf)
                cur = line
                buf = []
            elif cur is not None:
                buf.append(line)
    if cur:
        yield cur, "".join(buf)


def main():
    path = sys.argv[1]
    cmd = sys.argv[2] if len(sys.argv) > 2 else ""
    if cmd == "find":
        rx = re.compile(sys.argv[3], re.I)
        for head, _ in blocks(path):
            if rx.search(head):
                print(head.rstrip())
    elif cmd == "head":
        n = int(sys.argv[3])
        for i, (head, _) in enumerate(blocks(path)):
            if i >= n:
                break
            print(head.rstrip())
    else:
        addr = int(cmd, 16)
        for head, body in blocks(path):
            a = int(head.split()[1], 16)
            if a <= addr:
                best = (head, body)
            else:
                break
        else:
            best = None
        if best is None:
            print("no block <= %x" % addr)
            return
        head, body = best
        print(head.rstrip())
        print(body.rstrip()[:8000])


if __name__ == "__main__":
    main()
