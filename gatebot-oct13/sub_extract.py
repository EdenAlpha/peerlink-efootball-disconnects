import os, sys
so = r"C:\Users\Administrator\Documents\Default Project\peerlink-efootball-disconnects\efootball-apk\native\lib\arm64-v8a\libUE4.so"
for g in [0x00bb4c4f, 0x00b415b3, 0x00c4be56, 0x00b84447, 0x00bd8969]:
    with open(so, "rb") as f:
        f.seek(g - 0x100000)
        b = f.read(40)
        print("0x%08x -> %r" % (g, b.split(b"\x00")[0].decode("utf-8","replace")))
# extract two sub-parsers from the main dump
D = r"C:\Users\Administrator\Documents\Default Project\work\ghidra_sgr"
WANT = ["077240d4", "0759614c"]
def blocks(path):
    cur, buf = None, []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.startswith("==== "):
                if cur is not None: yield cur, "".join(buf)
                cur = line.split()[1]; buf = [line]
            elif cur is not None: buf.append(line)
    if cur is not None: yield cur, "".join(buf)
out = []
for addr, text in blocks(os.path.join(D, "fulldump2_out.txt")):
    if addr in WANT:
        out.append(text)
        WANT.remove(addr)
    if not WANT: break
open(os.path.join(D, "..", "flow_sub.txt"), "w", encoding="utf-8").write("".join(out))
print("sub-parsers extracted: %s" % ("all" if not WANT else WANT))
