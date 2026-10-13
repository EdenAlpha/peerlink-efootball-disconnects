so = r"C:\Users\Administrator\Documents\Default Project\peerlink-efootball-disconnects\efootball-apk\native\lib\arm64-v8a\libUE4.so"
for g in [0x00c42eed]:
    with open(so, "rb") as f:
        f.seek(g - 0x100000)
        print("0x%08x -> %r" % (g, f.read(32).split(b"\x00")[0].decode("utf-8","replace")))
