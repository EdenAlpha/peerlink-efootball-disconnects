import struct
SO = r"C:\Users\Administrator\Documents\Default Project\peerlink-efootball-disconnects\efootball-apk\native\lib\arm64-v8a\libUE4.so"
with open(SO,"rb") as f:
    f.seek(0x09926d08 - 0x100000)
    d = f.read(8*16)
print([hex(v) for v in struct.unpack("<16Q", d)])
