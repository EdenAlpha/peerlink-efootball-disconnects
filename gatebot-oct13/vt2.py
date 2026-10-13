import struct
SO = r"C:\Users\Administrator\Documents\Default Project\peerlink-efootball-disconnects\efootball-apk\native\lib\arm64-v8a\libUE4.so"
with open(SO,"rb") as f:
    f.seek(0x8922d08)
    d = f.read(8*48)
slots = struct.unpack("<48Q", d)
for i, v in enumerate(slots):
    print(i, hex(v))
