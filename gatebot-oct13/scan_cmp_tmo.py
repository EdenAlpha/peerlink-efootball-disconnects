import struct
from xref2 import Elf

SO = (r"C:\Users\Administrator\Documents\Default Project\peerlink-"
      r"efootball-disconnects\efootball-apk\native1110\libUE4.so")
e = Elf(SO)
_, _, _, tv, to, ts = e.sec(".text")
text = e.read(to, ts)

def ldr32(w):
    # LDR wt, [xn, #imm]  (unsigned offset, size=10 -> 32-bit)
    if (w & 0xFFC00000) == 0xB9400000:
        rt = w & 0x1F
        rn = (w >> 5) & 0x1F
        imm = ((w >> 10) & 0xFFF) * 4
        return rt, rn, imm
    return None

def cmp_imm(w):
    # SUBS (32-bit) with imm: cmp wn, #imm -> sf=0 op=1 S=1
    if (w &0xFF800000) == 0x71000001:
        imm = (w >> 10) & 0xFFF
        rn = (w >> 5) & 0x1F
        return rn, imm
    return None

hits = 0
n = len(text)
for i in range(0, n - 48, 4):
    w = struct.unpack_from("<I", text, i)[0]
    r = ldr32(w)
    if r is None:
        continue
    rt, rn, imm = r
    if imm not in (0x78, 0x7C, 0x80, 0x84):
        continue
    # look at next 12 insns for cmp rt, #10 / #30 / #300
    for k in range(4, 52, 4):
        w2 = struct.unpack_from("<I", text, i + k)[0]
        c = cmp_imm(w2)
        if c and c[0] == rt and c[1] in (10, 30, 300):
            print("vaddr 0x%x  ldr w%d,[x%d,#0x%x]  then cmp w%d,#%d @0x%x"
                  % (tv + i, rt, rn, imm, rt, c[1], tv + i + k))
            hits += 1
            break
print("total hits:", hits)
