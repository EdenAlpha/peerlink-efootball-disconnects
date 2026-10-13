#!/usr/bin/env python3
"""plt_map.py -- exact PLT stub -> symbol map via GOT slot lookup.

Each aarch64 PLT stub: adrp x16, Page(GOT); ldr x17, [x16, #off8];
add x16, x16, #off; br x17.  The GOT slot address identifies the
relocation entry (rela.dyn JUMP_SLOT or rela.plt) -> symbol name.
Also: dump neighbors of a stub address given on argv.
"""
import struct
import sys

SO = (r"C:\Users\Administrator\Documents\Default Project"
      r"\peerlink-efootball-disconnects\efootball-apk"
      r"\native1110\libUE4.so")

data = open(SO, "rb").read()


def parse_elf(buf):
    (e_shoff,) = struct.unpack_from("<Q", buf, 0x28)
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", buf, 0x3A)
    shs = [struct.unpack_from("<IIQQQQIIQQ", buf, e_shoff + i * e_shentsize)
           for i in range(e_shnum)]
    shstr = shs[e_shstrndx]
    strtab = buf[shstr[4]:shstr[4] + shstr[5]]

    def nm(off):
        end = strtab.find(b"\x00", off)
        return strtab[off:end].decode(errors="replace")

    sections = {nm(s[0]): s for s in shs}
    dynsym, dynstr = sections[".dynsym"], sections[".dynstr"]
    dstr = buf[dynstr[4]:dynstr[4] + dynstr[5]]
    entsz = dynsym[9] or 24

    def dyn_name(i):
        (st_name,) = struct.unpack_from("<I", buf, dynsym[4] + i * entsz)
        end = dstr.find(b"\x00", st_name)
        return dstr[st_name:end].decode(errors="replace")

    # r_offset -> name  for JUMP_SLOT (aarch64 type 1027) in rela.dyn;
    # rela.plt entries are jump slots by definition
    gotmap = {}
    s = sections.get(".rela.dyn")
    if s:
        off, sz, ent = s[4], s[5], s[9] or 24
        for i in range(sz // ent):
            r_off, r_info = struct.unpack_from("<QQ", buf, off + i * ent)
            if (r_info & 0xFFFFFFFF) == 1027:
                gotmap[r_off] = dyn_name(r_info >> 32)
    s = sections.get(".rela.plt")
    if s:
        off, sz, ent = s[4], s[5], s[9] or 24
        for i in range(sz // ent):
            r_off, r_info = struct.unpack_from("<QQ", buf, off + i * ent)
            gotmap[r_off] = dyn_name(r_info >> 32)
    plt = sections.get(".plt") or sections.get(".plt.got")
    return plt, gotmap


plt_sec, gotmap = parse_elf(data)
print("plt 0x%x size 0x%x  JUMP_SLOTs: %d" % (plt_sec[3], plt_sec[5],
                                              len(gotmap)))

# decode stubs
stubs = {}          # addr -> symbol
unknown = 0
a = plt_sec[3] + 16  # skip PLT0
while a + 16 <= plt_sec[3] + plt_sec[5]:
    w0, w1, w2, w3 = struct.unpack_from("<4I", data, a)
    # adrp x16
    if w0 & 0x9F000000 == 0x90000000 and (w0 & 31) == 16:
        immlo = (w0 >> 29) & 3
        immhi = (w0 >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        if imm & (1 << 20):
            imm -= 1 << 21
        page = (a & ~0xFFF) + imm * 4096
        # ldr x17, [x16, #imm12*8]
        if w1 & 0xFFC003FF == 0xF9400211:
            imm12 = (w1 >> 10) & 0xFFF
            slot = page + imm12 * 8
            name = gotmap.get(slot)
            if name:
                stubs[a] = name
            else:
                stubs[a] = "<?got 0x%x>" % slot
                unknown += 1
    a += 16
print("stubs decoded: %d (unknown got: %d)" % (len(stubs), unknown))

# sanity: find socket/connect/send/recv/close/setsockopt
want = ("socket", "connect", "send", "recv", "sendto", "recvfrom",
        "setsockopt", "getaddrinfo", "freeaddrinfo", "htons", "close",
        "shutdown", "write", "read", "poll", "select")
found = {n: [] for n in want}
for addr, nm in stubs.items():
    base = nm.split("(")[0]
    if base in found:
        found[base].append(addr)
for n, addrs in found.items():
    if addrs:
        print("  %-14s %d stubs: %s" % (n, len(addrs),
                                        ["0x%x" % x for x in addrs[:4]]))
    else:
        print("  %-14s ABSENT" % n)

if len(sys.argv) > 1:
    # dump: given a bl target addr or any addr, show stub context
    pass
