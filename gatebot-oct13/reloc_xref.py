#!/usr/bin/env python3
"""reloc_xref.py -- xref a rodata literal in the 11.1.0 libUE4.so via the
Android RELATIVE relocation tables.

The shipping binary has no DT_RELA usable by the loader; strings are reached
through pointer tables in .data.rel.ro/.init_array whose on-disk slots are
R_AARCH64_RELATIVE (1027) relocations whose ADDEND is the string's vaddr.
Direct adrp+add refs exist too (cmd names), but the packed JSON keys are
table-driven -- that is why cmd_xref.py reported 0 xrefs for them.

  python reloc_xref.py reflexive_address nat_type game_sycom

Prints: literal -> string vaddr(s) -> table slot vaddr(s) -> code sites
(adrp+add building the slot address) -> containing function entries.
Then: python dump_fn.py <entry> to read the function itself.
"""
import struct
import sys

SO = (r"C:\Users\Administrator\Documents\Default Project"
      r"\peerlink-efootball-disconnects\efootball-apk"
      r"\native1110\libUE4.so")

KEYS = sys.argv[1:] or ["reflexive_address", "nat_type", "game_sycom"]
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
    return sections


secs = parse_elf(data)
text = secs[".text"]
text_lo, text_hi = text[3], text[3] + text[5]


def find_literal(k):
    b = k.encode()
    offs, st = [], 0
    while True:
        i = data.find(b, st)
        if i < 0:
            return offs
        offs.append(i)
        st = i + 1


def relative_slots(addrs):
    """R_AARCH64_RELATIVE entries whose addend is one of addrs -> [(slot,addend)]"""
    rela = secs[".rela.dyn"]
    off, sz, ent = rela[4], rela[5], rela[9] or 24
    want = set(addrs)
    out = []
    for i in range(sz // ent):
        r_offset, r_info, r_addend = struct.unpack_from("<QQq", data,
                                                        off + i * ent)
        if (r_info & 0xFFFFFFFF) == 1027 and r_addend in want:
            out.append((r_offset, r_addend))
    return out


def code_sites(slot):
    """adrp+add building `slot`, followed (anywhere later in window) by ldr."""
    hits = []
    for wi in range(text_lo // 4, text_hi // 4):
        w = struct.unpack_from("<I", data, wi * 4)[0]
        if w & 0x9F000000 != 0x90000000:
            continue
        pc = wi * 4
        immlo = (w >> 29) & 3
        immhi = (w >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        if imm & (1 << 20):
            imm -= 1 << 21
        page = (pc & ~0xFFF) + imm * 4096
        if page != (slot & ~0xFFF):
            continue
        for b in range(1, 12):
            off2 = pc + b * 4
            w2 = struct.unpack_from("<I", data, off2)[0]
            if (w2 & 0xFF800000) == 0x91000000:
                imm12 = (w2 >> 10) & 0xFFF
                if (w2 >> 22) & 1:
                    imm12 <<= 12
                if imm12 == (slot & 0xFFF):
                    hits.append(off2)
                break
    return hits


def fn_back(site, limit=0x8000):
    for i in range(0, limit, 4):
        off = (site & ~3) - i
        if off < text_lo:
            return None
        w = struct.unpack_from("<I", data, off)[0]
        # stp x29,x30,[sp,#..]!  /  sub sp,sp,#..  (with pacibsp before)
        if (w & 0xFFC003E0) == 0xA98003E0 or (w & 0xFFC003FF) == 0xD10003FF:
            return off
    return None


def str_at(vaddr):
    s = data[vaddr:vaddr + 60]
    out = b""
    for c in s:
        if 32 <= c < 127:
            out += bytes([c])
        else:
            break
    return out.decode()


for k in KEYS:
    offs = find_literal(k)
    print("== %s  literal@%s" % (k, ["0x%x" % o for o in offs][:6]))
    slots = relative_slots(offs)
    for slot, addend in slots[:8]:
        print("   slot 0x%x -> %r" % (slot, str_at(addend)[:48]))
        for site in code_sites(slot)[:8]:
            f = fn_back(site)
            print("      site 0x%x  fn 0x%x" % (site, f if f else 0))
