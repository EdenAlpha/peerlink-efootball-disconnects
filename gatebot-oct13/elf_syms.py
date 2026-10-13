#!/usr/bin/env python3
"""elf_syms.py -- what does libUE4.so name the game's networking?

capture_appdata.py proved the 143 B -> 129 B heartbeat on the match-supervisor
DTLS channel is real and that our zero-filled records are never answered, so
the plaintext has to be reversed rather than guessed.  Before opening a
disassembler on a 162 MB binary, read the ELF symbol tables: an unstripped or
partially-stripped build names its own protocol handlers, and that turns
"find the code that writes 143 bytes" into a lookup.

  python elf_syms.py
  python elf_syms.py --k=ntl --k=peer --k=dtls
"""
import struct
import sys

SO = (r"C:\Users\Administrator\Documents\Default Project\peerlink-efootball-disconnects"
      r"\efootball-apk\native1110\libUE4.so")

DEFAULT_KEYS = ["dtls", "ssl_", "stun", "turn", "ntl", "peer", "punch",
                "relay", "keepalive", "heartbeat", "watchdog", "supervis",
                "session", "nat_", "hole", "disconn", "gamerelay", "sycom"]

S_SYMTAB, S_DYNSYM, S_STRTAB = 2, 11, 3


def read_shdrs(f):
    f.seek(0)
    ident = f.read(16)
    if ident[:4] != b"\x7fELF":
        raise SystemExit("not an ELF: %r" % SO)
    if ident[4] != 2:
        raise SystemExit("not ELF64")
    if ident[5] != 1:
        raise SystemExit("not little-endian")
    f.seek(16)
    (e_type, e_machine, _v, _entry, e_phoff, e_shoff, _flags, _ehsize,
     e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx) = struct.unpack(
        "<HHIQQQIHHHHHH", f.read(48))
    f.seek(e_shoff)
    raw = f.read(e_shentsize * e_shnum)
    out = []
    for i in range(e_shnum):
        b = raw[i * e_shentsize:(i + 1) * e_shentsize]
        (sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link,
         sh_info, sh_addralign, sh_entsize) = struct.unpack("<IIQQQQIIQQ", b[:64])
        out.append(dict(name=sh_name, type=sh_type, offset=sh_offset,
                        size=sh_size, link=sh_link, entsize=sh_entsize))
    # section-name string table
    shstr = out[e_shstrndx]
    f.seek(shstr["offset"])
    shstrtab = f.read(shstr["size"])
    for s in out:
        s["nm"] = cstr(shstrtab, s["name"])
    return out


def cstr(buf, off):
    end = buf.find(b"\x00", off)
    return buf[off:end].decode("utf-8", "replace") if end >= 0 else ""


def syms(f, shdrs, kind):
    res = []
    for s in shdrs:
        if s["type"] != kind:
            continue
        strtab = shdrs[s["link"]]
        f.seek(strtab["offset"])
        st = f.read(strtab["size"])
        ent = s["entsize"] or 24
        f.seek(s["offset"])
        n = s["size"] // ent
        # read in chunks so 162 MB never lands in one go
        step = 20000
        for base in range(0, n, step):
            f.seek(s["offset"] + base * ent)
            blob = f.read(ent * min(step, n - base))
            for j in range(len(blob) // ent):
                b = blob[j * ent:(j + 1) * ent]
                st_name, st_info, st_other, st_shndx, st_value, st_size = \
                    struct.unpack("<IBBHQQ", b[:24])
                name = cstr(st, st_name)
                if name:
                    res.append((name, st_value, st_size, s.get("nm")))
    return res


def main() -> int:
    keys = [a[4:].lower() for a in sys.argv[1:] if a.startswith("--k=")]
    if not keys:
        keys = DEFAULT_KEYS

    with open(SO, "rb") as f:
        shdrs = read_shdrs(f)
        tables = [(s.get("nm"), s["type"]) for s in shdrs
                  if s["type"] in (S_SYMTAB, S_DYNSYM)]
        print("symbol tables: %s" % tables)
        all_syms = []
        for kind, label in ((S_SYMTAB, ".symtab"), (S_DYNSYM, ".dynsym")):
            got = syms(f, shdrs, kind)
            print("  %-10s %d symbols" % (label, len(got)))
            all_syms.extend((label,) + t for t in got)

    print("\n=== %d total symbols, matching %d keys ==="
          % (len(all_syms), len(keys)))
    hits = {}
    for label, name, val, size, tab in all_syms:
        low = name.lower()
        for k in keys:
            if k in low:
                hits.setdefault(k, []).append((name, val, size, label))
                break

    for k in keys:
        got = hits.get(k, [])
        print("\n--- %r : %d ---" % (k, len(got)))
        for name, val, size, label in got[:40]:
            print("  0x%09x  %6d  %-8s %s" % (val, size, label, name))
        if len(got) > 40:
            print("  ... %d more" % (len(got) - 40))
    if not hits:
        print("\n  no symbol matched -- the binary is stripped; fall back to\n"
              "  the string table and the DTLS write call sites.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
