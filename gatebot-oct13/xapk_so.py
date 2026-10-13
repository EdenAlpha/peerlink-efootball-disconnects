#!/usr/bin/env python3
"""Extract libUE4.so from an eFootball XAPK and locate the SET_GAME_RESULT
command code by string xref.  Evidence-only, no network.

usage:
  python xapk_so.py <file.xapk> [--out libUE4_new.so]
  python xapk_so.py <file.xapk> --locate     # after extraction: string xrefs

Steps
  1. XAPK (zip, stored entries) -> inner split APK that contains
     lib/arm64-v8a/libUE4.so (11.0.1: config.arm64_v8a.apk).
  2. inner APK (zip, deflated) -> lib/arm64-v8a/libUE4.so.
  3. --locate: find "CmdSetGameResult.php" in the ELF, report adrp/add
     xrefs (the command ctor), then list the string table around it.
"""
import io
import os
import struct
import sys
import zipfile

NEEDLE = b"CmdSetGameResult.php"


def find_inner(xapk_path):
    with zipfile.ZipFile(xapk_path) as z:
        for name in z.namelist():
            if not name.lower().endswith(".apk"):
                continue
            with z.open(name) as f:
                head = f.read(4)
            if head != b"PK\x03\x04":
                continue
            # scan central directory for the lib entry without full read
            with zipfile.ZipFile(io.BytesIO(z.read(name))) as inner:
                for e in inner.infolist():
                    if e.filename.endswith("lib/arm64-v8a/libUE4.so"):
                        return name, e.file_size
    return None, None


def extract(xapk_path, out_path):
    inner, size = find_inner(xapk_path)
    if not inner:
        print("FAIL: no inner APK with lib/arm64-v8a/libUE4.so")
        return None
    print(f"inner split: {inner}  libUE4.so size={size}")
    with zipfile.ZipFile(xapk_path) as z:
        with z.open(inner) as f:
            data = f.read()
    with zipfile.ZipFile(io.BytesIO(data)) as inner_zip:
        with inner_zip.open("lib/arm64-v8a/libUE4.so") as f:
            blob = f.read()
    if len(blob) != size:
        print(f"WARN: size mismatch {len(blob)} != {size}")
    parent = os.path.dirname(os.path.abspath(out_path))
    os.makedirs(parent, exist_ok=True)
    with open(out_path, "wb") as o:
        o.write(blob)
    print(f"wrote {out_path} ({len(blob)} bytes)")
    return out_path


# ---- locate CmdSetGameResult.php via validated xref2 ---------------------

def _load_xref2():
    import importlib.util
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "..", "kgs-gate-cipher", "scripts", "xref2.py")
    path = os.path.normpath(path)
    if not os.path.exists(path):
        path = r"C:\Users\Administrator\Documents\Default Project" \
               r"\kgs-gate-cipher\scripts\xref2.py"
    spec = importlib.util.spec_from_file_location("xref2_real", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def locate(path):
    xref2 = _load_xref2()
    e = xref2.Elf(path)
    hits = []
    for t, fl, nm, addr, off, sz in e.sections:
        if nm in (".rodata", ".data", ".rodata.str1.16") or (fl & 2 and sz):
            chunk = e.read(off, sz)
            i = chunk.find(NEEDLE)
            while i >= 0:
                hits.append(addr + i)
                i = chunk.find(NEEDLE, i + 1)
    if not hits:
        print("FAIL: %r not found in ELF" % NEEDLE.decode())
        return
    for va in hits:
        print("string va=0x%x" % va)
    refs = xref2.find_xrefs(path, hits)
    for va, pcs in refs.items():
        if not pcs:
            print("  0x%x: no adrp/add xref" % va)
        for pc in pcs:
            print("  0x%x <- code 0x%x" % (va, pc))


def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return
    xapk = args[0]
    locate_mode = "--locate" in args
    out = None
    if "--out" in args:
        out = args[args.index("--out") + 1]
    if out is None:
        out = os.path.splitext(xapk)[0] + "_libUE4.so"
    if not (os.path.exists(out) and os.path.getsize(out) > 100000000):
        got = extract(xapk, out)
        if not got:
            return
    if locate_mode:
        locate(out)


if __name__ == "__main__":
    main()
