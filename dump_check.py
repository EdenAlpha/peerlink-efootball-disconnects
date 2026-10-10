import struct
P = r"C:\Users\Administrator\AppData\Local\Temp\2\artj\kgs-gappslive-36963768970\kgs\full"
maps = open(P + "\\maps.txt", errors="replace").read().splitlines()
print("libUE4.so regions:")
for m in maps:
    if "libUE4.so" in m:
        p = m.split()
        print(" ", p[0], p[1], p[2], p[5][-20:])

# maps: vaddr range, perms, file offset, dev, inode, path
# first maps line for libUE4.so has file offset 0 -> ELF header at dump offset for that region
# find the r-xp (executable) segment
for m in maps:
    if "libUE4.so" in m:
        p = m.split()
        if p[1].startswith("r-x"):
            print("\nexecutable segment:", p[0], "file_off", p[2])
            break

f = open(P + "\\full.bin", "rb")
# The ELF is contiguous within the region whose file offset == 0 in the maps line.
# maps line field p[2] is the file offset of the region within libUE4.so, not the dump offset.
# index.txt has the dump offset per region. Find the dump offset for the r--p first region (file_off 0).
index = open(P + "\\index.txt", errors="replace").read().splitlines()
print("\nindex entries for libUE4 regions:")
for line in index:
    if "libUE4" in line:
        print(" ", line[:90])
        break
