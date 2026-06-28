# -*- coding: utf-8 -*-
import struct

# your path here
p = r"path\to\global-metadata.dat"

d = open(p, "rb").read()
print("file len:", len(d))
magic, version = struct.unpack_from("<II", d, 0)
print(f"magic   = 0x{magic:08X}")
print(f"version = 0x{version:08X} ({version})")

print("\nheader (offset,size) pairs:")
maxend = 0
consistent_chain = True
prev_end = None
for i in range(31):
    off, sz = struct.unpack_from("<II", d, 8 + i * 8)
    end = off + sz
    maxend = max(maxend, end)
    tag = ""
    if prev_end is not None and off == prev_end:
        tag = "  <- chained"
    prev_end = end
    print(f"  pair {i:2d} @0x{8+i*8:03X}: off=0x{off:08X} ({off:>10}) size=0x{sz:08X} ({sz:>10}) end=0x{end:08X}{tag}")

print(f"\nmax(offset+size) = 0x{maxend:08X} = {maxend:,}")
print("file vs computed:", len(d), "vs", maxend, "->", "MATCH" if len(d) == maxend else "diff %d" % (len(d) - maxend))
