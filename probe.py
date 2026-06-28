# -*- coding: utf-8 -*-
import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

# your path here, VA here is version-specific
SO = r"path\to\libil2cpp.so"
FUNC = 0x3DE202C
META = 0xA2BBBD8
CACHE = 0xCAAB5A8

with open(SO, "rb") as f:
    data = f.read()

# ELF64 program headers
e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
e_phentsize = struct.unpack_from("<H", data, 0x36)[0]
e_phnum = struct.unpack_from("<H", data, 0x38)[0]

loads = []
for i in range(e_phnum):
    off = e_phoff + i * e_phentsize
    p_type, p_flags = struct.unpack_from("<II", data, off)
    p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack_from("<QQQQQQ", data, off + 8)
    if p_type == 1:  # PT_LOAD
        loads.append((p_vaddr, p_offset, p_filesz, p_memsz, p_flags))

print("PT_LOAD segments:")
for v, o, fz, mz, fl in loads:
    print(f"  vaddr=0x{v:08X} off=0x{o:08X} filesz=0x{fz:08X} memsz=0x{mz:08X} flags={fl}")


def v2o(vaddr):
    for v, o, fz, mz, fl in loads:
        if v <= vaddr < v + fz:
            return o + (vaddr - v), fl
    return None, None


for name, va in [("FUNC", FUNC), ("META", META), ("CACHE", CACHE)]:
    fo, fl = v2o(va)
    print(f"{name} vaddr=0x{va:08X} -> file_off={('0x%X' % fo) if fo is not None else 'NOT IN FILE (bss?)'} flags={fl}")

# Disassemble first instructions of FUNC
fo, _ = v2o(FUNC)
if fo is not None:
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    print("\nDisasm @ FUNC:")
    for ins in md.disasm(data[fo:fo + 0x40], FUNC):
        print(f"  0x{ins.address:08X}: {ins.mnemonic} {ins.op_str}")

# Show encrypted bytes at META head
fo, _ = v2o(META)
if fo is not None:
    print("\nEncrypted META head (16 bytes):", data[fo:fo + 16].hex())
