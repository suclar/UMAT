# -*- coding: utf-8 -*-
"""
Extract the embedded, XOR-obfuscated `global-metadata.dat` from certain horse girl game's
ARM64 il2cpp library (libil2cpp.so).

The library hides global-metadata.dat as an encrypted blob at `byte_A2BBBD8`
(vaddr 0x0A2BBBD8).  A heavily control-flow-obfuscated routine
`decrypt_and_cache_buffer` (sub_3DE202C @ vaddr 0x03DE202C) decrypts it in
place on first call and caches the pointer in qword_CAAB5A8 (vaddr 0x0CAAB5A8).

Because the decryptor's control flow branches on the *encrypted* bytes, the
algorithm cannot be safely re-implemented by hand.  Instead we map the ELF
image into a Unicorn (QEMU) ARM64 CPU and execute the routine verbatim, then
read the now-decrypted blob back out.

Usage:
    python emulate_extract.py [path\\to\\libil2cpp.so] [out\\global-metadata.dat]
"""
import struct
import sys

from unicorn import (
    Uc, UcError, UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN, UC_HOOK_CODE,                #type: ignore
)
from unicorn.arm64_const import UC_ARM64_REG_SP, UC_ARM64_REG_LR, UC_ARM64_REG_PC

# ---- Target-specific constants (from IDA analysis of certain libil2cpp.so versions) ----------
FUNC_VADDR  = 0x03DE202C   # decrypt_and_cache_buffer (sub_3DE202C)
META_VADDR  = 0x0A2BBBD8   # byte_A2BBBD8  - encrypted global-metadata.dat
CACHE_VADDR = 0x0CAAB5A8   # qword_CAAB5A8 - decrypt cache pointer (must be 0)

IL2CPP_MAGIC = 0xFAB11BAF
METADATA_VERSION = 31               # fallback if auto-detection fails
HEADER_PAIRS = 31                   # fallback pair count (v29/v31 header = 0x100)

# --- il2cpp metadata version auto-detection ----------------------------------
# The game scrambles the sanity(+0) and version(+4) fields, but the table of
# (offset, size) section pairs is intact.  We recover the version in two steps:
#
# 1) Header geometry: stringLiteralOffset (the first pair's offset) equals the
#    header byte-size, giving the pair count -> a *family* of versions.
#
# 2) Structure sizes: versions inside a family share an identical header, so we
#    disambiguate via the byte size of specific metadata structures, recovered
#    from a section's total size divided down (section_size % elem_size == 0).
#
# IMPORTANT: typeDefinitions (Il2CppTypeDefinition) is 0x58 for ALL of v27/v29/
# v31, so it only confirms the family.  The real v29-vs-v31 discriminator is
# Il2CppMethodDefinition, which gained `returnParameterToken` in v31:
#     v27/v29 -> 0x20 (32 bytes),   v31 -> 0x24 (36 bytes).
#
# pair_count -> {versions, typedef pair index, methods pair index}
HEADER_LAYOUTS = {
    31: {"versions": [27, 29, 31], "typedef_index": 19, "methods_index": 5},
    32: {"versions": [24, 27], "typedef_index": None, "methods_index": None},
    33: {"versions": [24], "typedef_index": None, "methods_index": None},
    34: {"versions": [24], "typedef_index": None, "methods_index": None},
}
# Il2CppMethodDefinition element size -> version (within the 31-pair family).
METHODDEF_ELEM_TO_VERSION = [(0x24, 31), (0x20, 29)]
# Il2CppTypeDefinition element sizes we recognise (only confirms the family).
TYPEDEF_ELEMS = (0x58, 0x5C, 0x60)

STACK_BASE = 0x1_0000_0000          # well above the image
STACK_SIZE = 0x0010_0000
RET_SENTINEL = 0x1_F000_0000        # LR target used to stop emulation
PAGE = 0x1000


def align_up(x, a=PAGE):
    return (x + a - 1) & ~(a - 1)


def load_segments(data):
    """Return list of PT_LOAD segments (vaddr, file_off, filesz, memsz, flags)."""
    assert data[:4] == b"\x7fELF", "not an ELF file"
    assert data[4] == 2, "expected ELF64"
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize = struct.unpack_from("<H", data, 0x36)[0]
    e_phnum = struct.unpack_from("<H", data, 0x38)[0]
    segs = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type = struct.unpack_from("<I", data, off)[0]
        if p_type != 1:  # PT_LOAD
            continue
        p_flags = struct.unpack_from("<I", data, off + 4)[0]
        p_offset, p_vaddr, _p_paddr, p_filesz, p_memsz, _align = \
            struct.unpack_from("<QQQQQQ", data, off + 8)
        segs.append((p_vaddr, p_offset, p_filesz, p_memsz, p_flags))
    return segs


def metadata_size_from_header(buf, pair_count=HEADER_PAIRS):
    """Compute il2cpp metadata size = max(offset+size) over the header pairs.

    The game deliberately corrupts the `sanity` (offset 0) and `version`
    (offset 4) fields, so we do NOT rely on the magic.  The remaining header
    is a standard sequence of (offset, size) uint32 pairs and is intact.
    """
    total = 0
    for i in range(pair_count):
        pos = 8 + i * 8
        if pos + 8 > len(buf):
            break
        offset, size = struct.unpack_from("<II", buf, pos)
        end = offset + size
        if end <= len(buf):
            total = max(total, end)
    return total


def detect_metadata_version(buf):
    """Recover the il2cpp metadata version from the header geometry + structs.

    Returns a dict {header_size, pair_count, chained, candidates,
    typedef_elem, method_elem, version} or None if the buffer is not a
    recognisable il2cpp metadata header.
    """
    if len(buf) < 16:
        return None
    # stringLiteralOffset (first section) == size of the header in bytes.
    header_size = struct.unpack_from("<I", buf, 8)[0]
    if header_size < 0x40 or header_size > 0x400 or (header_size - 8) % 8 != 0:
        return None
    pair_count = (header_size - 8) // 8

    # Verify the pair table is a consistent, chained il2cpp header.
    prev_end = None
    chained = True
    for i in range(pair_count):
        off, sz = struct.unpack_from("<II", buf, 8 + i * 8)
        if off > len(buf) or off + sz > len(buf):
            chained = False
            break
        if i == 0 and off != header_size:
            chained = False
            break
        if prev_end is not None and sz != 0 and not (prev_end <= off <= prev_end + 16):
            chained = False
            break
        prev_end = off + sz

    layout = HEADER_LAYOUTS.get(pair_count)
    candidates = layout["versions"] if layout else []
    version = None
    typedef_elem = None
    method_elem = None
    if layout:
        ti = layout["typedef_index"]
        if ti is not None and ti < pair_count:
            _o, td_sz = struct.unpack_from("<II", buf, 8 + ti * 8)
            for elem in TYPEDEF_ELEMS:
                if td_sz % elem == 0:
                    typedef_elem = elem
                    break
        # Decisive v29-vs-v31 split: Il2CppMethodDefinition is 0x20 vs 0x24.
        mi = layout["methods_index"]
        if mi is not None and mi < pair_count:
            _o, m_sz = struct.unpack_from("<II", buf, 8 + mi * 8)
            hits = [(e, v) for e, v in METHODDEF_ELEM_TO_VERSION if m_sz % e == 0]
            if len(hits) == 1:
                method_elem, version = hits[0]
    if version is None and len(candidates) == 1:
        version = candidates[0]
    return {
        "header_size": header_size,
        "pair_count": pair_count,
        "chained": chained,
        "candidates": candidates,
        "typedef_elem": typedef_elem,
        "method_elem": method_elem,
        "version": version,
    }


def main():
    #TODO: del default paths and require args
    so_path = sys.argv[1] if len(sys.argv) > 1 else r".\libil2cpp.so"
    out_path = sys.argv[2] if len(sys.argv) > 2 else r".\global-metadata.dat"

    with open(so_path, "rb") as f:
        data = f.read()

    segs = load_segments(data)
    image_end = align_up(max(v + mz for v, _o, _fz, mz, _fl in segs))
    print(f"[*] image span: 0..0x{image_end:X} ({image_end/1024/1024:.1f} MiB)")

    uc = Uc(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN)

    # Map the whole image as one region and write each PT_LOAD's file bytes.
    uc.mem_map(0, image_end)
    for v, o, fz, _mz, _fl in segs:
        uc.mem_write(v, data[o:o + fz])
    print(f"[*] mapped {len(segs)} PT_LOAD segments")

    # Stack
    uc.mem_map(STACK_BASE, STACK_SIZE)
    uc.reg_write(UC_ARM64_REG_SP, STACK_BASE + STACK_SIZE // 2)
    uc.reg_write(UC_ARM64_REG_LR, RET_SENTINEL)

    # Ensure the decrypt cache pointer is 0 so the routine actually decrypts.
    uc.mem_write(CACHE_VADDR, b"\x00" * 8)

    # Optional progress/heartbeat so a hang is visible.
    state = {"count": 0}

    def hook(uc_, address, size, _user):
        state["count"] += 1
        if state["count"] % 50_000_000 == 0:
            print(f"    .. {state['count']:,} insns, pc=0x{address:08X}")

    uc.hook_add(UC_HOOK_CODE, hook)

    print(f"[*] running decrypt_and_cache_buffer @ 0x{FUNC_VADDR:08X} ...")
    try:
        uc.emu_start(FUNC_VADDR, RET_SENTINEL)
    except UcError as e:
        pc = uc.reg_read(UC_ARM64_REG_PC)
        print(f"[!] emulation error: {e} at pc=0x{pc:08X}")
        raise
    print(f"[+] done, executed {state['count']:,} instructions")

    # Read back the decrypted region.
    region_end = 0
    for v, _o, fz, _mz, _fl in segs:
        if v <= META_VADDR < v + fz:
            region_end = v + fz
            break
    if not region_end:
        region_end = META_VADDR + 0x0080_0000
    raw = uc.mem_read(META_VADDR, region_end - META_VADDR)

    magic, version = struct.unpack_from("<II", raw, 0)
    print(f"[*] decrypted header sanity =0x{magic:08X} version=0x{version:08X} ")


    # Auto-detect the real metadata version from the (intact) header geometry.
    det = detect_metadata_version(raw)
    if det:
        print(f"[*] header geometry: size=0x{det['header_size']:X} "
              f"pairs={det['pair_count']} chained={det['chained']}")
        info = []
        if det['typedef_elem']:
            info.append(f"typedef=0x{det['typedef_elem']:X}")
        if det['method_elem']:
            info.append(f"methoddef=0x{det['method_elem']:X}")
        if det['candidates']:
            extra = f" ({', '.join(info)})" if info else ""
            print(f"[*] candidate versions: {det['candidates']}{extra}")
    if det and det.get("version"):
        version_out = det["version"]
        pair_count = det["pair_count"]
        print(f"[+] auto-detected metadata version = {version_out}")
    else:
        version_out = METADATA_VERSION
        pair_count = HEADER_PAIRS
        print(f"[!] version auto-detect failed; using fallback = {version_out}")

    size = metadata_size_from_header(raw, pair_count)
    if not (0 < size <= len(raw)):
        print("[!] could not derive size from header; writing full region")
        size = len(raw)
    else:
        print(f"[*] metadata size (max offset+size) = {size:,} bytes")

    buf = bytearray(raw[:size])
    # Restore the standard il2cpp header so vanilla Il2CppDumper /
    # Il2CppInspector accept the file.  The rest of the header is intact.
    struct.pack_into("<II", buf, 0, IL2CPP_MAGIC, version_out)
    print(f"[*] restored sanity=0x{IL2CPP_MAGIC:08X} version={version_out}")

    with open(out_path, "wb") as f:
        f.write(buf)
    print(f"[+] wrote {len(buf):,} bytes -> {out_path}")


if __name__ == "__main__":
    """
    Default path is set to current directory
    if not other specified.
    """
    main()
