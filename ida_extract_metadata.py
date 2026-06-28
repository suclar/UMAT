# -*- coding: utf-8 -*-
"""
IDA (9.x) script: extract global-metadata.dat from libil2cpp-5.so.

Run inside IDA with the libil2cpp.so IDB open:
    File > Script file...  ->  ida_extract_metadata.py
or from the command line:
    ida -A -Sida_extract_metadata.py libil2cpp.so

It reads the encrypted blob and the obfuscated decryptor straight from the IDB
and replays the routine on a Unicorn ARM64 CPU (no hand-ported crypto), then
writes a clean, header-restored global-metadata.dat next to the input.

Requires Unicorn in IDA's Python:  <ida_python> -m pip install unicorn
"""
import struct

import idaapi
import idc
import ida_segment

try:
    from unicorn import (
        Uc, UcError, UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN, #type: ignore
    )
    from unicorn.arm64_const import (
        UC_ARM64_REG_SP, UC_ARM64_REG_LR, UC_ARM64_REG_PC,
    )
except ImportError:
    raise SystemExit("Unicorn not installed. Run: <ida_python> -m pip install unicorn")

# ---- Constants from the analysis of certain libil2cpp.so versions ---------------------------
FUNC_VADDR  = 0x03DE202C   # decrypt_and_cache_buffer (sub_3DE202C)
META_VADDR  = 0x0A2BBBD8   # byte_A2BBBD8  - encrypted global-metadata.dat
CACHE_VADDR = 0x0CAAB5A8   # qword_CAAB5A8 - decrypt cache pointer (must be 0)

IL2CPP_MAGIC = 0xFAB11BAF
METADATA_VERSION = 31              # fallback if auto-detection fails
HEADER_PAIRS = 31                  # fallback pair count

# pair_count -> {versions, typeDefinitions pair index, methods pair index}.
# typeDefinitions (0x58) is identical for v27/v29/v31 and only confirms the
# family; Il2CppMethodDefinition is the real v29-vs-v31 split (0x20 vs 0x24,
# v31 added returnParameterToken).
HEADER_LAYOUTS = {
    31: {"versions": [27, 29, 31], "typedef_index": 19, "methods_index": 5},
    32: {"versions": [24, 27], "typedef_index": None, "methods_index": None},
    33: {"versions": [24], "typedef_index": None, "methods_index": None},
    34: {"versions": [24], "typedef_index": None, "methods_index": None},
}
METHODDEF_ELEM_TO_VERSION = [(0x24, 31), (0x20, 29)]
TYPEDEF_ELEMS = (0x58, 0x5C, 0x60)

PAGE = 0x1000
STACK_BASE = 0x1_0000_0000
STACK_SIZE = 0x0010_0000
RET_SENTINEL = 0x1_F000_0000


def align_down(x, a=PAGE):
    return x & ~(a - 1)


def align_up(x, a=PAGE):
    return (x + a - 1) & ~(a - 1)


def metadata_size_from_header(buf, pair_count=HEADER_PAIRS):
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
    """Recover the il2cpp metadata version from the (intact) header geometry."""
    if len(buf) < 16:
        return None
    header_size = struct.unpack_from("<I", buf, 8)[0]  # stringLiteralOffset
    if header_size < 0x40 or header_size > 0x400 or (header_size - 8) % 8 != 0:
        return None
    pair_count = (header_size - 8) // 8
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
    td_elem = None
    method_elem = None
    if layout:
        ti = layout["typedef_index"]
        if ti is not None and ti < pair_count:
            _off, td_sz = struct.unpack_from("<II", buf, 8 + ti * 8)
            for elem in TYPEDEF_ELEMS:
                if td_sz % elem == 0:
                    td_elem = elem
                    break
        mi = layout["methods_index"]
        if mi is not None and mi < pair_count:
            _off, m_sz = struct.unpack_from("<II", buf, 8 + mi * 8)
            hits = [(e, v) for e, v in METHODDEF_ELEM_TO_VERSION if m_sz % e == 0]
            if len(hits) == 1:
                method_elem, version = hits[0]
    if version is None and len(candidates) == 1:
        version = candidates[0]
    return {"header_size": header_size, "pair_count": pair_count,
            "chained": chained, "candidates": candidates,
            "typedef_elem": td_elem, "method_elem": method_elem,
            "version": version}


def main():
    uc = Uc(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN)

    # --- map the decryptor's code -------------------------------------------
    func = idaapi.get_func(FUNC_VADDR)
    if not func:
        raise SystemExit("decrypt_and_cache_buffer not found at 0x%X" % FUNC_VADDR)
    code_base = align_down(func.start_ea)
    code_size = align_up(func.end_ea) - code_base
    uc.mem_map(code_base, code_size)
    uc.mem_write(func.start_ea, idc.get_bytes(func.start_ea, func.end_ea - func.start_ea))
    print("[*] code  0x%X..0x%X" % (code_base, code_base + code_size))

    # --- map the encrypted metadata blob (whole owning segment) -------------
    seg = ida_segment.getseg(META_VADDR)
    data_base = align_down(seg.start_ea)                                #type: ignore
    data_end = align_up(seg.end_ea)                                     #type: ignore
    raw = idc.get_bytes(seg.start_ea, seg.end_ea - seg.start_ea) or b"" #type: ignore
    if not raw:  # segment may be huge; fall back to a generous window
        data_base = align_down(META_VADDR)
        data_end = align_up(META_VADDR + 0x0400_0000)
        raw = idc.get_bytes(META_VADDR, data_end - META_VADDR) or b""
        if not _is_mapped(uc, data_base):
            uc.mem_map(data_base, data_end - data_base)
        uc.mem_write(META_VADDR, raw)
    else:
        uc.mem_map(data_base, data_end - data_base)
        uc.mem_write(seg.start_ea, raw)                                 #type: ignore
    print("[*] data  0x%X..0x%X (%.1f MiB)" % (
        data_base, data_end, (data_end - data_base) / 1024 / 1024))

    # --- cache page (force 0 so decryption runs) ----------------------------
    cache_base = align_down(CACHE_VADDR)
    if not _overlaps(uc, cache_base):
        uc.mem_map(cache_base, PAGE)
    uc.mem_write(CACHE_VADDR, b"\x00" * 8)

    # --- stack ---------------------------------------------------------------
    uc.mem_map(STACK_BASE, STACK_SIZE)
    uc.reg_write(UC_ARM64_REG_SP, STACK_BASE + STACK_SIZE // 2)
    uc.reg_write(UC_ARM64_REG_LR, RET_SENTINEL)

    print("[*] emulating decrypt_and_cache_buffer ...")
    try:
        uc.emu_start(FUNC_VADDR, RET_SENTINEL)
    except UcError as e:
        print("[!] emulation error %s at pc=0x%X" % (e, uc.reg_read(UC_ARM64_REG_PC)))
        raise

    region_end = seg.end_ea if seg and META_VADDR < seg.end_ea else META_VADDR + len(raw)
    out = bytes(uc.mem_read(META_VADDR, region_end - META_VADDR))

    det = detect_metadata_version(out)
    if det and det.get("version"):
        version_out = det["version"]
        pair_count = det["pair_count"]
        print("[+] auto-detected metadata version = %d (header 0x%X, %d pairs, methoddef 0x%X)"
              % (version_out, det["header_size"], pair_count, det.get("method_elem") or 0))
    else:
        version_out = METADATA_VERSION
        pair_count = HEADER_PAIRS
        print("[!] version auto-detect failed; using fallback = %d" % version_out)

    size = metadata_size_from_header(out, pair_count)
    if not (0 < size <= len(out)):
        size = len(out)
    buf = bytearray(out[:size])
    struct.pack_into("<II", buf, 0, IL2CPP_MAGIC, version_out)

    out_path = idc.get_idb_path().rsplit(".", 1)[0] + "_global-metadata.dat"
    with open(out_path, "wb") as f:
        f.write(buf)
    print("[+] wrote %d bytes -> %s" % (len(buf), out_path))


def _is_mapped(uc, addr):
    try:
        uc.mem_read(addr, 1)
        return True
    except UcError:
        return False


def _overlaps(uc, base):
    for s, e, _p in uc.mem_regions():
        if s <= base < e:
            return True
    return False


if __name__ == "__main__":
    main()
