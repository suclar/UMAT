# manualop — global-metadata.dat extraction toolkit

*[English](#english) · [简体中文](#简体中文)*

---

## English

Tools for recovering the embedded, XOR-obfuscated **`global-metadata.dat`** from
certain horse girl game's ARM64 il2cpp library (`libil2cpp.so`).

Steam/DMM **`GameAssembly.dll`** support will be added in the future.

### Background

The library hides `global-metadata.dat` as an encrypted blob at `byte_A2BBBD8`
(vaddr `0x0A2BBBD8`). A heavily control-flow-obfuscated routine
`decrypt_and_cache_buffer` (`sub_3DE202C` @ vaddr `0x03DE202C`) decrypts it in
place on first call and caches the result pointer in `qword_CAAB5A8`
(vaddr `0x0CAAB5A8`).

Because the decryptor branches on the *encrypted* bytes themselves, the
algorithm cannot be safely re-implemented by hand. Instead these tools map the
ELF image into a **Unicorn (QEMU) ARM64 CPU** and execute the routine verbatim,
then read the now-decrypted blob back out.

The game additionally scrambles the metadata header's `sanity` (offset `+0`)
and `version` (offset `+4`) fields, while leaving the table of `(offset, size)`
section pairs intact. The scripts restore the standard header
(`sanity = 0xFAB11BAF`, `version = 31`) so that vanilla
**Il2CppDumper** / **Il2CppInspector** accept the output file.

### Files

| File | Purpose |
| --- | --- |
| [emulate_extract.py](emulate_extract.py) | **Main extractor.** Standalone (no IDA needed). Maps the ELF into Unicorn, runs the decryptor, auto-detects the metadata version, restores the header and writes a clean `global-metadata.dat`. |
| [ida_extract_metadata.py](ida_extract_metadata.py) | Same emulation, but reads the encrypted blob and decryptor straight from an open IDA (9.x) IDB. Run from inside IDA. |
| [analyze_meta.py](analyze_meta.py) | Sanity-checker. Prints the magic/version and the 31 `(offset, size)` header pairs of an extracted `.dat`, verifying that the sections chain and the file size matches `max(offset+size)`. |
| [probe.py](probe.py) | Low-level probe. Dumps the ELF `PT_LOAD` segments and disassembles the decryptor prologue (Capstone) to confirm the target addresses. |

### Requirements

```powershell
pip install unicorn capstone
```

Tested with Unicorn 2.1.4 + Capstone 5.0.7 on Python 3.13. 

### Usage

**Standalone extraction (recommended):**

```powershell
python emulate_extract.py [path\to\libil2cpp.so] [out\global-metadata.dat]
```
Will search local directory if path is not specified

Be patient when processing large file

**Inside IDA (libil2cpp.so IDB open):**

```
File > Script file...  ->  ida_extract_metadata.py
```

or from a shell:

```powershell
ida -A -S ida_extract_metadata.py [path\to\libil2cpp.so]
```

(Unicorn must be installed in IDA's Python: `<ida_python> -m pip install unicorn`.)

**Verify the result:**

```powershell
python analyze_meta.py
```

### How version auto-detection works

1. **Header geometry** — `stringLiteralOffset` (the first pair's offset) equals
   the header byte-size, which yields the pair count and therefore a *family* of
   versions (the 31-pair header covers v27/v29/v31).
2. **Structure sizes** — versions within a family share an identical header, so
   the version is disambiguated from structure byte-sizes recovered as
   `section_size % elem_size == 0`. The decisive v29-vs-v31 split is
   `Il2CppMethodDefinition`, which gained `returnParameterToken` in v31:
   v27/v29 → `0x20` (32 bytes), v31 → `0x24` (36 bytes). The game currently(2026-06-28) resolves to
   **v31**.

> Note: `Il2CppTypeDefinition` is `0x58` for all of v27/v29/v31, so it only
> confirms the family — it cannot distinguish the version on its own.

### Key addresses

| Symbol | Vaddr | Meaning |
| --- | --- | --- |
| `decrypt_and_cache_buffer` (`sub_3DE202C`) | `0x03DE202C` | The obfuscated decryptor |
| `byte_A2BBBD8` | `0x0A2BBBD8` | Encrypted `global-metadata.dat` blob |
| `qword_CAAB5A8` | `0x0CAAB5A8` | Decrypt cache pointer (must be `0` to force decryption) |

Decrypted size = `0x027C2C1C` = 41,692,188 bytes.

---

## 简体中文

用于从某个赛马拟人游戏的 ARM64 il2cpp 库（`libil2cpp.so`）中还原内嵌、
经XOR 混淆的 **`global-metadata.dat`** 的工具集。

Steam 与 DMM 版本支持将后续更新
### 背景

Powered by Claude OPUS 4.8

该库将 `global-metadata.dat` 以加密 blob 的形式藏在 `byte_A2BBBD8`
（虚拟地址 `0x0A2BBBD8`）。一个控制流被大量混淆的函数
`decrypt_and_cache_buffer`（`sub_3DE202C` @ 虚拟地址 `0x03DE202C`）会在首次调用时
就地解密，并把结果指针缓存到 `qword_CAAB5A8`（虚拟地址 `0x0CAAB5A8`）。

由于解密函数的分支依赖于*加密后的字节*本身，该算法无法安全地手工重写。因此这些
工具会把 ELF 镜像映射进 **Unicorn（QEMU）ARM64 CPU** 并原样执行该函数，再把解密
完成的 blob 读出来。

某游戏还额外打乱了元数据头部的 `sanity`（偏移 `+0`）和 `version`（偏移 `+4`）字
段，但保留了 `(offset, size)` 段表的完整性。脚本会恢复标准头部
（`sanity = 0xFAB11BAF`、`version = 31`），使原版的 **Il2CppDumper** /
**Il2CppInspector** 能够接受输出文件。

### 文件说明

| 文件 | 用途 |
| --- | --- |
| [emulate_extract.py](emulate_extract.py) | **主提取脚本。** 独立运行（无需 IDA）。把 ELF 映射进 Unicorn，运行解密函数，自动识别元数据版本，恢复头部并写出干净的 `global-metadata.dat`。 |
| [ida_extract_metadata.py](ida_extract_metadata.py) | 相同的模拟流程，但直接从已打开的 IDA（9.x）IDB 中读取加密 blob 和解密函数。在 IDA 内运行。 |
| [analyze_meta.py](analyze_meta.py) | 校验工具。打印已提取 `.dat` 的 magic/version 以及 31 组 `(offset, size)` 头部对，验证各段是否首尾相接、文件大小是否等于 `max(offset+size)`。 |
| [probe.py](probe.py) | 底层探测。输出 ELF 的 `PT_LOAD` 段，并用 Capstone 反汇编解密函数序言以确认目标地址。 |

### 环境依赖

```powershell
pip install unicorn capstone
```

已在 Python 3.13 上用 Unicorn 2.1.4 + Capstone 5.0.7 测试通过。

### 使用方法

**独立提取（推荐）：**

```powershell
python emulate_extract.py [libil2cpp.so 路径] [global-metadata.dat 输出路径]
```
未指定路径时将默认读取`manualop`目录下的`libil2cpp.so`并输出`GM.dat`至同目录

文件较大，坐和待宽

**在 IDA 内运行（已打开 [libil2cpp.so 路径] 的 IDB）：**

```
File > Script file...  ->  ida_extract_metadata.py
```

或从命令行：

```powershell
ida -A -S ida_extract_metadata.py [libil2cpp.so 路径]
```

（IDA 的 Python 中需先安装 Unicorn：`<ida_python> -m pip install unicorn`。）

**校验结果：**

```powershell
python analyze_meta.py
```

### 版本自动识别原理

1. **头部几何结构** —— `stringLiteralOffset`（第一组对的 offset）等于头部的字节
   大小，由此得到对的数量，进而确定一个版本*家族*（31 组对的头部涵盖
   v27/v29/v31）。
2. **结构体大小** —— 同一家族内的版本共用相同头部，因此通过
   `section_size % elem_size == 0` 还原出的结构体字节大小来区分版本。区分
   v29 与 v31 的决定性依据是 `Il2CppMethodDefinition`，它在 v31 新增了
   `returnParameterToken`：v27/v29 → `0x20`（32 字节），v31 → `0x24`（36 字节）。
   当前版本(2026-06-28)应判定为 **v31**。

> 注意：`Il2CppTypeDefinition` 在 v27/v29/v31 中都是 `0x58`，因此它只能确认家族，
> 无法单独区分版本。

### 关键地址（libil2cpp.so）

| 符号 | 虚拟地址 | 含义 |
| --- | --- | --- |
| `decrypt_and_cache_buffer`（`sub_3DE202C`） | `0x03DE202C` | 被混淆的解密函数 |
| `byte_A2BBBD8` | `0x0A2BBBD8` | 加密的 `global-metadata.dat` blob |
| `qword_CAAB5A8` | `0x0CAAB5A8` | 解密缓存指针（必须为 `0` 才会触发解密） |

解密后大小 = `0x027C2C1C` = 41,692,188 字节。
