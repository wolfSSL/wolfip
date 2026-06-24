#!/usr/bin/env python3
"""
elf2uf2.py - Minimal ELF -> UF2 converter for RP2350.

Replaces picotool for the simple "drag UF2 onto BOOTSEL drive" flow.
Reads PT_LOAD segments from the input ELF and emits 256-byte UF2 blocks
targeting the XIP flash window at 0x10000000.

Usage:
    elf2uf2.py app.elf app.uf2 [--family arm|riscv]

family default = arm (RP2350 Cortex-M33). Use riscv for Hazard3 builds.
"""

import struct
import sys
from pathlib import Path

UF2_MAGIC_START0 = 0x0A324655
UF2_MAGIC_START1 = 0x9E5D5157
UF2_MAGIC_END    = 0x0AB16F30
UF2_FLAG_FAMILY  = 0x00002000

FAMILY_RP2350_ARM_S   = 0xe48bff59
FAMILY_RP2350_RISCV   = 0xe48bff5b
FAMILY_RP2350_ARM_NS  = 0xe48bff5a

# ELF reading (32-bit, little-endian only - matches RP2350 builds).
def parse_elf_segments(elf_bytes):
    if elf_bytes[:4] != b'\x7fELF':
        raise SystemExit("not an ELF")
    if elf_bytes[4] != 1 or elf_bytes[5] != 1:
        raise SystemExit("only ELF32 little-endian supported")
    e_phoff   = struct.unpack_from('<I', elf_bytes, 0x1C)[0]
    e_phentsz = struct.unpack_from('<H', elf_bytes, 0x2A)[0]
    e_phnum   = struct.unpack_from('<H', elf_bytes, 0x2C)[0]
    segs = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsz
        p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = \
            struct.unpack_from('<IIIIIIII', elf_bytes, off)
        if p_type != 1:  # PT_LOAD
            continue
        if p_filesz == 0:
            continue
        data = elf_bytes[p_offset:p_offset + p_filesz]
        # The LMA (p_paddr) is the physical-load address. For XIP-flash
        # programs that's the 0x10... region. For sections that load via
        # the bootrom into SRAM (.data) the LMA is also in FLASH (AT >).
        segs.append((p_paddr, data))
    return sorted(segs, key=lambda s: s[0])

def emit_uf2(segs, family_id):
    # Coalesce into contiguous flat image keyed on absolute LMA.
    pages = {}
    for addr, data in segs:
        for i, b in enumerate(data):
            pages[addr + i] = b
    if not pages:
        raise SystemExit("no PT_LOAD data")
    lo = min(pages)
    hi = max(pages) + 1
    # Pad to 256-byte page boundary; UF2 page payload is 256 bytes.
    lo &= ~0xFF
    if hi & 0xFF:
        hi = (hi + 0x100) & ~0xFF
    total_blocks = (hi - lo) // 256
    out = bytearray()
    for blk in range(total_blocks):
        page_addr = lo + blk * 256
        payload = bytes(pages.get(page_addr + i, 0) for i in range(256))
        hdr = struct.pack('<IIIIIIII',
                          UF2_MAGIC_START0, UF2_MAGIC_START1,
                          UF2_FLAG_FAMILY,
                          page_addr,
                          256, blk, total_blocks, family_id)
        body = payload + bytes(476 - 256)
        tail = struct.pack('<I', UF2_MAGIC_END)
        out += hdr + body + tail
    return bytes(out)

def main():
    if len(sys.argv) < 3:
        print(__doc__, file=sys.stderr); sys.exit(2)
    elf = Path(sys.argv[1])
    uf2 = Path(sys.argv[2])
    family = 'arm'
    for a in sys.argv[3:]:
        if a.startswith('--family='): family = a.split('=', 1)[1]
        elif a == '--family' and sys.argv.index(a) + 1 < len(sys.argv):
            family = sys.argv[sys.argv.index(a) + 1]
    fid = {'arm': FAMILY_RP2350_ARM_S,
           'arm-ns': FAMILY_RP2350_ARM_NS,
           'riscv': FAMILY_RP2350_RISCV}.get(family)
    if fid is None:
        raise SystemExit("--family must be arm | arm-ns | riscv")
    segs = parse_elf_segments(elf.read_bytes())
    blob = emit_uf2(segs, fid)
    uf2.write_bytes(blob)
    print(f"wrote {uf2} ({len(blob)} bytes, "
          f"{len(blob)//512} blocks, family={family}, fid=0x{fid:08x})")

if __name__ == '__main__':
    main()
