#!/usr/bin/env python3
# fix_checksum.py - Add LPC54S018M enhanced boot block to flash image
#
# The LPC54S018M boot ROM expects:
#   1. Image type magic 0xEDDC94BD at offset 0x24, and boot header offset (0x160)
#      at offset 0x28.
#   2. Boot header structure (25 words) at the offset specified above.
#   3. Vector checksum at offset 0x1C such that vectors[0..7] sum to 0.
#
# Without these, the boot ROM rejects the image and enters ISP mode instead
# of booting from SPIFI flash.
#
# This is what NXP calls the "enhanced boot block" / image header for SPIFI.
# Pattern derived from wolfBoot's Makefile rule for nxp_lpc54s018m target.
#
# For RAM-loaded builds (target_ram.ld) this script just patches the vector
# checksum since the boot ROM is bypassed.

import os
import struct
import sys


def find_vector_offset(data):
    """Detect vector table offset by checking for valid SP."""
    for off in (0, 0x200):
        if off + 32 > len(data):
            continue
        sp = struct.unpack_from('<I', data, off)[0]
        if 0x20000000 <= sp <= 0x20030000:
            return off
    return 0


def patch_vector_checksum(f, off):
    """Patch vector[7] (offset+0x1C) so vectors[0..7] sum to 0."""
    f.seek(off)
    d = f.read(28)
    w = struct.unpack('<7I', d)
    partial = sum(w) & 0xFFFFFFFF
    cksum = (0x100000000 - partial) & 0xFFFFFFFF
    f.seek(off + 0x1C)
    f.write(struct.pack('<I', cksum))
    return cksum


def write_enhanced_boot_block(f, image_size):
    """Write LPC54S018M enhanced boot block.

    Pattern from wolfBoot's Makefile rule for nxp_lpc54s018m target.
    The boot ROM reads:
      - 0x24: image type magic 0xEDDC94BD
      - 0x28: offset to boot header (0x160, matching wolfBoot)
      - 0x160: 25-word boot header

    Note: 0x24/0x28 fall in reserved Cortex-M vector slots (vector[9],[10])
    which are always zero, so overwriting them is safe. Vector table is
    trimmed to 81 entries (ends at 0x144) so 0x160 doesn't collide.
    """
    BOOT_HDR_OFFSET = 0x160

    # Image type magic at 0x24, boot header offset at 0x28
    f.seek(0x24)
    f.write(struct.pack('<2I', 0xEDDC94BD, BOOT_HDR_OFFSET))

    # Boot header structure (25 words)
    f.seek(BOOT_HDR_OFFSET)
    f.write(struct.pack('<25I',
        0xFEEDA5A5,    # magic
        3,             # image type
        0x10000000,    # load address
        image_size - 4,
        0, 0, 0, 0, 0,
        0xEDDC94BD,    # type magic
        0, 0, 0,
        0x001640EF,
        0, 0,
        0x1301001D,
        0, 0, 0,
        0x00000100,
        0, 0,
        0x04030050,
        0x14110D09))


def main():
    if len(sys.argv) != 2:
        print("Usage: %s <app.bin>" % sys.argv[0])
        sys.exit(1)

    fname = sys.argv[1]
    size = os.path.getsize(fname)

    with open(fname, 'r+b') as f:
        data = f.read()
        off = find_vector_offset(data)
        if off + 32 > len(data):
            print("Error: file too small")
            sys.exit(1)

        if off == 0:
            # Flash boot build: write enhanced boot block first
            if size < 0x160 + 100:
                print("Error: image too small for enhanced boot block")
                sys.exit(1)
            write_enhanced_boot_block(f, size)

        cksum = patch_vector_checksum(f, off)

    # Verify
    with open(fname, 'rb') as f:
        f.seek(off)
        vecs = struct.unpack('<8I', f.read(32))
        total = sum(vecs) & 0xFFFFFFFF
        if total != 0:
            print("ERROR: checksum verification failed (sum=0x%08X)" % total)
            sys.exit(1)

    if off == 0:
        print("Vector checksum patched: offset=0x%X entry[7]=0x%08X "
              "(+ enhanced boot block @ 0x24/0x160)" % (off, cksum))
    else:
        print("Vector checksum patched: offset=0x%X entry[7]=0x%08X" % (off, cksum))


if __name__ == '__main__':
    main()
