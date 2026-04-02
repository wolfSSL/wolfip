#!/usr/bin/env python3
# fix_checksum.py - compute LPC vector table checksum
#
# The LPC54S018 boot ROM requires that vector table entries 0-7 sum to zero.
# Auto-detects whether vector table is at offset 0 (RAM build) or 0x200
# (SPIFI flash build with 512-byte config block).

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

def main():
    if len(sys.argv) != 2:
        print("Usage: %s <app.bin>" % sys.argv[0])
        sys.exit(1)

    fname = sys.argv[1]
    with open(fname, 'r+b') as f:
        data = f.read()
        off = find_vector_offset(data)

        if off + 32 > len(data):
            print("Error: file too small")
            sys.exit(1)

        vecs = list(struct.unpack_from('<8I', data, off))
        partial_sum = sum(vecs[:7]) & 0xFFFFFFFF
        cksum = (0x100000000 - partial_sum) & 0xFFFFFFFF

        f.seek(off + 7 * 4)
        f.write(struct.pack('<I', cksum))

    with open(fname, 'rb') as f:
        f.seek(off)
        vecs = struct.unpack('<8I', f.read(32))
        total = sum(vecs) & 0xFFFFFFFF
        if total != 0:
            print("ERROR: checksum verification failed (sum=0x%08X)" % total)
            sys.exit(1)

    print("Vector checksum patched: offset=0x%X entry[7]=0x%08X" % (off, cksum))

if __name__ == '__main__':
    main()
