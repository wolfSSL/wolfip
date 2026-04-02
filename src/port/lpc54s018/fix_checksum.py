#!/usr/bin/env python3
# fix_checksum.py - compute LPC vector table checksum
#
# The LPC54S018 boot ROM requires that vector table entries 0-7 sum to zero.
# The vector table starts at offset 0x200 in the binary (after the 512-byte
# SPIFI configuration block).
#
# This script patches entry[7] so that sum(entries[0:8]) == 0 (mod 2^32).

import struct
import sys

SPIFI_CONFIG_SIZE = 0x200  # 512-byte SPIFI config block before vector table

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <app.bin>")
        sys.exit(1)

    fname = sys.argv[1]
    with open(fname, 'r+b') as f:
        f.seek(SPIFI_CONFIG_SIZE)
        data = f.read(32)
        if len(data) < 32:
            print(f"Error: file too small (need at least {SPIFI_CONFIG_SIZE + 32} bytes)")
            sys.exit(1)

        vecs = list(struct.unpack('<8I', data))
        # Compute checksum: entry[7] = -(sum of entries 0-6) mod 2^32
        partial_sum = sum(vecs[:7]) & 0xFFFFFFFF
        cksum = (0x100000000 - partial_sum) & 0xFFFFFFFF
        vecs[7] = cksum

        # Write back
        f.seek(SPIFI_CONFIG_SIZE + 7 * 4)
        f.write(struct.pack('<I', cksum))

    # Verify
    with open(fname, 'rb') as f:
        f.seek(SPIFI_CONFIG_SIZE)
        vecs = struct.unpack('<8I', f.read(32))
        total = sum(vecs) & 0xFFFFFFFF
        if total != 0:
            print(f"ERROR: checksum verification failed (sum=0x{total:08X})")
            sys.exit(1)

    print(f"Vector checksum patched: entry[7]=0x{cksum:08X}")

if __name__ == '__main__':
    main()
