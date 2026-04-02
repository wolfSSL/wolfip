#!/bin/bash
# Flash wolfIP to LPC54S018M-EVK SRAM via pyocd (on-board Link2 CMSIS-DAP)
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ELF="${SCRIPT_DIR}/app.elf"
BIN="${SCRIPT_DIR}/app.bin"

[ -f "$ELF" ] || { echo "app.elf not found. Run 'make' first."; exit 1; }
[ -f "$BIN" ] || { echo "app.bin not found. Run 'make' first."; exit 1; }

# Extract initial SP (word 0) and entry point (word 1) from binary
INIT_SP=$(od -A n -t x4 -N 4 "$BIN" | awk '{print "0x"$1}')
ENTRY=$(od -A n -j 4 -t x4 -N 4 "$BIN" | awk '{print "0x"$1}')

echo "Loading app.elf to SRAM via pyocd"
echo "  SP: ${INIT_SP}, Entry: ${ENTRY}"

pyocd commander -t lpc54608 -c "
    halt;
    load ${ELF};
    write32 0xE000ED08 0x20000000;
    write32 0x40000220 0x78;
    wreg sp ${INIT_SP};
    wreg pc ${ENTRY};
    go;
    exit
"

echo "Done. Monitor UART: screen /dev/ttyACM0 115200"
