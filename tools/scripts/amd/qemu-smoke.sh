#!/usr/bin/env bash
#
# QEMU boot smoke test for a wolfIP AMD/Xilinx bare-metal port.
#
# Boots boards/<board>/app.elf under the matching mainline Xilinx QEMU machine,
# captures the UART console, and asserts the app reaches its "Ready" banner -
# i.e. startup (EL3/SVC), MMU, GIC, UART, the GEM bring-up and the wolfIP main
# loop all execute under emulation. The PHY autoneg/link waits time out
# gracefully under QEMU (no real link), and DHCP then falls back to a static IP,
# so reaching "Ready" is a robust gate that does not depend on QEMU's GEM PHY
# reporting link. (Full DHCP/echo over QEMU user-net is a separate, best-effort
# concern and is intentionally not wired here.)
#
# Usage: qemu-smoke.sh <zcu102|versal|zynq7000> [app.elf]
# Env:   QEMU_TIMEOUT (seconds, default 120), UART_LOG (default uart-<board>.log)
#
set -u

BOARD="${1:?usage: qemu-smoke.sh <zcu102|versal|zynq7000> [app.elf]}"
ELF="${2:-src/port/amd/boards/$BOARD/app.elf}"
TIMEOUT="${QEMU_TIMEOUT:-120}"
LOG="${UART_LOG:-uart-$BOARD.log}"

if [ ! -f "$ELF" ]; then
    echo "ERROR: app.elf not found: $ELF (build it first)" >&2
    exit 2
fi

# Per-board QEMU machine + console UART routing. The console UART differs per
# board (zcu102 = PS-UART0 = serial0; versal = PL011 = serial0; zynq7000 =
# UART1 = serial1, so serial0 is routed to null).
case "$BOARD" in
    zcu102)
        QEMU=qemu-system-aarch64
        MACHINE="xlnx-zcu102,secure=on"
        SERIAL=(-serial "mon:stdio")
        ;;
    versal)
        QEMU=qemu-system-aarch64
        MACHINE="xlnx-versal-virt"
        SERIAL=(-serial "mon:stdio")
        ;;
    zynq7000)
        QEMU=qemu-system-arm
        MACHINE="xilinx-zynq-a9"
        SERIAL=(-serial null -serial "mon:stdio")
        ;;
    *)
        echo "ERROR: unknown board '$BOARD'" >&2
        exit 2
        ;;
esac

if ! command -v "$QEMU" >/dev/null 2>&1; then
    echo "ERROR: $QEMU not found (install qemu-system-arm / qemu-system-aarch64)" >&2
    exit 2
fi

echo "=== QEMU smoke: $BOARD ($QEMU -M $MACHINE), elf=$ELF, timeout=${TIMEOUT}s ==="
: > "$LOG"

# Bare-metal load: -device loader sets PC to the ELF entry at the machine's
# reset EL (EL3 on the AArch64 machines, SVC on zynq-a9). No netdev is attached:
# the gate does not need networking, and an unconsumed -netdev would error out.
"$QEMU" -M "$MACHINE" -nographic -no-reboot \
    "${SERIAL[@]}" \
    -device "loader,file=$ELF,cpu-num=0" \
    >>"$LOG" 2>&1 &
QPID=$!

ok=0
fault=0
deadline=$((SECONDS + TIMEOUT))
while kill -0 "$QPID" 2>/dev/null; do
    if grep -qa "Ready" "$LOG"; then ok=1; break; fi
    # Hard-fault / abort markers from the exception vectors or QEMU itself.
    if grep -qaiE "synchronous exception|unhandled|abort|panic" "$LOG"; then
        fault=1; break
    fi
    if [ "$SECONDS" -ge "$deadline" ]; then break; fi
    sleep 2
done

kill "$QPID" 2>/dev/null
wait "$QPID" 2>/dev/null || true

echo "----- captured UART ($LOG) -----"
cat "$LOG"
echo "--------------------------------"

if [ "$ok" -eq 1 ]; then
    echo "PASS: $BOARD reached 'Ready' under QEMU"
    exit 0
fi
if [ "$fault" -eq 1 ]; then
    echo "FAIL: $BOARD hit a fault/abort marker before 'Ready'" >&2
    exit 1
fi
echo "FAIL: $BOARD did not reach 'Ready' within ${TIMEOUT}s" >&2
exit 1
