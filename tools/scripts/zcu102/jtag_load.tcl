# jtag_load.tcl - generic AArch64 JTAG bare-metal loader for ZCU102.
#
# Source-agnostic: works for any AArch64 EL3 bare-metal ELF whose
# loadable text + vectors fit in OCM (0xFFFC0000, 256 KiB).
# BSS / page-tables / DMA buffers can live in DDR; they get zeroed
# by the app's own startup code, so it doesn't matter that DDR has
# a JTAG-DAP 16-KiB alias bug at low addresses.
#
# Usage:
#   source /opt/Xilinx/2025.2/Vitis/settings64.sh   # for xsdb on PATH
#   FSBL_PSU_INIT_TCL=/path/to/psu_init.tcl \
#   APP_ELF=/path/to/app.elf \
#   APP_BIN=/path/to/app.bin \
#   xsdb tools/scripts/zcu102/jtag_load.tcl
#
# Set the ZCU102 SW6 boot-mode straps to ALL ON (JTAG mode 0000)
# and power the board on before running.
#
# This pattern was distilled from a working Xilinx PUF-provision
# JTAG loader. See src/port/amd/boards/zcu102/README.md and the comments in
# src/port/amd/boards/zcu102/jtag/boot.tcl for the full set of traps this
# loader is built to avoid.

set OCM_BASE 0xFFFC0000

if {![info exists ::env(APP_ELF)] || ![info exists ::env(APP_BIN)] \
    || ![info exists ::env(FSBL_PSU_INIT_TCL)]} {
    puts "Usage: APP_ELF=... APP_BIN=... FSBL_PSU_INIT_TCL=... xsdb $argv0"
    exit 1
}
foreach var {APP_ELF APP_BIN FSBL_PSU_INIT_TCL} {
    if {![file exists $::env($var)]} {
        puts "ERROR: $var = $::env($var) not found"
        exit 1
    }
}

# ---------------------------------------------------------------------
# Load a flat binary file to a target address via mwr -force, one 32-
# bit word at a time. Slow but reliable - bypasses xsdb's cache
# coherency logic which is broken on DDR after psu_init.
# ---------------------------------------------------------------------
proc load_binary {bin_file base_addr} {
    set fp [open $bin_file rb]
    set data [read $fp]
    close $fp
    set len [string length $data]

    set pad [expr {(4 - ($len % 4)) % 4}]
    if {$pad > 0} { append data [string repeat "\x00" $pad] }
    set words [expr {[string length $data] / 4}]

    puts "  loading $len bytes ($words words) to [format 0x%08X $base_addr]"

    targets -set -nocase -filter {name =~ "*PSU*"}
    for {set i 0} {$i < $words} {incr i} {
        set off [expr {$i * 4}]
        binary scan $data @${off}iu word
        mwr -force [format "0x%X" [expr {$base_addr + $off}]] \
                   [format "0x%X" [expr {$word & 0xFFFFFFFF}]]
        if {($i % 8192) == 0 && $i > 0} {
            puts "  [expr {$i * 100 / $words}]%..."
        }
    }
    puts "  100% done"
}

# ---------------------------------------------------------------------
# 1. Connect, system reset, force CSU JTAG bootmode.
# ---------------------------------------------------------------------
puts "Connecting..."
connect
puts "All targets:"
targets

targets -set -nocase -filter {name =~ "*PSU*"}
puts "System reset..."
rst -system
after 500

puts "Forcing JTAG boot mode (CSU 0xFF5E0200 <- 0x0100)..."
mwr 0xFF5E0200 0x0100
after 1000

# ---------------------------------------------------------------------
# 2. psu_init (DDR, clocks, MIO, UART, GEM).
# ---------------------------------------------------------------------
puts "Sourcing psu_init.tcl..."
source $::env(FSBL_PSU_INIT_TCL)
puts "psu_init..."
psu_init
after 1000
puts "psu_post_config..."
psu_post_config
after 500

# ---------------------------------------------------------------------
# 3. UART0 baud init at 115200 8N1 (100 MHz ref / 124 / 7 = 115207).
# ---------------------------------------------------------------------
puts "UART0 baud init..."
targets -set -nocase -filter {name =~ "*PSU*"}
mwr 0xFF000000 0x03      ;# CR: TX_RST + RX_RST
mwr 0xFF000004 0x20      ;# MR: 8N1
mwr 0xFF000018 124       ;# BAUDGEN.CD = 124
mwr 0xFF000034 6         ;# BAUDDIV.BDIV = 6
mwr 0xFF000000 0x114     ;# CR: TXEN + RXEN + STPBRK
after 100

foreach c [split "=== JTAG ready, loading app ===\r\n" ""] {
    scan $c %c v
    mwr -force 0xFF000030 $v
}
after 200

# ---------------------------------------------------------------------
# 4. Load the app binary into OCM.
# ---------------------------------------------------------------------
puts ""
puts "Loading: $::env(APP_BIN) at [format 0x%08X $OCM_BASE]"
load_binary $::env(APP_BIN) $OCM_BASE

# ---------------------------------------------------------------------
# 5. Install b . boot loop at default RVBAR_EL3 (0xFFFF0000).
# ---------------------------------------------------------------------
puts ""
puts "Installing RVBAR boot loop at 0xFFFF0000..."
targets -set -nocase -filter {name =~ "*PSU*"}
mwr -force 0xFFFF0000 0x14000000     ;# B . (aarch64 self-branch)
mwr -force 0xFFFF0004 0x14000000

# ---------------------------------------------------------------------
# 6. A53 #0: reset, halt, set PC, continue.
# ---------------------------------------------------------------------
puts ""
puts "Preparing A53 #0..."
targets -set -nocase -filter {name =~ "*A53*#0"}
rst -processor
after 200
catch {stop}
after 200
puts "PC after rst -processor (expect 0xFFFF0000): [rrd pc]"

# Pull entry point from the ELF.
set readelf "aarch64-none-elf-readelf"
if {[info exists ::env(READELF)]} { set readelf $::env(READELF) }
set entry [exec $readelf -h $::env(APP_ELF) \
           | grep "Entry point" | awk "{print \$NF}"]
puts "App ELF entry: $entry"
rwr pc $entry
puts "PC after rwr:  [rrd pc]"

puts ""
puts "Continuing app..."
con

after 500
puts "Detached. App is running."
disconnect
exit
