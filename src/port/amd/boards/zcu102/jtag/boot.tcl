# JTAG load of the wolfIP A53-0 bare-metal app on ZCU102.
#
# Pattern adapted from a known-working ZynqMP JTAG bare-metal loader
# (puf-provision/run.tcl). Key differences from earlier attempts that
# all failed silently:
#   1. Force JTAG bootmode via CSU register write (mwr 0xFF5E0200 0x0100).
#      Without this, rst -system leaves the SoC in a state where dow
#      eventually fails or the core won't resume.
#   2. Use psu_init.tcl directly (no FSBL stage). FSBL on this board has
#      a JTAG-mode park (WFE deep-sleep) that 'con' cannot wake.
#   3. Use mwr -force per word to write the raw binary instead of dow.
#      xsdb's dow path on DDR has a cache-flush dance that fails after
#      psu_init runs.
#   4. Install a 'b .' bootloop at the A53 default RVBAR (0xFFFF0000)
#      so rst -processor is safe and doesn't fly off into garbage.
#   5. After dow, target A53, rst -processor, stop, rwr pc, con.
#
# Env vars (set by jtag/boot.sh):
#   APP_BIN       path to the raw binary (objcopy -O binary app.elf app.bin)
#   APP_ELF       path to the ELF (for entry point reading)
#   PSU_INIT_TCL  path to psu_init.tcl

set OCM_BASE 0xFFFC0000
# DDR layout uses 0x10000000 (matches WOLFBOOT_LOAD_ADDRESS in
# wolfBoot's config/examples/zynqmp.config). The jtag/boot.sh script
# exports APP_LOAD_ADDR if set, otherwise defaults to the OCM base.
# Use scan to convert a hex string ("0x10000000") to an integer the
# rest of this script can compare and pass to mwr / dow.
if {[info exists env(APP_LOAD_ADDR)]} {
    scan $env(APP_LOAD_ADDR) "%i" APP_LOAD_ADDR
} else {
    set APP_LOAD_ADDR $OCM_BASE
}

# Load a raw binary file to a target address via mwr -force, one
# 32-bit word at a time. Slow but reliable - bypasses xsdb's cache
# coherency logic that breaks dow on DDR after psu_init.
proc load_binary {bin_file base_addr} {
    set fp [open $bin_file rb]
    set data [read $fp]
    close $fp
    set len [string length $data]

    # Pad to 4-byte alignment.
    set pad [expr {(4 - ($len % 4)) % 4}]
    if {$pad > 0} {
        append data [string repeat "\x00" $pad]
    }
    set padded [string length $data]
    set words [expr {$padded / 4}]

    puts "  loading [format %d $len] bytes ($words words) to [format 0x%08X $base_addr]"

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
    return $len
}

# ----------------------------------------------------------------------
# 1. Connect, system reset, force JTAG bootmode.
# ----------------------------------------------------------------------
puts "Connecting..."
connect

# Enumerate the JTAG chain explicitly. Without this poke, the DAP /
# PSU / APU targets are sometimes not visible immediately after the
# hw_server attach - 'targets' will only show PS TAP / PMU / PL.
puts "JTAG chain:"
jtag targets

puts "All targets:"
targets

puts "System reset..."
# On a cold board in JTAG boot mode the PSU/APU node is not enumerated
# until the PMU has been reset -- only PS TAP / PMU / PL are visible at
# connect. Select the PMU for the system reset; the PSU node (with the
# A53 cores) appears afterwards for the steps below. Filtering for
# "*PSU*" before this reset fails on a freshly powered board.
targets -set -nocase -filter {name =~ "PMU"}
rst -system
after 1500

# ----------------------------------------------------------------------
# 1b. Load and start PMU firmware (MicroBlaze on the PMU).
#
# Without PMU FW, JTAG writes to DDR after psu_init are unreliable on
# this board -- the DDR controller training appears to need PMU
# coordination. Loading PMU FW via JTAG mirrors what the CSU
# BootROM would do during a normal SD/QSPI boot. Only do this if
# PMUFW_ELF is set in the environment; otherwise we keep the OCM-only
# behavior we had in Phase 1. We do this BEFORE the CSU JTAG-bootmode
# write because CSU touches PMU on the bootmode handshake.
# ----------------------------------------------------------------------
if {[info exists env(PMUFW_BIN)]} {
    puts ""
    puts "Loading PMU FW: $env(PMUFW_BIN)"
    # xsdb's `dow` fails on PMU MicroBlaze without a loaded XSA
    # ("Invalid context"). Bypass it by writing the binary via
    # mwr-force to PMU IRAM at 0xFFDC0000 -- same technique we use
    # for the A53 app. The PMU's BootROM hands control to IRAM @
    # 0xFFDC0000 after we deassert PMU reset (psu_init touches PMU
    # via CRL_APB.RST_LPD_TOP which keeps PMU running).
    jtag targets
    targets -set -nocase -filter {name =~ "PMU"}
    stop
    after 200
    load_binary $env(PMUFW_BIN) 0xFFDC0000
    con
    after 1500
    puts "PMU FW running."
}

puts "Forcing JTAG boot mode (CSU)..."
targets -set -nocase -filter {name =~ "*PSU*"}
mwr 0xFF5E0200 0x0100
after 1000

# ----------------------------------------------------------------------
# 2. psu_init - DDR, clocks, MIO, UART, GEM3 pinmux.
# ----------------------------------------------------------------------
puts "Sourcing psu_init.tcl..."
source $env(PSU_INIT_TCL)
puts "psu_init..."
psu_init
after 1000
puts "psu_post_config..."
psu_post_config
after 500

# ----------------------------------------------------------------------
# 3. UART0 baud init (FSBL would do this; psu_init alone doesn't).
# ----------------------------------------------------------------------
puts "UART0 baud init (115200 8N1 at 100 MHz ref)..."
targets -set -nocase -filter {name =~ "*PSU*"}
mwr 0xFF000000 0x03      ;# CR: TX_RST + RX_RST
mwr 0xFF000004 0x20      ;# MR: 8N1
mwr 0xFF000018 124       ;# BAUDGEN: CD = 124
mwr 0xFF000034 6         ;# BAUDDIV: BDIV = 6
mwr 0xFF000000 0x114     ;# CR: TXEN + RXEN + STPBRK
after 100

# Banner write so we can see UART is live before our app starts.
foreach c [split "=== JTAG ready, loading app ===\r\n" ""] {
    scan $c %c v
    mwr -force 0xFF000030 $v
}
after 200

# ----------------------------------------------------------------------
# 4. Load the wolfIP app.
#
# For the OCM layout we use mwr-force per-word (load_binary): the
# native xsdb `dow` path triggers a cache-flush dance that fails after
# psu_init when targeting OCM. For the DDR layout that workaround is
# not necessary -- the AXI master path is reliable to DDR once the
# DDR controller is up, and `dow` is much faster than the
# word-at-a-time fallback. Choose based on APP_LOAD_ADDR: anything
# >= 0xFF000000 is OCM/peripheral and gets the slow safe path; below
# that is DDR and uses dow on the ELF directly.
# ----------------------------------------------------------------------
puts ""
puts "Loading: $env(APP_BIN) at [format 0x%X $APP_LOAD_ADDR] via mwr-force"
load_binary $env(APP_BIN) $APP_LOAD_ADDR
# Verify the first word landed. KNOWN ISSUE: with APP_LOAD_ADDR in DDR
# (e.g. 0x10000000), single-word mwr-force writes succeed but the
# bulk per-word loop in load_binary frequently shows the first word
# read back as something other than what we wrote, even with PMU FW
# running. The same xsdb cache/coherency dance that breaks `dow` over
# DDR after psu_init appears to be at play. The OCM target works
# reliably. Track this separately; the DDR path will be exercised
# end-to-end via SD/QSPI once wolfBoot's bootgen chain is set up.
if {$APP_LOAD_ADDR < 0xFF000000} {
    set fp [open $env(APP_BIN) rb]
    set head [read $fp 4]
    close $fp
    binary scan $head iu expect
    set got [mrd -value -force [format 0x%X $APP_LOAD_ADDR]]
    puts [format "  verify: image\[0\]=0x%08X mem\[0\]=0x%08X %s" \
          $expect $got [expr {$expect == $got ? "OK" : "MISMATCH (known JTAG-DDR issue)"}]]
}

# ----------------------------------------------------------------------
# 5. Install RVBAR boot loop in OCM so rst -processor doesn't crash.
# ----------------------------------------------------------------------
puts ""
puts "Installing RVBAR boot loop at 0xFFFF0000..."
targets -set -nocase -filter {name =~ "*PSU*"}
mwr -force 0xFFFF0000 0x14000000   ;# B . (branch to self, aarch64)
mwr -force 0xFFFF0004 0x14000000

# ----------------------------------------------------------------------
# 6. A53 #0: reset, halt, set PC, continue.
# ----------------------------------------------------------------------
puts ""
puts "Preparing A53 #0..."
targets -set -nocase -filter {name =~ "*A53*#0"}
rst -processor
after 200
catch {stop}
after 200
puts "PC after rst -processor (should be RVBAR 0xFFFF0000): [rrd pc]"

set readelf [expr {[info exists env(READELF)] ? $env(READELF) : "aarch64-none-elf-readelf"}]
set entry [exec $readelf -h $env(APP_ELF) | grep "Entry point" | awk "{print \$NF}"]
puts "App ELF entry: $entry"
rwr pc $entry
puts "PC after rwr: [rrd pc]"

puts ""
puts "con..."
con

puts "Detaching, leaving app running."
disconnect
exit
