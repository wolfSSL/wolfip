# JTAG load of the wolfIP Cortex-A9 bare-metal app on Zynq-7000 (ZC702).
#
# Zynq-7000 has no PMU/PLM. The prebuilt FSBL brings the PS up (ps7_init:
# DDR, MIO pinmux, clocks, UART) and then parks itself (no bundled
# second stage). We run the FSBL, stop where it parks, then load our app
# over the top and start it in SVC mode. Pattern adapted from the
# wolfBoot Zynq-7000 jtag_load.tcl.
#
# Set the ZC702 boot-mode straps to JTAG (SW16 = all OFF) and power-cycle
# before use. After a run the board may need a power-cycle to recover the
# CPU into a JTAG-loadable state.
#
# Env vars (set by jtag/boot.sh):
#   APP_ELF    path to app.elf
#   FSBL_ELF   path to a prebuilt Zynq-7000 FSBL ELF
#   READELF    arm-none-eabi-readelf (to read the app entry point)

set APP_ELF  $env(APP_ELF)
set FSBL_ELF $env(FSBL_ELF)
set readelf  [expr {[info exists env(READELF)] ? $env(READELF) : "arm-none-eabi-readelf"}]

puts "Connecting..."
connect

# The chain sometimes comes up empty if a previous run left the CPU
# off-chain (WFI + clock gated). Retry the A9 target selection.
set selected 0
for {set i 0} {$i < 5} {incr i} {
    set rc [catch {targets -set -filter {name =~ "ARM Cortex-A9 MPCore #0"}} err]
    if {$rc == 0} { set selected 1; break }
    puts "Cortex-A9 select failed (try $i): $err"
    after 500
}
if {!$selected} {
    puts "ERROR: could not select Cortex-A9 target after 5 retries."
    puts "Power-cycle the ZC702 and try again."
    exit 1
}

# Full PS reset, then wait for the BootROM to enter its JTAG-mode poll
# loop before loading the FSBL.
puts "System reset..."
rst -system
after 1500
targets -set -filter {name =~ "ARM Cortex-A9 MPCore #0"}

# Run the FSBL to completion: ps7_init (DDR/MIO/clocks/UART), then it
# parks. 3 s is plenty.
puts "Loading FSBL: $FSBL_ELF"
dow $FSBL_ELF
con
after 3000

# Stop where the FSBL parked. Do NOT rst -processor here -- that drops
# back into the BootROM and loses the FSBL's PS configuration.
stop

# The OCM-layout app links at 0xFFFC0000, but the FSBL leaves the OCM
# banks at the reset mapping (banks 0-2 at 0x00000000, bank 3 at
# 0xFFFF0000), so 0xFFFC0000-0xFFFEFFFF is unmapped and `dow` fails with
# "OCM is not enabled at 0xFFFC0000". Map all four 64 KB OCM banks to the
# high address so the whole 256 KB sits contiguously at 0xFFFC0000.
# SLCR must be unlocked first (0xDF0D), then re-locked (0x767B).
puts "Mapping OCM high (SLCR.OCM_CFG = 0x0F)..."
mwr -force 0xF8000008 0x0000DF0D   ;# SLCR_UNLOCK
mwr -force 0xF8000910 0x0000000F   ;# OCM_CFG: RAM_HI for all 4 banks
mwr -force 0xF8000004 0x0000767B   ;# SLCR_LOCK

# Load the app. xsdb's `dow` does not reliably set the PC on a second
# target dow, so set PC (app entry) and CPSR (SVC, IRQ/FIQ masked)
# explicitly. ARMv7-A reset/SVC convention, unlike the AArch64 ports.
puts "Loading app: $APP_ELF"
dow $APP_ELF
set entry [exec $readelf -h $APP_ELF | grep "Entry point" | awk "{print \$NF}"]
puts "App ELF entry: $entry"
rwr pc $entry
rwr cpsr 0xD3                  ;# SVC mode, IRQ+FIQ masked
puts "PC=[rrd pc] CPSR=[rrd cpsr]"

puts ""
puts "con... watch UART1 (115200 8N1) for the wolfIP banner."
con

puts "Detaching, leaving app running."
disconnect
exit
