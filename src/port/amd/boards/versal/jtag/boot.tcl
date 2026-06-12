# JTAG load of the wolfIP A72-0 bare-metal app on Versal (VMK180).
#
# Versal differs from ZynqMP: there is no psu_init.tcl. Platform bring-up
# (PMC, PSM, NoC, DDR, MIO, clocks) is performed by the PLM, which runs
# from a boot PDI. The board must be in JTAG boot mode (SW1 mode pins =
# 0000) so the BootROM waits and does NOT auto-boot Linux from SD/QSPI;
# otherwise Linux comes up and owns GEM0 (runtime-suspends its clock),
# which stalls our bare-metal driver.
#
# Flow:
#   1. rst -system            -- clean POR; in JTAG mode the A72 stays
#                                held in reset (no Linux).
#   2. device program <pdi>   -- PLM configures DDR/clocks/MIO and
#                                de-isolates the FPD; this is the Versal
#                                equivalent of the ZynqMP psu_init step.
#   3. rst -proc A72#0         -- a Versal A72 resets to EL3 (RVBAR), the
#      (-skip-activate-           exception level startup.S expects. The
#       subsystem)                -skip-activate-subsystem flag avoids the
#                                heavy default-subsystem reset that drops
#                                the board USB-UART.
#   4. dow app.elf + con      -- DDR is PLM-trained so `dow` is reliable.
#
# Env vars (set by jtag/boot.sh):
#   APP_ELF    path to app.elf (build with LAYOUT=ddr)
#   BOOT_PDI   path to a VMK180 boot PDI (PLM + platform config)

set APP_ELF  $env(APP_ELF)
set BOOT_PDI $env(BOOT_PDI)

puts "Connecting..."
connect

puts "JTAG chain:"
jtag targets

# 1. Clean POR. In JTAG boot mode this leaves the A72 held in reset.
puts "rst -system (clean POR; JTAG mode -> no Linux)..."
targets -set -nocase -filter {name =~ "Versal *"}
rst -system
after 3000

# 2. Program the boot PDI through the PMC. With more than one device on
#    the chain (e.g. a ZCU102 on a second cable) the PMC must be selected
#    explicitly or `device program` reports an ambiguous device.
puts "device program (PLM brings up DDR/clocks/MIO): $BOOT_PDI"
targets -set -nocase -filter {name =~ "PMC"}
device program $BOOT_PDI
after 2500

# 3. Take over A72 #0 at EL3, before u-boot (if present in the PDI)
#    autoboots anything.
puts "Preparing Cortex-A72 #0..."
targets -set -nocase -filter {name =~ "*Cortex-A72*#0"}
rst -proc -skip-activate-subsystem
after 400
catch {stop}
after 200
puts "PC after rst -proc (RVBAR, EL3): [rrd pc]"

# 4. Load and run.
puts "Loading app: $APP_ELF"
dow $APP_ELF
after 200
puts "PC after dow (app entry): [rrd pc]"

puts ""
puts "con..."
con

puts "Detaching, leaving app running."
disconnect
exit
