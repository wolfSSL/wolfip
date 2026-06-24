#!/bin/bash
# wolfsta hwsim DHCP test over WPA2-PSK (SoftMAC nl80211 path).
exec env AUTH=psk "$(dirname "$0")/run_hwsim_wolfsta_dhcp_test.sh" "$@"
