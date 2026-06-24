#!/bin/bash
# WPA3-SAE PMKSA fast-reconnect over hwsim: reuse the SAE SoftMAC harness
# but run the PMKSA two-pass test binary (full SAE, then cached reconnect).
R="$(cd "$(dirname "$0")/../.." && pwd)"
exec env TEST_BIN="$R/build/test-supplicant-hwsim-pmksa-softmac" \
    "$(dirname "$0")/run_hwsim_sae_softmac_test.sh" "$@"
