#!/bin/bash
# Negative test: supplicant uses a wrong SAE password; expect clean reject.
exec env WOLFIP_SAE_BADPW=1 "$(dirname "$0")/run_hwsim_sae_softmac_test.sh" "$@"
