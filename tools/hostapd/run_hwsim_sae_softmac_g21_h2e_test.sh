#!/bin/bash
# SoftMAC SAE hwsim test, ECC group 21 (P-521), H2E.
exec env WOLFIP_SAE_GROUP=21 WOLFIP_SAE_H2E=1 "$(dirname "$0")/run_hwsim_sae_softmac_test.sh" "$@"
