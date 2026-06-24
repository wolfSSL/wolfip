#!/bin/bash
# SoftMAC SAE hwsim test, ECC group 20 (P-384), hunt-and-peck.
exec env WOLFIP_SAE_GROUP=20 "$(dirname "$0")/run_hwsim_sae_softmac_test.sh" "$@"
