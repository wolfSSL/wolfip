#!/bin/bash
# run_hwsim_sae_softmac_h2e_test.sh
#
# Thin wrapper: run the SoftMAC SAE hwsim test in H2E mode (sae_pwe=2,
# RFC 9380 SSWU PWE). Kept as a separate script so it can be granted
# NOPASSWD sudo without having to allow `sudo env ...`.
exec env WOLFIP_SAE_H2E=1 "$(dirname "$0")/run_hwsim_sae_softmac_test.sh" "$@"
