# Supplicant interop test harness

Two real-authenticator validation paths for the wolfIP supplicant, both built on a Linux host with `hostapd` and run via the top-level Makefile.

## Targets

```
make supplicant-hostapd-test       # EAP-TLS over veth + hostapd wired
make supplicant-hostapd-peap-test  # EAP-PEAP/MSCHAPv2 over veth (needs PEAP build)
make supplicant-hwsim-psk-test     # WPA2-PSK over mac80211_hwsim + hostapd nl80211
make supplicant-hwsim-sae-test     # WPA3-SAE: hostapd over hwsim (see SAE note)
```

Both require `sudo` for veth/TAP creation, raw `AF_PACKET` sockets, and `mac80211_hwsim` module load. Pass them through any of:

- `sudo make ...` interactively
- Add a `/etc/sudoers.d/wolfip-supplicant` entry: `<user> ALL=(root) NOPASSWD: /path/to/wolfip/tools/hostapd/run_*_test.sh`

## Setup on a fresh Debian / Ubuntu / Raspberry Pi OS box

```bash
sudo apt-get install -y hostapd libnl-3-dev libnl-genl-3-dev \
                       build-essential autoconf libtool pkg-config iw
```

Then a wolfSSL build with the features the supplicant uses (TLS 1.3, AES Key Wrap, EAP keying-material exporter):

```bash
git clone --depth 1 -b v5.9.1-stable https://github.com/wolfSSL/wolfssl.git
cd wolfssl
./autogen.sh
CFLAGS="-DWOLFSSL_PUBLIC_MP" ./configure \
    --enable-tls13 --enable-aeskeywrap \
    --enable-keying-material --enable-supportedcurves
make -j"$(nproc)"
sudo make install
sudo ldconfig
```

The `wpa_crypto.c` module needs the `wc_ForceZero` public symbol, present from wolfSSL 5.7+. The `sae_crypto.c` (WPA3-SAE) module needs the `mp_*` / `sp_*` math API exported via `WOLFSSL_PUBLIC_MP` (set via `CFLAGS` above).

## Iterating remotely (Pi5 / any SSH-reachable Linux box)

If the same setup is on a remote machine, `make ... HOST=<user>@<host>` isn't built in - just SSH and invoke there:

```bash
rsync -aq --delete --exclude=/build --exclude=/.vscode ./ user@host:~/wolfip/
ssh user@host 'cd ~/wolfip && make supplicant-tests'
ssh user@host 'cd ~/wolfip && sudo make supplicant-hwsim-psk-test'
```

The hwsim path needs `mac80211_hwsim.ko` present in the kernel image (standard on Debian and Raspberry Pi OS kernels).

## Files

| File | Purpose |
|------|---------|
| `hostapd.conf.template` | wired hostapd, IEEE 802.1X + EAP-TLS server |
| `eap_users` | EAP user file allowing `alice@wolfip.local` -> TLS |
| `run_hostapd_test.sh` | veth + hostapd + EAP-TLS test runner |
| `hostapd_psk.conf.template` | wired hostapd + WPA2-PSK (does NOT work past EAP - kept as documented limitation) |
| `hostapd_psk_hwsim.conf.template` | wireless hostapd over hwsim radio, WPA2-PSK |
| `nl80211_connect.c` | minimal libnl-genl-3 client: open auth + WPA2 assoc with `CONTROL_PORT` so user-space owns EAPOL |
| `run_hwsim_psk_test.sh` | mac80211_hwsim + hostapd + nl80211 + supplicant runner |
| `hostapd_sae_hwsim.conf.template` | WPA3-Personal (SAE) AP for hwsim |
| `run_hwsim_sae_test.sh` | SAE runner (see hwsim limitation above) |

## Why two paths

Hostapd's wired driver always routes new STAs through 802.1X EAP, so WPA2-PSK over a veth never reaches the 4-way handshake. The mac80211_hwsim path simulates an actual 802.11 radio, which lets hostapd's `wpa_auth_sm` see a real association with an RSN IE advertising AKM=PSK and run the 4-way without going through EAP first.

## WPA3-SAE: hwsim limitation, real validation on FullMAC

The `supplicant-hwsim-sae-test` target builds a binary that drives WPA3-SAE through `NL80211_CMD_CONNECT` with `EXTERNAL_AUTH_SUPPORT`. That is the cfg80211 surface FullMAC drivers expose (`brcmfmac` on CYW43439, the actual shipping target): the kernel fires `NL80211_CMD_EXTERNAL_AUTH` to userspace, the supplicant runs SAE Commit/Confirm, and frames flow via `NL80211_CMD_FRAME`.

`mac80211_hwsim` is SoftMAC. `iw phy ... info` reports only "Device supports SAE with AUTHENTICATE command" - it has no `EXTERNAL_AUTH_FOR_CONNECT` extended feature and silently ignores `EXTERNAL_AUTH_SUPPORT`, falling back to internal open auth (which hostapd rejects). The test prints a clear "kernel never fired NL80211_CMD_EXTERNAL_AUTH" note and exits non-zero on hwsim. The same binary is expected to pass on CYW43439 / Pi Pico W hardware (Phase D).

For software-side validation of SAE there are two test binaries that DO run cleanly:

```
make build/test-sae-crypto         && build/test-sae-crypto       # crypto unit
make build/test-supplicant-sae     && build/test-supplicant-sae   # state machine
```

Together they exercise: RFC 9380 J.1.1 SSWU known-answer (P-256), hunt-and-peck PWE, H2E PT, full Commit/Confirm/PMK derivation, and the in-process supplicant<->fake-AP handshake for both H&P and H2E across groups 19/20/21.

## Build flags

| Flag | Default | Effect |
|------|---------|--------|
| `WOLFIP_ENABLE_EAP_TLS` | 1 | WPA2-Enterprise EAP-TLS via wolfSSL custom IO |
| `WOLFIP_ENABLE_PEAP_MSCHAPV2` | 0 | EAP-PEAPv0 with MSCHAPv2 inner; pulls in MD4 + DES (see PEAP section) |
| `WOLFIP_ENABLE_SAE` | 1 | WPA3-Personal SAE dragonfly handshake; needs `WOLFSSL_PUBLIC_MP` |
| `WOLFIP_ENABLE_SAE_H2E` | 1 | SAE Hash-to-Element PWE (RFC 9380 SSWU); off = hunt-and-peck only |

## Optional: EAP-PEAP / MSCHAPv2

EAP-PEAP with the MSCHAPv2 inner method is the most-deployed WPA2-Enterprise method (Windows AD, eduroam, many corporate networks). It is **off by default** in the wolfIP supplicant build because it pulls in two pieces of deprecated cryptography: MD4 (for the NT password hash) and single DES (for the challenge-response splay).

Enable with:

```bash
make ... WOLFIP_ENABLE_PEAP_MSCHAPV2=1 WOLFSSL_PREFIX=$HOME/wolfssl-md4
```

This requires a wolfSSL build with both `--enable-md4` and `--enable-des3` configured. To produce a side-by-side wolfSSL with those enabled without touching the system install:

```bash
git clone --depth 1 -b v5.9.1-stable https://github.com/wolfSSL/wolfssl.git
cd wolfssl
./autogen.sh
./configure --prefix=$HOME/wolfssl-md4 \
            --enable-tls13 --enable-aeskeywrap \
            --enable-keying-material --enable-supportedcurves \
            --enable-md4 --enable-des3
make -j"$(nproc)" install      # no sudo - installs into ~/wolfssl-md4
```

The Makefile detects `WOLFSSL_PREFIX` and links + rpath-embeds against that tree.

Verification (in-tree crypto vectors only, no hostapd needed):

```bash
WOLFIP_ENABLE_PEAP_MSCHAPV2=1 WOLFSSL_PREFIX=$HOME/wolfssl-md4 \
    make build/test-mschapv2 && build/test-mschapv2
```

The default build path remains MSCHAPv2-free: no MD4, no DES, no `WOLFSSL_PREFIX` needed, and the resulting library is identical to what shipped before this feature landed.
