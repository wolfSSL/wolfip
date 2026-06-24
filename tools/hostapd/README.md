# Supplicant interop test harness

Two real-authenticator validation paths for the wolfIP supplicant, both built on a Linux host with `hostapd` and run via the top-level Makefile.

## Targets

```
make supplicant-hostapd-test       # EAP-TLS over veth + hostapd wired
make supplicant-hostapd-peap-test  # EAP-PEAP/MSCHAPv2 over veth (needs PEAP build)
make supplicant-hwsim-psk-test     # WPA2-PSK over mac80211_hwsim + hostapd nl80211
make supplicant-hwsim-sae-test     # WPA3-SAE H&P (sae_pwe=0)  - FullMAC path, see SAE note
make supplicant-hwsim-sae-h2e-test # WPA3-SAE H2E (sae_pwe=2)  - FullMAC path, see SAE note
make supplicant-hwsim-sae-softmac-test     # WPA3-SAE H&P over the SoftMAC path (works on hwsim)
make supplicant-hwsim-sae-softmac-h2e-test # WPA3-SAE H2E over the SoftMAC path (works on hwsim)
make wolfsta                       # build the wolfIP + supplicant host STA app
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
| `run_hwsim_sae_test.sh` | SAE runner, FullMAC external-auth path (see hwsim limitation below) |
| `nl80211_sta.c` | reusable SoftMAC STA radio glue: CONNECT (PSK/802.1X), AUTHENTICATE+SAE_DATA / ASSOCIATE (SAE), NEW_KEY install, AF_PACKET EAPOL; wired to the supplicant ops |
| `run_hwsim_sae_softmac_test.sh` | SAE runner over the SoftMAC path - validates green on hwsim |
| `../wolfsta/wolfsta.c` | host STA app: wolfIP + supplicant on a real netdev (PSK/SAE) -> DHCP |
| `run_realcard_sae_test.sh` | real SoftMAC card: SAE association runner (auto-detects netdev, scans for BSSID/freq) |
| `run_realcard_wolfsta_test.sh` | real SoftMAC card: full wolfsta join -> DHCP -> UDP echo runner |
| `realcard_common.sh` | shared helpers (iface detect, bring-up, SSID scan) for the run_realcard scripts |

## Why two paths

Hostapd's wired driver always routes new STAs through 802.1X EAP, so WPA2-PSK over a veth never reaches the 4-way handshake. The mac80211_hwsim path simulates an actual 802.11 radio, which lets hostapd's `wpa_auth_sm` see a real association with an RSN IE advertising AKM=PSK and run the 4-way without going through EAP first.

## WPA3-SAE: hwsim limitation, real validation on FullMAC

The `supplicant-hwsim-sae-test` target builds a binary that drives WPA3-SAE through `NL80211_CMD_CONNECT` with `EXTERNAL_AUTH_SUPPORT`. That is the cfg80211 surface FullMAC drivers expose (`brcmfmac` on CYW43439, the actual shipping target): the kernel fires `NL80211_CMD_EXTERNAL_AUTH` to userspace, the supplicant runs SAE Commit/Confirm, and frames flow via `NL80211_CMD_FRAME`.

`mac80211_hwsim` is SoftMAC. `iw phy ... info` reports only "Device supports SAE with AUTHENTICATE command" - it has no `EXTERNAL_AUTH_FOR_CONNECT` extended feature and silently ignores `EXTERNAL_AUTH_SUPPORT`, falling back to internal open auth (which hostapd rejects). The test prints a clear "kernel never fired NL80211_CMD_EXTERNAL_AUTH" note and exits non-zero on hwsim. The same binary is expected to pass on CYW43439 / Pi Pico W hardware (Phase D).

### SoftMAC path: validates SAE over a real radio on hwsim (no hardware)

`mac80211_hwsim` *does* support SAE through the SoftMAC surface: `NL80211_CMD_AUTHENTICATE` carrying the SAE payload in `NL80211_ATTR_SAE_DATA` (Commit then Confirm), followed by `NL80211_CMD_ASSOCIATE`. `tools/hostapd/nl80211_sta.c` implements exactly this, and `supplicant-hwsim-sae-softmac-test` / `-h2e-test` drive it. Because hwsim honors this path, these targets are expected to reach `AUTHENTICATED` with no hardware, and the same `nl80211_sta.c` code drives a real SoftMAC USB radio (e.g. a TP-Link ath9k_htc / rtl8xxxu / mt76 card).

The two SAE paths are complementary: the FullMAC external-auth binary (`test_supplicant_hostapd_sae.c`) targets `brcmfmac` / CYW43439; the SoftMAC binary (`test_supplicant_hwsim_sae_softmac.c` + `nl80211_sta.c`) targets hwsim and SoftMAC cards. After SAE both run the same 4-way handshake; the negotiated PTK/GTK are installed into the kernel via `NL80211_CMD_NEW_KEY`.

The WPA3-SAE 4-way differs from WPA2-PSK: it uses EAPOL-Key Descriptor Version 0 (AES-128-CMAC MIC, not HMAC-SHA1) and derives the PTK with the HMAC-SHA256 KDF. wolfSupplicant handles both - it selects the MIC/KDF from the AKM. The AES-128-CMAC EAPOL-Key MIC is implemented in-tree (RFC 4493 over AES-CBC), so SAE does **not** require a wolfSSL built with `--enable-cmac`; it still needs `WOLFSSL_PUBLIC_MP`.

For software-side validation of SAE there are also two in-process test binaries that DO run cleanly:

```
make build/test-sae-crypto         && build/test-sae-crypto       # crypto unit
make build/test-supplicant-sae     && build/test-supplicant-sae   # state machine
```

Together they exercise: RFC 9380 J.1.1 SSWU known-answer (P-256), hunt-and-peck PWE, H2E PT, full Commit/Confirm/PMK derivation, and the in-process supplicant<->fake-AP handshake for both H&P and H2E across groups 19/20/21.

## Real-radio (SoftMAC) interop status

Validated to `AUTHENTICATED` against hostapd over `mac80211_hwsim`, and the same `nl80211_sta.c` code path is **hardware-validated on a real SoftMAC card** (TP-Link TL-WN722N v1 / Atheros AR9271 / `ath9k_htc`) against a real AP - see "Real hardware validation" below:

| Path | Make target | Status |
|------|-------------|--------|
| WPA3-SAE P-256 (group 19), H&P + H2E | `supplicant-hwsim-sae-softmac-test` / `-h2e-test` | OK |
| WPA3-SAE P-384 (group 20), H&P + H2E | `supplicant-hwsim-sae-softmac-g20-test` / `-g20-h2e-test` | OK |
| WPA3-SAE P-521 (group 21), H2E | `supplicant-hwsim-sae-softmac-g21-h2e-test` | OK |
| WPA3-SAE P-521 (group 21), hunt-and-peck | `supplicant-hwsim-sae-softmac-g21-test` | OK |
| WPA2-Enterprise EAP-TLS over the radio | `supplicant-hwsim-eap-softmac-test` | OK |
| WPA3-SAE PMKSA fast reconnect (no SAE) | `supplicant-hwsim-pmksa-test` | OK |
| WPA3-SAE wrong-password rejected (negative) | `supplicant-hwsim-sae-softmac-badpw-test` | OK |
| wolfsta join + DHCP + ping + UDP echo (SAE) | `supplicant-hwsim-wolfsta-dhcp-test` | OK |
| wolfsta join + DHCP (WPA2-PSK) | `supplicant-hwsim-wolfsta-dhcp-psk-test` | OK |

H2E (the WPA3-mandated PWE) and hunt-and-peck (legacy) both interoperate for all three groups (P-256/P-384/P-521). P-521 is the awkward one: its 521-bit prime is not byte-aligned, so the hunt-and-peck pwd-value (the IEEE 802.11 KDF emits its bits left-aligned) must be right-shifted by `8 - 521%8 = 7` bits to form a right-aligned integer before the "< p" test, exactly as hostapd's `buf_shift_right` does - masking the high byte instead (which agrees with an in-process peer but not hostapd) was the interop bug. WPA2-Enterprise EAP-TLS completes the full enterprise join over the radio (802.1X assoc -> EAP-TLS -> MSK-keyed 4-way). PMKSA fast reconnect does a full SAE once, caches the PMK/PMKID, then rejoins via open auth + ASSOCIATE carrying the PMKID in the RSN IE - hostapd matches the cached PMKSA ("SAE: PMK from PMKSA cache") and runs the 4-way directly with no dragonfly. The negative test confirms a wrong password is cleanly rejected (no crash / no false AUTHENTICATED). IEEE 802.11w MFP robustness testing is future work.

## Real hardware validation (SoftMAC card + any WPA3-SAE AP)

The hwsim targets above are validated on real radios with **no source changes** - the same `build/*` binaries are pointed at a real interface. Any true SoftMAC USB card and any WPA3-SAE-capable AP will do; the reference bench used here is:

- **STA (device under test):** TP-Link TL-WN722N **v1** = Atheros **AR9271** (`ath9k_htc`, USB `0cf3:9271`). This is a true SoftMAC part: `iw phy <phy> info` reports "Device supports SAE with AUTHENTICATE command", CCMP/GCMP/CMAC/GMAC, and the `CONTROL_PORT_OVER_NL80211` extended feature. The Realtek-based v2/v3 (RTL8188EUS) are a different driver and not what `nl80211_sta.c` targets. Other `ath9k_htc` / `rtl8xxxu` / `mt76` SoftMAC sticks should behave the same way (the runner scripts auto-detect any of them).
- **AP:** any WPA3-SAE access point - a consumer WPA3 router, a second SoftMAC USB card running hostapd, or (as here) a Raspberry Pi 5 (`brcmfmac`, `wlan0`) on a wired uplink so its Wi-Fi is free. Despite being FullMAC, brcmfmac + hostapd 2.10 brings up a working WPA3-SAE AP. The generic hostapd config below works on any host with a Wi-Fi NIC capable of AP mode.

Confirmed end to end over the air: WPA3-SAE Commit/Confirm -> ASSOCIATE -> 4-way (M1..M4) -> key install -> `AUTHENTICATED`, then wolfIP DHCP lease, UDP echo (bidirectional CCMP-encrypted data), and an ICMP reply from wolfIP's responder.

**EAPOL transport note:** on a real SoftMAC card the kernel drops EAPOL injected on the AF_PACKET data path while the controlled port is unauthorized, so `nl80211_sta.c` carries the 4-way over the nl80211 control port (`NL80211_ATTR_CONTROL_PORT_OVER_NL80211` + `NL80211_CMD_CONTROL_PORT_FRAME`, owned by a dedicated socket). hwsim is lenient about this; real hardware is not. This is on by default and also exercised by every hwsim target above.

### Generic AP setup (reference host: Raspberry Pi 5)

The steps below stand up a WPA3-SAE AP on any Linux host with an AP-capable Wi-Fi NIC; only the interface name (`wlan0` here) and channel are host-specific. On a Pi 5, `hostapd`/`iw` install into `/usr/sbin`, which is not in a non-login SSH `PATH` - use full paths. Wi-Fi may be rfkill-soft-blocked after a fresh install.

```bash
sudo apt-get install -y hostapd iw rfkill dnsmasq socat
sudo rfkill unblock wifi

cat | sudo tee /tmp/wolfip_rt.conf >/dev/null <<'CONF'
interface=wlan0
driver=nl80211
ssid=wolfIP-RT
country_code=US
hw_mode=g
channel=11
wpa=2
wpa_key_mgmt=SAE
rsn_pairwise=CCMP
ieee80211w=2
sae_pwe=2
sae_password=ThisIsAPassword!
CONF
sudo /usr/sbin/hostapd -dd -t /tmp/wolfip_rt.conf >/tmp/wolfip_rt.log 2>&1 &

# AP-side L3 + DHCP (DNS disabled with --port=0 to avoid the system dnsmasq
# already on :53) + a UDP echo server for the wolfsta data-path probe.
sudo ip addr add 192.168.50.1/24 dev wlan0
sudo dnsmasq --port=0 --interface=wlan0 --bind-interfaces \
     --dhcp-range=192.168.50.50,192.168.50.150,255.255.255.0,5m \
     --dhcp-authoritative --no-resolv --no-hosts &
sudo socat UDP4-RECVFROM:7777,fork,reuseaddr EXEC:/bin/cat &
```

### STA side (the host with the AR9271)

`<IF>` is the AR9271 netdev (e.g. `wlxXXXXXXXXXXXX`), `<BSSID>` the Pi 5 `wlan0` MAC, freq `2462` = channel 11. The supplicant owns L3, so flush the kernel IP on the interface.

```bash
sudo rfkill unblock wifi
sudo iw dev <IF> set type managed
sudo ip link set <IF> up
sudo ip addr flush dev <IF>

# WPA3-SAE association only (Commit/Confirm + 4-way -> AUTHENTICATED):
sudo env WOLFIP_SAE_H2E=1 WOLFIP_SAE_GROUP=19 \
    build/test-supplicant-hwsim-sae-softmac <IF> wolfIP-RT ThisIsAPassword! <BSSID> 2462

# Full end-to-end (join -> DHCP -> UDP echo to the AP):
sudo env WOLFIP_SAE_H2E=1 WOLFSTA_ECHO=192.168.50.1:7777 WOLFSTA_HOLD_SECS=15 \
    build/wolfsta <IF> wolfIP-RT sae ThisIsAPassword! <BSSID> 2462 19
```

`sae_pwe=2` on the AP means H2E, so the STA must run with `WOLFIP_SAE_H2E=1`. To check wolfIP's ICMP responder, `ping` the leased IP from the AP (`ping -I wlan0 <leased-ip>`).

### Convenience runners

The two STA-side steps above are wrapped by `run_realcard_sae_test.sh` (SAE association only) and `run_realcard_wolfsta_test.sh` (full join -> DHCP -> UDP echo, exits non-zero on failure), sharing `realcard_common.sh`. Both **auto-detect** the SoftMAC netdev (first `ath9k_htc` / `rtl8xxxu` / `mt76` radio) and **auto-discover** the AP's BSSID and channel by scanning for the SSID, so the only thing you normally set is the SSID/passphrase. Run `--help` for the full option list. They need root:

```bash
# Against the default SSID (wolfIP-RT / ThisIsAPassword!), everything discovered:
sudo ./run_realcard_sae_test.sh
sudo ./run_realcard_wolfsta_test.sh

# Point at any other AP (BSSID/FREQ still auto-scanned unless you set them):
sudo SSID=my-ap PSK='my-pass' ./run_realcard_sae_test.sh
sudo SSID=my-ap PSK='my-pass' MODE=psk ./run_realcard_wolfsta_test.sh

# Pass an explicit interface as the first argument if auto-detect picks wrong:
sudo SSID=my-ap PSK='my-pass' ./run_realcard_sae_test.sh wlan1
```

## Build flags

| Flag | Default | Effect |
|------|---------|--------|
| `WOLFIP_ENABLE_EAP_TLS` | 1 | WPA2-Enterprise EAP-TLS via wolfSSL custom IO |
| `WOLFIP_ENABLE_PEAP_MSCHAPV2` | 0 | EAP-PEAPv0 with MSCHAPv2 inner; pulls in MD4 + DES (see PEAP section) |
| `WOLFIP_ENABLE_SAE` | 1 | WPA3-Personal SAE dragonfly handshake; needs `WOLFSSL_PUBLIC_MP` |
| `WOLFIP_ENABLE_SAE_H2E` | 1 | SAE Hash-to-Element PWE (RFC 9380 SSWU); off = hunt-and-peck only |
| `WOLFIP_ENABLE_SAE_HNP` | 1 | SAE hunt-and-peck PWE; set to 0 in H2E-only builds to drop ~600 B of text |

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
