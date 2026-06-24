# wolfsta - host Wi-Fi STA (wolfIP + wolfSupplicant)

`wolfsta` is a Linux host application that joins a Wi-Fi network with the in-tree wolfSupplicant and then runs the wolfIP stack over the radio's netdev. It is the STA-side counterpart of the `tools/hostapd/` interop harness and the reference integration of `tools/hostapd/nl80211_sta.c` (the reusable SoftMAC nl80211 radio glue).

It targets a SoftMAC radio: `mac80211_hwsim` for hardware-free CI, or a real SoftMAC USB card (e.g. a TP-Link `ath9k_htc` / `rtl8xxxu` / `mt76` adapter). FullMAC radios (e.g. CYW43439) use the external-auth path instead - see `tools/hostapd/README.md`.

## What it does

```
join (supplicant) -> AUTHENTICATED -> DHCP -> [optional ping / UDP echo]
```

1. Drives the radio via nl80211 (`nl80211_sta.c`): WPA2-PSK / WPA2-Enterprise over `NL80211_CMD_CONNECT`, or WPA3-SAE over `NL80211_CMD_AUTHENTICATE` (SAE Commit/Confirm in `NL80211_ATTR_SAE_DATA`) + `NL80211_CMD_ASSOCIATE`.
2. Runs the wolfSupplicant 4-way handshake over the EAPOL control port (AF_PACKET) and installs the negotiated PTK/GTK into the kernel via `NL80211_CMD_NEW_KEY`.
3. Brings up the wolfIP stack on the radio netdev through an AF_PACKET link device and obtains a DHCP lease. Because the kernel decrypts/encrypts at the MAC layer once keys are installed, wolfIP owns L3 over plaintext Ethernet.

## Build

```
make wolfsta          # needs WOLFIP_ENABLE_SAE=1 (default) and libnl-genl-3
```

SAE needs a wolfSSL built with `WOLFSSL_PUBLIC_MP`. No `--enable-cmac` is required: the EAPOL-Key AES-128-CMAC MIC used by SAE is implemented in-tree (`wpa_eapol_mic_aes_cmac`).

## Run

The kernel must not also run IP on the interface, or the two stacks fight over ARP/ICMP:

```
sudo ip addr flush dev <ifname>
sudo ip link set <ifname> up
sudo ./build/wolfsta <ifname> <ssid> psk|sae <passphrase> <bssid> [freq_mhz] [sae_group]
```

Example (WPA3-SAE, P-256, channel 1):

```
sudo ./build/wolfsta wlan1 wolfIP-SAE 'ThisIsAPassword!' 02:00:00:00:00:00 2412 19
```

On success it prints the DHCP lease and holds the link up so reachability can be checked externally (e.g. `ping <leased-ip>` from another host).

## hwsim validation (no hardware)

`make supplicant-hwsim-sae-softmac-test` and `-h2e-test` stand up hostapd on a `mac80211_hwsim` radio and drive the SoftMAC SAE path to `AUTHENTICATED` end to end. See `tools/hostapd/README.md`.

## Real hardware

The same `build/wolfsta` binary is validated unchanged on a real SoftMAC card (TL-WN722N v1 / AR9271) against a Pi 5 hostapd AP: WPA3-SAE join -> DHCP lease -> UDP echo + ICMP reply over the air. See the "Real hardware validation" section in `tools/hostapd/README.md` for the exact AP/STA recipe.
