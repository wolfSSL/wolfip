# Wired IEEE 802.1X EAP-TLS demo (STM32H563 + wolfSupplicant)

This exercises the in-tree wolfSupplicant (`src/supplicant/`) EAP-TLS path on real hardware over a **wired** Ethernet link. The STM32H563 runs wolfIP + the supplicant and authenticates against a Linux host running `hostapd` as the 802.1X authenticator (with its integrated EAP server). Unlike WPA2-PSK on a FullMAC Wi-Fi chip (where the radio firmware owns the handshake), here the host owns the entire EAPOL/EAP-TLS exchange end to end - so it actually drives the supplicant code, with no RF variance.

There is no WPA 4-way handshake on wired 802.1X: success is reaching EAP-Success, at which point the supplicant has derived the MSK-based PMK and parks at `SUPP_STATE_4WAY_M1_WAIT` (waiting for an M1 that wired never sends). The demo treats that state as "authenticated".

## Transport

EAPOL (ethertype `0x888E`) frames move over a wolfIP **packet socket** (`AF_PACKET`/`SOCK_RAW`), not an IP socket - so no IP address is needed; 802.1X runs at layer 2. The supplicant produces/consumes bare EAPOL payloads; `dot1x_client.c` adds and strips the 802.3 header. The board sends to the authenticator's unicast MAC (`DOT1X_AUTH_MAC` in `dot1x_client.c`), not the PAE group `01:80:C2:00:00:03`: the PAE group is link-local and dropped by 802.1D switches, so unicast is required on a switched segment and works equally well point-to-point. hostapd's `use_pae_group_addr=0` makes it reply to the supplicant's unicast MAC (learned from the EAPOL-Start).

## 1. Generate the test PKI (once)

```sh
cd src/port/stm32h563/dot1x
./gen_certs.sh
```

This creates one EC P-256 CA that signs both a client cert (CN `alice@wolfip.local`, embedded into the firmware as `../dot1x_certs.h`) and a server cert (`host/server.pem` + `host/server.key` for hostapd). These are THROWAWAY TEST credentials. The generated `../dot1x_certs.h` and `host/` are **git-ignored** (they hold private keys), so this step is required before the first build; re-run to rotate (then rebuild the firmware and restart hostapd together so both sides share the CA).

## 2. Build + flash the firmware

```sh
cd src/port/stm32h563
CC=arm-none-eabi-gcc OBJCOPY=arm-none-eabi-objcopy make clean ENABLE_DOT1X=1
CC=arm-none-eabi-gcc OBJCOPY=arm-none-eabi-objcopy make ENABLE_DOT1X=1
# flash app.bin to 0x08000000 (st-flash / STM32_Programmer_CLI / your usual tool)
```

`ENABLE_DOT1X=1` auto-enables TLS (wolfSSL), links the EAP-TLS subset of the supplicant, and turns on wolfIP packet sockets. TZEN=0 only.

## 3. Start hostapd on the Linux host

Edit `interface=` in `hostapd.conf` to the NIC wired to the board, then:

```sh
cd src/port/stm32h563/dot1x
sudo hostapd -dd ./hostapd.conf
```

The host NIC needs no IP for the auth itself. Bring it up: `sudo ip link set <iface> up`.

## 4. Wire it and run

Connect the host NIC directly to the board's Ethernet (a direct point-to-point cable is the simplest setup and how this demo was validated; a switched segment also works because EAPOL is sent unicast). Reset the board and watch its UART (115200 8N1):

```
=== Wired 802.1X EAP-TLS (wolfSupplicant) ===
  dot1x: EAP-TLS start (EAPOL-Start) as alice@wolfip.local
  dot1x: EAP-TLS SUCCESS - authenticated, PMK derived
=== 802.1X: AUTHENTICATED ===
```

On the hostapd side you should see the EAP-TLS exchange complete with `CTRL-EVENT-EAP-SUCCESS` for the board's MAC.

## Success criterion

- Board UART prints `802.1X: AUTHENTICATED`.
- hostapd logs an EAP-TLS success for the supplicant.

If it fails, raise verbosity on both sides: the board's `dot1x_client.c` logs each phase; `hostapd -dd` shows the TLS alert or cert error. Common causes: the client cert CN/identity not matching the `eap_user` file, a CA mismatch (regenerate both sides with `gen_certs.sh`), or the host NIC not up / wrong `interface=`.
