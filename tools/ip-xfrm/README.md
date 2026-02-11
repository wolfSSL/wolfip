# IPsec ESP support and testing

This contains `ip xfrm` convenience scripts for wolfIP IPsec testing,
as well as sample wireshark ESP SA config for decoding ESP packets:

- `cbc_auth`: sets up aes-cbc (rfc3602) + hmac auth (rfcs 2403, 2404, 4868)
   on linux host.
- `des3_auth`: same with des3 (rfc2451) + hmac auth (rfcs 2403, 2404, 4868).
- `rfc4106`: same with aes-gcm (rfc4106).
- `rfc4543`: same with aes-gmac (rfc4543).
- `show`: show all ip xfrm state and policies on linux host.
- `delete_all`: deletes all ip xfrm state and policies on linux host.
- `esp_sa.txt`: wireshark `esp_sa` config file.

Copy `esp_sa.txt` to you wireshark config, and you can decrypt and inspect
ESP payloads, verify ESP ICV and TCP/IP checksums, etc:

```
cp tools/ip-xfrm/esp_sa.txt ~/.config/wireshark/esp_sa
wireshark test.pcap
```

## Testing

Build wolfssl with:
```sh
./configure --enable-des3 --enable-aesgcm-stream
  make
  sudo make install
```

Build wolfIP like normal:
```sh
make
```

This will result in two ESP tests:
- `./build/test-esp`: self-contained ESP event loop test (client and
   server spawned within test).
- `./build/esp-server`: ESP echo server, supporting TCP and UDP.

### ESP event-loop test with rfc4106

Test rfc4106 gcm with wolfIP:
```
./tools/ip-xfrm/rfc4106 128
sudo LD_LIBRARY_PATH=/usr/local/lib ./build/test-esp
./tools/ip-xfrm/delete_all
cp tools/ip-xfrm/esp_sa.txt ~/.config/wireshark/esp_sa
wireshark test.pcap
```

### ESP echo-server with UDP and des3-hmac

In first terminal:
```
./tools/ip-xfrm/delete_all
./tools/ip-xfrm/des3_auth sha256 128 udp
```

In second terminal:
```
sudo LD_LIBRARY_PATH=/usr/local/lib ./build/esp-server -m 2 -u
```

In first terminal again:
```
nc 10.10.10.2 8 -p 12345 -u
```

Type messages in first terminal, and you should see them arrive
as ESP packets in second terminal, be decrypted, then echoed
back again as ESP packets.
