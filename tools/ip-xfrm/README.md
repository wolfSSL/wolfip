# IPsec ESP and ip xfrm support

Convenience scripts for testing IPsec with wolfIP:

- `rfc4106` sets up rfc4106 aes-gcm xp frm state and policies.
- `delete_all` (deletes all ip xfrm state and policies)
- `hmac_auth` (set auth only state and policies)
- `show` (show ip xfrm state and policies)
- `esp_sa.txt` (ESP SA config to use in Wireshark)

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

Test rfc4106 gcm with wolfIP:
```
./tools/ip-xfrm/rfc4106 128
sudo LD_LIBRARY_PATH=/usr/local/lib ./build/test-esp
./tools/ip-xfrm/delete_all
cp tools/ip-xfrm/esp_sa.txt ~/.config/wireshark/esp_sa
wireshark test.pcap
```
