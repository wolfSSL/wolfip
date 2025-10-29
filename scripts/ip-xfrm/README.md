# IPsec ESP and ip xfrm support

Some convience scripts and config for testing IPsec with wolfIP:

- delete_all (delete all ip xfrm state and policies)
- hmac_auth (set auth only state and policies)
- show (show ip xfrm state and policies)
- esp_sa.txt (ESP SA config to use in Wireshark)

# Build

## wolfssl

Build wolfssl with:

```sh
./configure --enable-cryptonly --enable-sha --enable-sha256 --enable-md5 --enable-des3
  make
  sudo make install
```

# wolfip

Build wolfip with:
```sh
-DWOLFIP_ESP -DWOLFSSL_WOLFIP
```

# testing

Use `scripts/ip-xfrm` convenience scripts:

```
./scripts/ip-xfrm/delete_all && ./scripts/ip-xfrm/cbc_auth sha256 128
```

Use this to show what is set:

```
./scripts/ip-xfrm/show
ip xfrm policy show
src 0.0.0.0/0 dst 10.10.10.2/32 proto tcp
	dir out priority 0 ptype main
	tmpl src 0.0.0.0 dst 0.0.0.0
		proto esp spi 0x764f47c9 reqid 0 mode transport

ip xfrm state show
src 10.10.10.2 dst 10.10.10.1
	proto esp spi 0x49ebfdd4 reqid 0 mode transport
	replay-window 0
	auth-trunc hmac(sha256) 0x02020202020202020202020202020202 128
	enc cbc(aes) 0x04040404040404040404040404040404
      ...etc...
```

Use `./scripts/ip-xfrm/watch_stat` to troubleshoot XfrmIn/Out errors.

# wireshark

Use this for your wireshark `esp_sa` file, and wireshark will be able to
decrypt and verify all ESP traffic:
- `scripts/ip-xfrm/esp_sa.txt`
