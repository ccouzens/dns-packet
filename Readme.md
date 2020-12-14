# DNS Packet

A script that makes a DNS request. The code is written at the UDP level.

Usage:

```bash
cargo run -- google.com 1.1.1.1
```

```
request packet: Length: 28 (0x1c) bytes
0000:   00 00 01 00  00 01 00 00  00 00 00 00  06 67 6f 6f   .............goo
0010:   67 6c 65 03  63 6f 6d 00  00 01 00 01                gle.com.....

response packet: Length: 44 (0x2c) bytes
0000:   00 00 81 80  00 01 00 01  00 00 00 00  06 67 6f 6f   .............goo
0010:   67 6c 65 03  63 6f 6d 00  00 01 00 01  c0 0c 00 01   gle.com.........
0020:   00 01 00 00  00 de 00 04  d8 3a c6 ae                .........:..

[Record { question: Question { name: "google.com", type: AddressRecord, class: Internet }, time_to_live: 222, length: 4, data: A(216.58.198.174) }]
```

Very roughly matching:

```bash
dig @1.1.1.1 +noedns google.com
```

## Background

[EmilHernvall's dnsguide](https://github.com/EmilHernvall/dnsguide/blob/master/chapter1.md)
was very helpful.
