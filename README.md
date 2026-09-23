# net_intercept

Experimental Linux kernel module for intercepting and analyzing IPv4 packets.

## Features

This module currently extracts:

- source and destination IP addresses
- protocol (ICMP, TCP, UDP)
- source and destination ports for TCP and UDP protocols

Packets information is displayed in the kernel logs:
```text
[NET_INTERCEPT] Proto: TCP (6) | Packet: 10.0.2.2:44042 -> 10.0.2.15:22
```