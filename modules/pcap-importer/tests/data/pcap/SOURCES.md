# Genuine test captures — sources and integrity catalogue

All files in this directory are **real, publicly published packet captures**
downloaded unmodified from the web on 2026-10-30. None was generated,
simulated or edited by this project. Malformed-input tests create *mutated
copies* in a temporary directory at test time (allowed for rejection testing
only); the originals here are never modified.

The SHA-256 values are checked by `tests/conftest.py` before every test run.

| File | Source URL | SHA-256 | Bytes | Content (as observed) |
|---|---|---|---:|---|
| dns.cap | https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/dns.cap | 041eeb6f98bb398f1ee8b09651b5b5a84f6a62639f95bf226f9e7b77355d9f28 | 4338 | pcap (µs, LE), Ethernet, 38 IPv4/UDP DNS packets |
| v6.pcap | https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/v6.pcap | 8e18b4c2aa872285881f3aff39481eabc83024369a7b83d95573d846a4a091f2 | 28251 | pcap, 161 IPv6 packets (TCP, UDP, ICMPv6) |
| tfp_capture.pcapng | https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/tfp_capture.pcapng | 0e90321c59b535f2564ed7c36ded6303aedc32325f3f9cdf86e0113b9fd34ae8 | 179072 | pcapng, **2 interfaces** (Ethernet + USB link type 220), IPv4/IPv6 TCP/UDP/ICMPv6/IGMP |
| arp-storm.pcap | https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/arp-storm.pcap | dc101ea9bfda59f56b54bfb949195c3f169032c045b47f98e6952a86933c1b8d | 47296 | pcap, 622 ARP frames (non-IP) |
| ipv4frags.pcap | https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/ipv4frags.pcap | d0b1965aa0c7f9792ee1922f18b1c4e67a45f014fbd324c18dda0dd280605ec4 | 2990 | pcap, fragmented IPv4 ICMP |
| sr-header.pcap | https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/sr-header.pcap | d9471b7f1ee484e572e94d9b961103559faef3f6c355b23d7a42f2f5181fa4d8 | 1784 | pcap, IPv6 TCP + IPv6 routing header carrying IPv6-in-IPv6 (protocol 41) |
| telnet-raw.pcap | https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/telnet-raw.pcap | 7a2fdd843b401fb945b0604b9d760424541b045dac6424361f14d276db2b05a3 | 24345 | pcap, one telnet TCP connection, 272 packets |
| tcp-ecn-sample.pcap | https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/tcp-ecn-sample.pcap | e6edf98f9e2e8a9711fb41a4e16840ef3942b40c7d2694ca373b7f285c783648 | 118965 | pcap, TCP with ECN (ECE/CWR flags), 479 packets |
| 200722_tcp_anon.pcapng | https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/200722_tcp_anon.pcapng | 5295b16ea117fa8bb1a65418fca81e709bea58d3a830bc3bb5c4a2ed0466ea9c | 12800 | pcapng, 35 IPv4 TCP packets |
| icmp_echo.pcapng | https://raw.githubusercontent.com/chrissanders/packets/master/icmp_echo.pcapng | 132accec4fc83a373ab15e7bb525dd8fb1f7935a105710d43a0b53a9a018b385 | 912 | pcapng, 4 ICMP echo requests + 4 replies |
| icmp_traceroute.pcapng | https://raw.githubusercontent.com/chrissanders/packets/master/icmp_traceroute.pcapng | 25049f2ad3ee32894bbdc91f234d4997b1462b19aee7e5f2364d497e75e049b5 | 7080 | pcapng, ICMP traceroute (echo + time-exceeded) |
| tcp_handshake.pcapng | https://raw.githubusercontent.com/chrissanders/packets/master/tcp_handshake.pcapng | 681bcc3526ad9476272b21f38caaebfcaed3354b7886cad86e1ecf23242567ab | 336 | pcapng, TCP three-way handshake (3 packets) |
| tcp_teardown.pcapng | https://raw.githubusercontent.com/chrissanders/packets/master/tcp_teardown.pcapng | f1bd881a23424e58a9f8e2872d5e4854aed140b4b76b64402c1a3606b458677b | 408 | pcapng, TCP FIN teardown (4 packets) |
| udp_dnsrequest.pcapng | https://raw.githubusercontent.com/chrissanders/packets/master/udp_dnsrequest.pcapng | 76f497ac221e7682f9c15cd66ec7dca8a475e8df498136ac2bff3dfcd9f5b828 | 156 | pcapng, a single UDP DNS request |
| http_ip4and6.pcapng | https://raw.githubusercontent.com/chrissanders/packets/master/http_ip4and6.pcapng | e5c68d29c19d7cd0761b635af4ebbccd2f51c47be6902e2859ce9ab7678b7502 | 3424 | pcapng, HTTP over IPv4 and IPv6 |
| synscan.pcapng | https://raw.githubusercontent.com/chrissanders/packets/master/synscan.pcapng | 3ef7a9011bcc2901080d3800d52fd5bb5cbcc1aeb8b5943bed3810868400aa58 | 185072 | pcapng, recorded TCP SYN scan, 2011 packets |
| arp_resolution.pcapng | https://raw.githubusercontent.com/chrissanders/packets/master/arp_resolution.pcapng | 70ee2e68676ac0f8ef3a5771cc13110fad8d5c5f23af6d31d7febfb8605b2a77 | 216 | pcapng, ARP request/reply (non-IP) |
| loopback.pcap | https://raw.githubusercontent.com/the-tcpdump-group/tcpdump/master/tests/loopback.pcap | 403e99de7ef383fba93cb56a188b6f5cb742d05a720d56373447d561efd71386 | 592 | pcap, Ethernet configuration-testing (loopback, 0x9000) frames, non-IP |

## Attribution / terms

* Wireshark wiki sample captures — published at https://wiki.wireshark.org/SampleCaptures for testing and education.
* chrissanders/packets — "You are free to use these, but should cite that they came from me" (Chris Sanders, *Practical Packet Analysis*), https://github.com/chrissanders/packets.
* tcpdump test suite — https://github.com/the-tcpdump-group/tcpdump (BSD licence).

## Scenario labels

None of these captures ships with a NetGuard scenario label, so tests import
them with `scenario_label = null`. `synscan.pcapng` is a recorded scan, but
the label is **not** assigned automatically: an operator would have to pass
`--scenario-label PORT_SCAN` based on the dataset's documentation.

## Re-download

`bash modules/pcap-importer/scripts/fetch_test_pcaps.sh` re-downloads all files and verifies the checksums above.
