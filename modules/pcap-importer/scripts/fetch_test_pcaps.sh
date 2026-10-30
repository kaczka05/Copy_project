#!/usr/bin/env bash
# Re-download the genuine public test captures and verify their SHA-256.
# Usage: bash modules/pcap-importer/scripts/fetch_test_pcaps.sh [target-dir]
set -euo pipefail
DIR="${1:-$(cd "$(dirname "$0")/.." && pwd)/tests/data/pcap}"
mkdir -p "$DIR"
W=https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures
C=https://raw.githubusercontent.com/chrissanders/packets/master
T=https://raw.githubusercontent.com/the-tcpdump-group/tcpdump/master/tests
while read -r name url sha; do
  [ -z "$name" ] && continue
  if [ ! -f "$DIR/$name" ]; then
    echo "downloading $name"
    curl -fsSL -o "$DIR/$name" "$url"
    sleep 2   # the Wireshark wiki rate-limits rapid downloads
  fi
  echo "$sha  $DIR/$name" | sha256sum -c -
done <<EOF
dns.cap $W/dns.cap 041eeb6f98bb398f1ee8b09651b5b5a84f6a62639f95bf226f9e7b77355d9f28
v6.pcap $W/v6.pcap 8e18b4c2aa872285881f3aff39481eabc83024369a7b83d95573d846a4a091f2
tfp_capture.pcapng $W/tfp_capture.pcapng 0e90321c59b535f2564ed7c36ded6303aedc32325f3f9cdf86e0113b9fd34ae8
arp-storm.pcap $W/arp-storm.pcap dc101ea9bfda59f56b54bfb949195c3f169032c045b47f98e6952a86933c1b8d
ipv4frags.pcap $W/ipv4frags.pcap d0b1965aa0c7f9792ee1922f18b1c4e67a45f014fbd324c18dda0dd280605ec4
sr-header.pcap $W/sr-header.pcap d9471b7f1ee484e572e94d9b961103559faef3f6c355b23d7a42f2f5181fa4d8
telnet-raw.pcap $W/telnet-raw.pcap 7a2fdd843b401fb945b0604b9d760424541b045dac6424361f14d276db2b05a3
tcp-ecn-sample.pcap $W/tcp-ecn-sample.pcap e6edf98f9e2e8a9711fb41a4e16840ef3942b40c7d2694ca373b7f285c783648
200722_tcp_anon.pcapng $W/200722_tcp_anon.pcapng 5295b16ea117fa8bb1a65418fca81e709bea58d3a830bc3bb5c4a2ed0466ea9c
icmp_echo.pcapng $C/icmp_echo.pcapng 132accec4fc83a373ab15e7bb525dd8fb1f7935a105710d43a0b53a9a018b385
icmp_traceroute.pcapng $C/icmp_traceroute.pcapng 25049f2ad3ee32894bbdc91f234d4997b1462b19aee7e5f2364d497e75e049b5
tcp_handshake.pcapng $C/tcp_handshake.pcapng 681bcc3526ad9476272b21f38caaebfcaed3354b7886cad86e1ecf23242567ab
tcp_teardown.pcapng $C/tcp_teardown.pcapng f1bd881a23424e58a9f8e2872d5e4854aed140b4b76b64402c1a3606b458677b
udp_dnsrequest.pcapng $C/udp_dnsrequest.pcapng 76f497ac221e7682f9c15cd66ec7dca8a475e8df498136ac2bff3dfcd9f5b828
http_ip4and6.pcapng $C/http_ip4and6.pcapng e5c68d29c19d7cd0761b635af4ebbccd2f51c47be6902e2859ce9ab7678b7502
synscan.pcapng $C/synscan.pcapng 3ef7a9011bcc2901080d3800d52fd5bb5cbcc1aeb8b5943bed3810868400aa58
arp_resolution.pcapng $C/arp_resolution.pcapng 70ee2e68676ac0f8ef3a5771cc13110fad8d5c5f23af6d31d7febfb8605b2a77
loopback.pcap $T/loopback.pcap 403e99de7ef383fba93cb56a188b6f5cb742d05a720d56373447d561efd71386
EOF
echo "All test captures present and verified in $DIR"
