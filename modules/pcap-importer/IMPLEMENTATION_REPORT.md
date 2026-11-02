# NetGuard PCAP/flow ingestion: implementation report

Module: `modules/pcap-importer/` (package `netguard_ingest`)
Owner: Member 1, Network Data & Flow Processing
Requirements covered: F01 (import prepared PCAP/flow data and validate input),
F02 (convert traffic into a normalised flow model), provenance for F15.

Technical details are in [docs/DESIGN.md](docs/DESIGN.md); commands in
[docs/HOW_TO_RUN.md](docs/HOW_TO_RUN.md). This report summarises what exists,
how it was tested, measured performance, deviations and limitations.

## 1. Implemented capabilities

* Import of prepared **pcap** (µs and ns, both byte orders) and **pcapng**
  (multiple sections and interfaces, per-interface link type and timestamp
  resolution) captures.
* Import of prepared **NetGuard-native flow datasets** in CSV and JSON-lines,
  with explicit, versioned mapping profiles (`netguard-native` built in).
* Packet decoding with dpkt: Ethernet (VLAN, QinQ, MPLS), Linux SLL/SLL2,
  NULL/LOOP, raw IP; IPv4, IPv6 with extension headers; TCP, UDP, ICMP, ICMPv6.
* **Unidirectional** flow extraction with idle timeout, active timeout,
  end-of-capture flush and a bounded flow table.
* Normalisation and validation identical for both input types, followed by a
  JSON Schema check against `contracts/kafka/flow-event.v1.schema.json`.
* Output as JSON-lines per ingestion: `flows.jsonl` (FlowEvent v1),
  `provenance.jsonl`, `rejects.jsonl`, `report.json`, plus the catalogue
  `ingestions.jsonl`. Directories appear atomically.
* Item-level rejection with stable error codes; the tool does not stop on
  malformed packets or records.
* No traffic is generated or simulated. Dataset records marked as simulator
  output are rejected (`SYNTHETIC_RECORD_REJECTED`).

## 2. Files

```text
modules/pcap-importer/
├── netguard_ingest/
│   ├── __init__.py, __main__.py
│   ├── cli.py              commands pcap | flows | list | validate-output
│   ├── config.py           defaults < environment < CLI
│   ├── pipeline.py         file checks, SHA-256, orchestration, report
│   ├── capture/reader.py   pcap/pcapng record framing
│   ├── capture/decoder.py  link/network/transport decoding (dpkt)
│   ├── capture/aggregator.py  flow table and timeouts
│   ├── datasets/reader.py  CSV / JSON-lines streaming
│   ├── datasets/mapping.py mapping profiles, type conversion
│   ├── datasets/profiles/netguard-native.json
│   ├── normalize.py        value rules
│   ├── validation.py       cross-field rules
│   ├── contract.py         FlowEvent v1 JSON Schema check
│   ├── output.py           atomic output directory, catalogue
│   ├── model.py, errors.py, ids.py, logging_setup.py
├── tests/                  pytest suite, genuine captures in tests/data/pcap
├── scripts/fetch_test_pcaps.sh
├── docs/DESIGN.md, docs/HOW_TO_RUN.md
├── README.md, IMPLEMENTATION_REPORT.md
├── pyproject.toml, requirements.txt, requirements-dev.txt
```

No source, contract or test file outside `modules/pcap-importer/` was changed.

## 3. Libraries

| Library | Version | Use |
|---|---|---|
| dpkt | 1.9.8 | pcap/pcapng header classes and all protocol parsing |
| jsonschema[format] | 4.26.0 | FlowEvent v1 contract check (the `format` extra enables `date-time`, `ipv4`, `ipv6`) |
| pytest | dev only | tests |

dpkt's own `pcap.Reader`/`pcapng.Reader` are not used for framing, because they
drop the original packet length, apply only the first pcapng interface and
return float timestamps (DESIGN.md §2). Headers are still decoded with dpkt
classes.

## 4. Key policies (summary)

| Topic | Policy |
|---|---|
| Flow key | `(src_ip, src_port, dst_ip, dst_port, IP protocol number)`; ports `null` for ICMP/ICMPv6/OTHER; A→B and B→A are separate flows |
| Timeouts | idle 60 s, active 1800 s, table limit 1,000,000 (all configurable) |
| Flow end | idle timeout, active timeout, end of capture, table limit; TCP FIN/RST do not close flows |
| Bytes | IP layer as captured (IP header to end of IP packet); link-layer headers, padding and FCS excluded |
| Fragments | non-first fragments rejected (`IP_FRAGMENT_NOT_REASSEMBLED`), no reassembly |
| Timestamps | RFC 3339 UTC, µs precision; naive dataset timestamps rejected unless a zone is configured |
| IP addresses | IPv4 dotted quad; IPv6 RFC 5952 lower-case; IPv4-mapped as `::ffff:a.b.c.d` on every Python version |
| Missing vs zero | empty cell / `null` means unavailable and is never turned into `0` |
| `tcp_flags` | bitwise OR of observed flags; `null` for non-TCP |
| Identifiers | `flow_id`, `event_id` deterministic (UUIDv5); `trace_id` = ingestion id |

## 5. Tests executed

Command: `python -m pytest` in `modules/pcap-importer`.

| Interpreter | Result |
|---|---|
| Python 3.11.18 (Linux) | 178 passed |
| Python 3.12.10 (Linux) | 178 passed |

| Test file | Tests | Scope |
|---|---:|---|
| test_capture_reader.py | 30 | framing, multi-interface pcapng, truncation, bad magic, unsupported formats |
| test_packet_decoder.py | 19 | link types, IPv4/IPv6, transport headers, malformed packets |
| test_flow_aggregation.py | 25 | direction, counters, timeouts, table limit, flags |
| test_dataset_ingestion.py | 11 | CSV/JSON-lines, malformed lines, encoding, missing columns, simulator records |
| test_normalize_validate.py | 66 | value rules, cross-field rules, contract check |
| test_integration.py | 27 | CLI end to end on genuine captures, outputs, report, provenance |

All captures in `tests/data/pcap/` are public captures listed with URL and
SHA-256 in `tests/data/pcap/SOURCES.md`; `conftest.py` checks the hashes before
the tests run. Malformed-input tests modify temporary copies only.

### End-to-end run on all sample captures

Every capture in `tests/data/pcap/` was imported with the CLI, then checked:
`validate-output` passes, `flows.jsonl` / `provenance.jsonl` / `rejects.jsonl`
agree with `report.json`, examined packets = packets in flows + rejected
packets, and each `flows.jsonl` re-imports as a NetGuard-native dataset with
status `COMPLETED`. Output was identical on Python 3.11.18 and 3.12.10 (apart
from `trace_id` and `ingest_time`).

| Capture | Packets | Flows | Rejected | Reason |
|---|---:|---:|---:|---|
| 200722_tcp_anon.pcapng | 35 | 4 | 0 | |
| arp-storm.pcap | 622 | 0 | 622 | NON_IP_PACKET (ARP) |
| arp_resolution.pcapng | 2 | 0 | 2 | NON_IP_PACKET (ARP) |
| dns.cap | 38 | 19 | 0 | |
| http_ip4and6.pcapng | 20 | 4 | 0 | |
| icmp_echo.pcapng | 8 | 2 | 0 | |
| icmp_traceroute.pcapng | 54 | 10 | 0 | |
| ipv4frags.pcap | 3 | 2 | 1 | IP_FRAGMENT_NOT_REASSEMBLED |
| loopback.pcap | 6 | 0 | 6 | NON_IP_PACKET (ethertype 0x9000) |
| sr-header.pcap | 10 | 1 | 4 | UNSUPPORTED_IP_PROTOCOL (IPv6-in-IPv6) |
| synscan.pcapng | 2011 | 2002 | 0 | |
| tcp-ecn-sample.pcap | 479 | 2 | 0 | |
| tcp_handshake.pcapng | 3 | 2 | 0 | |
| tcp_teardown.pcapng | 4 | 2 | 0 | |
| telnet-raw.pcap | 272 | 2 | 0 | |
| tfp_capture.pcapng | 1648 | 19 | 977 | UNSUPPORTED_LINK_TYPE=975 (USB interface), UNSUPPORTED_IP_PROTOCOL=2 |
| udp_dnsrequest.pcapng | 1 | 1 | 0 | |
| v6.pcap | 161 | 64 | 0 | |

Total: 18 captures, 2,136 flows. The rejections are expected for the content
of these files.

### Not tested on genuine data

SLL, SLL2, NULL/LOOP, raw-IP files, VLAN, MPLS, big-endian files,
nanosecond-resolution pcap, and pcapng Packet/Simple Packet blocks. They are
implemented from the format specifications, but no downloaded capture
contains them.

## 6. Performance

Python 3.11.18, single process, in-process timing on `synscan.pcapng`
(185,072 bytes, 2,011 packets, 2,002 flows), best of 3:

| Mode | Time | Flows/s | Packets/s |
|---|---:|---:|---:|
| with per-flow JSON Schema check (default) | 0.365 s | ~5,480 | ~5,500 |
| `--no-contract-validation` | 0.104 s | ~19,300 | ~19,400 |

From the command line each file takes about 0.21 s more, mostly interpreter
start-up and schema loading, so small captures take about 0.21 s each. The
schema check (about 130 µs per flow) is the main cost. Memory is limited by
`--max-active-flows`; input is streamed.

## 7. Quick reference

```bash
cd modules/pcap-importer
python -m pip install -r requirements-dev.txt
bash scripts/fetch_test_pcaps.sh                      # only if captures are missing

python -m netguard_ingest pcap tests/data/pcap/telnet-raw.pcap --output-dir ./ingestion-output
python -m netguard_ingest pcap tests/data/pcap --output-dir ./ingestion-output      # whole directory
python -m netguard_ingest flows my_flows.csv --output-dir ./ingestion-output
python -m netguard_ingest flows my_flows.jsonl --output-dir ./ingestion-output
python -m netguard_ingest list --output-dir ./ingestion-output
python -m netguard_ingest validate-output ./ingestion-output/<ingestion_id>/flows.jsonl
python -m pytest
```

Options: `--idle-timeout`, `--active-timeout`, `--max-active-flows`,
`--dataset-id`, `--scenario-label`, `--emit-other-protocols`,
`--no-contract-validation`, `--fail-on-rejections`, `--json`; global
`--log-level`, `--log-format json`. Full table in HOW_TO_RUN.md §7.

## 8. Deviations

* Output is JSON-lines files only; publishing to Kafka topic `flows.normalized`
  is left to the Flow Processor. Each line is already a validated FlowEvent v1
  message.
* No time-window features (pps, bps, unique ports/IPs, new-connection rate);
  these belong downstream.
* Only the `netguard-native` mapping profile is included.

## 9. Known limitations

* No IP reassembly: non-first fragments are rejected and counted, so flows
  with fragmented datagrams undercount packets and bytes.
* Tunnels (GRE, IP-in-IP, VXLAN, PPPoE) are not decapsulated.
* TCP FIN/RST and port reuse within the idle timeout do not split flows.
* Bidirectional dataset records (for example CICFlowMeter) cannot be mapped to
  unidirectional flows by a profile alone.
* Link types and formats listed in §5 "Not tested on genuine data".
* NFR01 (5,000 flows/s for 5 minutes) has not been load-tested; no large
  genuine capture was available. Short-run throughput is in §6.
* `contracts/kafka/examples/flow.valid.json` is not valid JSON (trailing comma
  after `"tcp_flags": 24`). Four tests in `tests/test_kafka_example_contracts.py`
  at the repository root fail because of it. The file is outside this module
  and was left unchanged; this module uses
  `contracts/kafka/flow-event.v1.schema.json` only, which is valid.
