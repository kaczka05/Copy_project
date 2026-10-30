# NetGuard — Final Implementation Report

**Subsystem:** PCAP / Flow Ingestion, Flow Extraction, Validation & Normalisation
**Module path:** `modules/pcap-importer/`
**Owner:** Member 1 — Network Data & Flow Processing
**Language / runtime:** Python 3.10+ (developed on 3.11.18)
**Status:** Complete. All in-scope acceptance criteria met.
**Report date:** 2026-10-30

This document is the acceptance deliverable for Section 21 of the PRD. It lists
what was built, what libraries were used, how it was tested, the policies
applied, and every known deviation or limitation — including the broken
reference contract example `flow.valid.json`, which the user explicitly
requested be left as-is and reported.

---

## 1. Scope delivered

The implementation fulfils the following PRD requirements:

| PRD requirement | Status | Notes |
|---|---|---|
| **F01** Ingest prepared PCAP and prepared flow datasets; validate input | ✅ Done | PCAP/PCAPNG and NetGuard-native CSV / JSON-lines |
| **F02** Convert traffic into a normalised unidirectional flow model | ✅ Done | FlowEvent v1 contract, JSON-lines output |
| **F15** Preserve dataset provenance / traceability | ✅ Done | SHA-256, `dataset_id`, `trace_id`, `source_type`, per-ingestion report |
| **No simulation / no fake data** (hard rule) | ✅ Enforced | No code path generates traffic; `SIMULATOR` source type and `simulation_run_id` are **rejected** |
| **Graceful handling of malformed input** | ✅ Done | Line/packet-level reject reasons; the pipeline never crashes on bad data |
| **Output to JSON-lines** | ✅ Done | `flows.jsonl` per ingestion, plus `report.json`, `rejections.jsonl`, `catalogue.jsonl` |
| **Deliver technical implementation report + how-to-run doc** | ✅ Done | This file + `docs/HOW_TO_RUN.md` |

**Explicitly out of scope** (not implemented, confirmed with user):
anomaly detection, Kafka publishing, REST API / dashboard, persistence,
live packet capture, synthetic traffic generation, time-window features
(pps, bps, unique-ports/IPs, new-connection rate).

---

## 2. Files created / modified

All new code lives under `modules/pcap-importer/`. No files outside this
module were modified.

```
modules/pcap-importer/
├── netguard_ingest/              # Python package (production code)
│   ├── __init__.py
│   ├── __main__.py               # `python -m netguard_ingest ...`
│   ├── cli.py                    # argparse CLI: pcap | flows | list | validate-output
│   ├── config.py                 # env + CLI precedence
│   ├── contract.py               # JSON-Schema validation against flow-event.v1
│   ├── errors.py                 # Reject codes & categories
│   ├── ids.py                    # Deterministic UUID5 flow_id / event_id, UUID4 trace_id
│   ├── logging_setup.py          # Text / JSON structured logs
│   ├── model.py                  # FlowEvent + report dataclasses
│   ├── normalize.py              # Timestamps, IPs, ports, protocol, counters, flags
│   ├── validation.py             # Cross-field invariants
│   ├── output.py                 # Atomic per-ingestion directory writer
│   ├── pipeline.py               # Orchestration, SHA-256, shared emit path
│   ├── capture/
│   │   ├── reader.py             # Streaming pcap + pcapng reader (own framing)
│   │   ├── decoder.py            # dpkt-based link/IP/transport decoder
│   │   └── aggregator.py         # Unidirectional flow table, timeouts, flush
│   └── datasets/
│       ├── reader.py             # CSV / JSONL stream reader with per-line reject
│       ├── mapping.py            # Explicit source→model field mapping
│       └── profiles/
│           └── netguard-native.json
├── tests/                        # pytest suite (177 passing)
│   ├── conftest.py               # SHA-256 pre-flight for every PCAP fixture
│   ├── test_capture_reader.py    # 30 tests
│   ├── test_packet_decoder.py    # 19 tests
│   ├── test_flow_aggregation.py  # 25 tests
│   ├── test_dataset_ingestion.py # 11 tests
│   ├── test_normalize_validate.py# 65 tests
│   ├── test_integration.py       # 27 end-to-end tests
│   └── data/pcap/                # Real captures + SOURCES.md with SHA-256
├── scripts/
│   └── fetch_test_pcaps.sh       # Reproducible download of real PCAPs
├── docs/
│   ├── HOW_TO_RUN.md             # Installation + every command
│   └── DESIGN.md                 # Technical design (as implemented)
├── pyproject.toml                # Package metadata + console_script
├── requirements.txt              # Runtime deps
├── requirements-dev.txt          # Runtime + pytest
├── README.md
└── IMPLEMENTATION_REPORT.md      # This document
```

---

## 3. Libraries used

| Library | Version | Why |
|---|---|---|
| `dpkt` | 1.9.8 | Packet header classes (`FileHdr`, `PktHdr`, SHB, IDB, EPB, Ethernet, IPv4/IPv6, TCP/UDP/ICMP). We call dpkt's parsers but drive the record/block loop ourselves — see §5. |
| `jsonschema[format]` | 4.26.0 | Contract validation of `flows.jsonl` against `contracts/kafka/flow-event.v1.schema.json`. The `[format]` extra is **mandatory**: it enables `date-time` / `ipv4` / `ipv6` checkers; the tool refuses to run without them. |
| `rfc3339-validator` | installed transitively | Backs `jsonschema`'s `date-time` format checker. |
| `pytest` | dev-only | Test runner. |

No other third-party packages are required. Standard library modules used:
`ipaddress`, `uuid`, `hashlib`, `json`, `csv`, `argparse`, `datetime`,
`pathlib`, `logging`, `enum`, `dataclasses`.

---

## 4. Flow-extraction strategy (unidirectional)

**Key definition:** `(src_ip, src_port, dst_ip, dst_port, protocol)` — ports
set to `0` for ICMP/ICMPv6/non-port protocols. **Unidirectional**: forward and
reverse directions are two distinct flows.

**Life-cycle:**

1. Each packet is decoded (`capture/decoder.py`) and attributed to its key.
2. The aggregator (`capture/aggregator.py`) updates `packets`, `bytes` (sum of
   captured L2 wire lengths), `tcp_flags` (bitwise OR of observed flags),
   `start_time` (first packet), `last_time` (last packet).
3. A flow is closed and emitted on any of:
   * **IDLE_TIMEOUT**: no packet for `--idle-timeout` seconds (default 60 s)
   * **ACTIVE_TIMEOUT**: open longer than `--active-timeout` seconds (default 1800 s)
   * **END_OF_CAPTURE**: file fully read
   * **FLOW_TABLE_LIMIT**: oldest flows evicted when `--max-active-flows` exceeded
4. `duration_ms` = `last_time − start_time` in milliseconds (always ≥ 0).

**Byte counting policy:** captured bytes (L2 wire length), not snaplen-truncated
caplen — truncation is counted separately in `packets.snaplen_truncated`.

**Non-TCP flows:** `tcp_flags` is `null`. Validation rejects `tcp_flags` on
non-TCP flows (contract rule).

---

## 5. Why the reader does its own framing

dpkt 1.9.8's bundled `pcap.Reader` / `pcapng.Reader` were insufficient:

* They discard the original packet length (we need both `caplen` and `wirelen`).
* They apply only the **first** pcapng IDB — wrong link type and timestamp
  resolution for multi-interface files (e.g. `tfp_capture.pcapng`, Ethernet +
  USB).
* They silently stop or return short buffers on truncated files.
* They expose only float timestamps (precision loss for ns-resolution captures).

Our reader (`capture/reader.py`) drives the record/block loop with integer-ns
timestamps and per-interface state. **Header decoding** still uses dpkt's
classes (`FileHdr`, `PktHdr`, `SectionHeaderBlock`,
`InterfaceDescriptionBlock`, `EnhancedPacketBlock`, `PacketBlock`,
`Ethernet`, `IP`, `IP6`, `TCP`, `UDP`, `ICMP`). The code does not re-implement
protocol parsing.

**Formats supported:**
* pcap: both byte orders, µs (`a1b2c3d4`) and ns (`a1b23c4d`), v2.x
* pcapng 1.x: multiple sections, multiple interfaces, EPB + PB, obsolete Simple
  Packet Blocks rejected (no timestamp)
* Link types: Ethernet (1) incl. 802.1Q / QinQ / MPLS; Linux SLL / SLL2;
  BSD loopback NULL / LOOP; raw IP; IPv4 / IPv6
* Rejected at file level: modified-pcap (Kuznetzov), gzip, unsupported magic,
  truncated SHB / global header, unknown major version

---

## 6. Normalisation rules applied

All applied identically to PCAP and dataset inputs:

* **Timestamps** → UTC RFC-3339 with microsecond precision; naive datetimes
  rejected unless `--assume-timezone` is set.
* **IP addresses** → `ipaddress.ip_address(...).compressed` canonical form;
  IPv4-in-IPv6 (`::ffff:a.b.c.d`) normalised to the embedded IPv4; link-local
  and multicast kept; zone-id stripped.
* **Ports** → integers in `[0, 65535]`; `null` only on non-port protocols.
* **Protocol** → upper-case canonical name (`TCP`, `UDP`, `ICMP`, `ICMPV6`,
  `OTHER` when `--emit-other-protocols`); numeric IP protocol accepted and
  mapped.
* **Counters** → non-negative integers; empty strings normalised to `0`
  (dataset path only) with a warning.
* **`duration_ms`** → integer or float ≥ 0.
* **TCP flags** → integer `0..255`; `0x..` accepted on input; `null` for non-TCP.
* **Scenario labels** → one of `NORMAL`, `PORT_SCAN`, `DOS_LIKE`,
  `BRUTE_FORCE_LIKE`, `ABNORMAL_CONNECTION_PATTERN`, or `null`.
* **Identifiers** → `flow_id` = UUID5(key + start_time), `event_id` =
  UUID5(flow_id + sequence), `trace_id` = per-ingestion UUID4
  (`ing-<hex>`).

**Validation (cross-field):** `src_ip ≠ dst_ip` not enforced (loopback is
legal); IPv4-vs-IPv6 family consistency; port required on TCP/UDP; `tcp_flags`
only on TCP; `packets ≥ 1`; `bytes ≥ packets` (sanity).

---

## 7. Output artefacts (per ingestion)

```
ingestion-output/
└── ing-<32-hex>/
    ├── flows.jsonl         # FlowEvent v1 records, one per line
    ├── report.json         # Full stats, source hash, config, rejections summary
    ├── rejections.jsonl    # Per-line / per-packet reject details (bounded)
    └── manifest.json       # Entry added to ../catalogue.jsonl
```

A `flows.jsonl` entry (real sample from `tcp-ecn-sample.pcap`):

```json
{"schema_version":1,"event_id":"evt-76542fbf-...","trace_id":"ing-c67edf47...","flow_id":"flow-7fbbd47d-...","ingest_time":"2026-10-30T18:40:48.150380Z","start_time":"2011-04-22T18:23:49.238845Z","duration_ms":94103.0,"src_ip":"1.1.23.3","src_port":46557,"dst_ip":"1.1.12.1","dst_port":80,"protocol":"TCP","packets":309,"bytes":12525,"tcp_flags":219,"source_type":"PCAP","dataset_id":"tcp-ecn-sample-e6edf98f9e2e","simulation_run_id":null,"scenario_label":null}
```

Contract validation (`contracts/kafka/flow-event.v1.schema.json`) is applied
to every emitted record. Any record failing the schema is routed to
`rejections.jsonl` with a precise reason; the pipeline continues.

---

## 8. Test suite — what was executed

* **Framework:** `pytest`
* **Last run:** `python -m pytest tests/ -q` → **177 passed in 2.23 s**
* **Fixture integrity:** `tests/conftest.py` SHA-256-verifies every public PCAP
  before the suite runs (see `tests/data/pcap/SOURCES.md`).

| Test file | # tests | Covers |
|---|---:|---|
| `test_capture_reader.py` | 30 | pcap/pcapng framing, multi-interface, truncation, unknown magic, obsolete blocks |
| `test_packet_decoder.py` | 19 | Ethernet / VLAN / MPLS / SLL / loopback link types; IPv4/IPv6 incl. ext. headers; TCP/UDP/ICMP; malformed-packet rejection reasons |
| `test_flow_aggregation.py` | 25 | Key direction, byte & packet accumulation, idle / active / EOF / table-limit close, tcp_flags OR |
| `test_dataset_ingestion.py` | 11 | CSV + JSONL happy path, malformed lines, BOM, missing columns, SIMULATOR rejection |
| `test_normalize_validate.py` | 65 | Timestamps, IPs, ports, protocol, counters, flags, scenario labels, contract validation |
| `test_integration.py` | 27 | End-to-end CLI runs on real captures, provenance, report content, atomic output |
| **Total** | **177** | |

**Real captures used (publicly published, SHA-256-verified):**
`dns.cap`, `v6.pcap`, `tfp_capture.pcapng`, `arp-storm.pcap`, `ipv4frags.pcap`,
`sr-header.pcap`, `telnet-raw.pcap`, `tcp-ecn-sample.pcap`,
`200722_tcp_anon.pcapng`, `icmp_echo.pcapng`, `icmp_traceroute.pcapng`,
`tcp_handshake.pcapng`, `tcp_teardown.pcapng`, `udp_dnsrequest.pcapng`,
`http_ip4and6.pcapng`, `synscan.pcapng`, `arp_resolution.pcapng`,
`loopback.pcap`. Sources: Wireshark SampleCaptures wiki,
`chrissanders/packets`, tcpdump test suite. Downloaded by
`scripts/fetch_test_pcaps.sh`.

**No synthetic traffic was generated anywhere in the test suite.** Malformed-
input tests mutate *temporary copies* of real captures.

---

## 9. Performance / benchmark numbers

End-to-end runs (`python -m netguard_ingest pcap <file> --output-dir /tmp/bench`),
cold cache, single process, Python 3.11.18 inside the container:

| Capture | Size | Elapsed | Packets examined | Flows emitted | Rejections |
|---|---:|---:|---:|---:|---:|
| `synscan.pcapng` | 185 072 B | 0.586 s | 2 011 | 2 002 | 0 |
| `200722_tcp_anon.pcapng` | 12 800 B | 0.218 s | 35 | 4 | 0 |
| `http_ip4and6.pcapng` | 3 424 B | 0.220 s | 20 | 4 | 0 |
| `tfp_capture.pcapng` (2 interfaces) | 179 072 B | 0.249 s | 1 648 | 19 | 977 (USB IF unsupported) |
| `tcp-ecn-sample.pcap` | 118 965 B | 0.224 s | 479 | 2 | 0 |
| `telnet-raw.pcap` | 24 345 B | 0.221 s | 272 | 2 | 0 |
| `arp-storm.pcap` | 47 296 B | 0.228 s | 622 | 0 | 622 (ARP, non-IP) |
| `dns.cap` | 4 338 B | 0.270 s | 38 | 19 | 0 |
| `v6.pcap` | 28 251 B | 0.230 s | 161 | 64 | 0 |
| `ipv4frags.pcap` | 2 990 B | 0.214 s | 3 | 2 | 1 (fragment w/o L4 header) |

Measured startup overhead (Python import + contract load) is ~0.20 s and
dominates the smaller files. Steady-state throughput on `synscan.pcapng`
is ≈ 3 400 packets/s / 320 KB/s per process. The pipeline is streaming
and memory-bound only by `--max-active-flows` (default 1 000 000).
pytest suite completes in **~2.2 s** total.

---

## 10. Quick-reference commands (how to run)

Full instructions: [`docs/HOW_TO_RUN.md`](docs/HOW_TO_RUN.md). Essentials:

```bash
# Install
cd modules/pcap-importer
python -m pip install -r requirements-dev.txt

# Fetch the real-world test PCAPs (public sources, SHA-256 checked)
bash scripts/fetch_test_pcaps.sh

# Ingest one PCAP / PCAPNG
python -m netguard_ingest pcap tests/data/pcap/telnet-raw.pcap \
    --output-dir ./ingestion-output

# Ingest a whole directory of captures
python -m netguard_ingest pcap tests/data/pcap --output-dir ./ingestion-output

# Ingest a prepared NetGuard-native flow dataset (CSV or JSONL)
python -m netguard_ingest flows path/to/flows.csv  --output-dir ./ingestion-output
python -m netguard_ingest flows path/to/flows.jsonl --output-dir ./ingestion-output

# List prior ingestions
python -m netguard_ingest list --output-dir ./ingestion-output

# Re-validate an existing flows.jsonl against FlowEvent v1
python -m netguard_ingest validate-output ./ingestion-output/ing-<id>/flows.jsonl

# Full test suite
python -m pytest
```

Flow-aggregation tuning: `--idle-timeout 60 --active-timeout 1800
--max-active-flows 1000000`. Provenance: `--dataset-id <id>
--scenario-label PORT_SCAN`. Fail-fast: `--fail-on-rejections`. Structured
logs: `--log-format json`.

---

## 11. Deviations from the PRD

| # | Deviation | Reason |
|---|---|---|
| 1 | Output is **JSON-lines files only**, not Kafka publishing | User explicitly chose JSON-lines output; Kafka publishing is the next tier's responsibility. The emitted records match `flow-event.v1` 1-for-1, so plugging a Kafka producer in later is drop-in. |
| 2 | No time-window features (pps, bps, unique-ports/IPs, new-connection rate) | Out of scope for this subsystem; belongs to the Flow Processor / detection tier. |
| 3 | `UNSUPPORTED_LINK_TYPE` rejects whole-file for classic pcap but per-packet for pcapng | Classic pcap has one global link type; pcapng can mix interfaces, so per-packet is the only correct behaviour. |
| 4 | `source_type=SIMULATOR` and any `simulation_run_id` are **rejected on input** | Enforces the PRD's "no simulation" rule even against data labelled by third parties. |

---

## 12. Known limitations

* **IPv4 fragmentation**: only the first fragment carries the L4 header, so
  subsequent fragments are rejected with `MISSING_L4_HEADER`. Reassembly is
  not performed (not required by the PRD; adds state and attack surface).
* **IPv6 extension headers** are walked but IPv6 fragmentation is treated the
  same way as IPv4 fragmentation.
* **TCP sessions are not reassembled**; packet counting + flag OR is sufficient
  for the flow model.
* **Encrypted / tunnelled traffic** (GRE, IPsec, VXLAN) is not decapsulated;
  tunnel outer flows are reported.
* **Live capture is not supported** by design — only prepared files.
* **No parallelism**: one process, one input file at a time. The CLI is
  trivially embarrassingly parallel across files via shell / `xargs -P`.
* **Clock skew / `thiszone`**: libpcap defines record timestamps as UTC;
  `thiszone` is ignored with a warning rather than silently applied.
* **Broken reference contract example** — see §13.

---

## 13. Known broken file (left as-is per user instruction)

**File:** `/app/contracts/kafka/examples/flow.valid.json`
**Issue:** invalid JSON — trailing comma after the last field (line 11):

```json
  "tcp_flags": 24,
}
```

**Affected tests (in `/app/tests/test_kafka_example_contracts.py`):**
`test_valid_flow`, `test_valid_detection`, `test_non_tcp_flags_rejected`,
`test_inconsistent_window_rejected` — 4 pre-existing failures,
`json.decoder.JSONDecodeError`.

**Why it is not fixed:** the user explicitly instructed to **leave the broken
contract alone and report it**. These failures predate this module and belong
to the Kafka contract examples maintained outside `modules/pcap-importer/`.
Fixing it is a two-character delete, but is intentionally deferred to the owner
of that artefact.

**Impact on this subsystem:** none. The real schema file
(`contracts/kafka/flow-event.v1.schema.json`) is valid and is loaded at
startup; our 177 tests pass; emitted flows validate against the schema.

---

## 14. Provenance preservation

Every ingestion records:

* `source.path`, `source.original_filename`, `source.size_bytes`,
  `source.sha256`
* `source.dataset_id` (either user-supplied via `--dataset-id` or derived
  deterministically as `<basename>-<sha256[:12]>`)
* `source.format` (pcap / pcapng / csv / jsonl)
* `tool.name` / `tool.version` / `tool.python` / `tool.dpkt` /
  `tool.jsonschema`
* `started_at` / `completed_at` / `processing_duration_ms`
* `config` (every CLI/env setting that influenced the run)
* Per-flow `trace_id` → ingestion id; `source_type` ∈ {PCAP, FLOW_DATASET};
  `source_dataset_id` carried onto every emitted record

This satisfies **F15** (trace an event from input onwards).

---

## 15. Acceptance checklist

* [x] Ingests real PCAP + PCAPNG, including multi-interface pcapng
* [x] Ingests NetGuard-native CSV and JSON-lines datasets
* [x] Produces normalised **unidirectional** flows
* [x] Validates against `flow-event.v1` schema
* [x] Writes JSON-lines output with provenance
* [x] Handles malformed input gracefully (no crashes, per-record reject)
* [x] 177 unit + integration tests pass
* [x] `README.md`, `docs/HOW_TO_RUN.md`, `docs/DESIGN.md`,
      `IMPLEMENTATION_REPORT.md` delivered
* [x] No synthetic / simulated traffic produced anywhere
* [x] Broken `flow.valid.json` reported, not modified

**End of report.**
