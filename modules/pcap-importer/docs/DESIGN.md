# NetGuard ingestion subsystem: technical design (as implemented)

This document describes what the code does. It is not an aspiration.

## 1. Component responsibilities and boundaries

Architecture position (NetGuard Application Architecture, *Ingestion Tier*):

```text
prepared PCAP / flow files ──► [PCAP/Flow Importer] ──► FlowEvent v1 JSON-lines ──► (Flow Processor publishes to
                                 this subsystem                                     Kafka flows.normalized — not here)
```

| Component | Module | Responsibility |
|---|---|---|
| CLI | `cli.py` | Commands, configuration precedence, exit codes, human summary |
| Pipelines | `pipeline.py` | File checks, SHA-256, orchestration, shared emit path, report |
| Capture reader | `capture/reader.py` | Streams pcap/pcapng records with exact `caplen`, `wirelen`, integer-ns timestamps and per-interface link type. Detects truncation and corruption |
| Packet decoder | `capture/decoder.py` | Link layer, then IPv4/IPv6, then TCP/UDP/ICMP/ICMPv6 metadata (dpkt). Returns a precise rejection reason when it fails |
| Flow aggregator | `capture/aggregator.py` | Unidirectional flow table, timeouts, end-of-capture flush, memory bound |
| Dataset readers | `datasets/reader.py` | Streams CSV and JSON-lines, reporting malformed lines and invalid encoding per line |
| Mapping profiles | `datasets/mapping.py`, `datasets/profiles/netguard-native.json` | Explicit source-to-model field mapping and type conversion |
| Normalisation | `normalize.py` | Value rules: timestamps, IPs, ports, protocol, counters, duration, TCP flags, labels |
| Validation | `validation.py` | Cross-field rules applied identically to both sources |
| Contract | `contract.py` | JSON Schema check against the repository's `flow-event.v1.schema.json` |
| Output | `output.py` | Atomic per-ingestion directory and ingestion catalogue |
| Model / errors / ids | `model.py`, `errors.py`, `ids.py` | Data contract, error codes, deterministic identifiers |

**Out of scope, not implemented:** traffic simulation or any synthetic data,
time-window features (pps, bps, connections per window, unique ports or IPs, new-connection
rate), detection, alerting, persistence, REST API, dashboard, Kafka publishing
(output is JSON-lines files only), and live capture.

## 2. Supported capture formats

* **pcap**: magic `a1b2c3d4` (µs) and `a1b23c4d` (ns), both byte orders, version 2.x.
  `thiszone` is ignored with a warning, because libpcap defines record timestamps as UTC.
* **pcapng 1.x**: multiple sections, multiple interfaces (each IDB keeps its own
  link type, `if_tsresol` in powers of 10 or 2, and `if_tsoffset`), Enhanced Packet
  Blocks, obsolete Packet Blocks. Simple Packet Blocks have no timestamp and are
  rejected (`MISSING_PACKET_TIMESTAMP`). Other block types are skipped and counted.
* **Rejected at file level**: modified (Kuznetzov) pcap, gzip-compressed files, any
  other magic number, truncated global header or SHB, unsupported major versions.
* **Link types**: Ethernet (1) incl. 802.1Q/QinQ VLAN and MPLS; Linux SLL (113);
  Linux SLL2 (276); BSD loopback NULL (0) / LOOP (108); raw IP (101, 12, 14); IPv4 (228); IPv6 (229).
  A classic pcap with an unsupported link type fails as `UNSUPPORTED_LINK_TYPE`.
  In pcapng, packets of unsupported interfaces are rejected one by one.

### Why the reader does its own framing

dpkt 1.9.8's `pcap.Reader` and `pcapng.Reader` discard the original packet
length, apply only the *first* pcapng IDB (wrong link type and resolution for
multi-interface files such as `tfp_capture.pcapng`), silently stop or return
short buffers on truncated files, and give only float timestamps. The reader
therefore runs the record/block loop itself, but decodes every header with
dpkt's own classes (`FileHdr`, `PktHdr`, `SectionHeaderBlock`,
`InterfaceDescriptionBlock`, `EnhancedPacketBlock`, `PacketBlock`). Protocol
parsing (Ethernet, IP, IPv6 extension headers, TCP, UDP, ICMP) is done by dpkt.

## 3. Supported prepared flow-dataset formats

* **NetGuard-native CSV**: UTF-8 (a BOM is accepted), a header row is mandatory,
  RFC 4180 quoting, `,` delimiter.
* **NetGuard-native JSON-lines** (`.jsonl` / `.ndjson`): one JSON object per line.
* The format comes from the file extension, or from `--format`.

Required fields: `start_time`, `duration_ms`, `src_ip`, `src_port`, `dst_ip`,
`dst_port`, `protocol`, `packets`, `bytes`. The port **columns** are required,
but their values may be empty (null), which means unavailable or not applicable.

Optional fields:
* `tcp_flags`: integer 0–255 or `0x..`.
* `scenario_label`
* `flow_id`: kept as `source_flow_id`.
* `source_type`: must be PCAP or FLOW_DATASET. `SIMULATOR` is rejected.
* `dataset_id`: kept as `source_dataset_id`.
* `simulation_run_id`: any value causes rejection.

The FlowEvent envelope fields `schema_version`, `event_id`, `trace_id`,
`ingest_time` and `features` are deliberately ignored. Any other column is
reported as unmapped (in the report and as a warning) and is not imported.

**Mapping profiles** (`--mapping <name|file.json>`) make schema mapping explicit:

```json
{"profile": "my-dataset", "profile_version": 1, "formats": ["csv"], "null_tokens": ["", "-"],
 "fields": {
   "start_time": {"source": "StartTime", "timestamp_format": "epoch_s"},
   "duration_ms": {"source": "Dur", "duration_unit": "s"},
   "src_ip": {"source": "SrcAddr"}, "src_port": {"source": "Sport"},
   "dst_ip": {"source": "DstAddr"}, "dst_port": {"source": "Dport"},
   "protocol": {"source": "Proto", "value_map": {"tcp": "TCP"}},
   "packets": {"source": "TotPkts"}, "bytes": {"source": "TotBytes"},
   "tcp_flags": {"source": "State", "tcp_flags_format": "letters", "optional_column": true},
   "scenario_label": {"source": "Label", "value_map": {"Benign": "NORMAL"}, "optional_column": true}}}
```

* Targets: the required fields above, plus `end_time` (instead of `duration_ms`)
  and the optional fields.
* `timestamp_format`: `rfc3339`, `epoch_s`, `epoch_ms`, `epoch_us`, `epoch_ns`, or `strptime:<pattern>`.
* `timezone`: an IANA zone, for naive timestamps only.
* `duration_unit`: `s`, `ms`, `us` or `ns`.
* `tcp_flags_format`: `int`, `letters` (`FSRPAUEC`) or `names` (`SYN|ACK`).

Unknown options, unmapped required targets and invalid formats are rejected
when the profile loads (`INVALID_MAPPING_PROFILE`). The only built-in profile is
`netguard-native`. Profiles for CIC-IDS2017, UNSW-NB15 and similar datasets are
not included.

## 4. Packet parsing process

For each packet record:

1. Strip the link layer with dpkt. Ethernet uses dpkt's VLAN and MPLS handling.
   A payload that is neither IPv4 nor IPv6 is rejected as `NON_IP_PACKET`, with
   its ethertype counted.
2. **IPv4**: check that version = 4, IHL ≥ 20, the captured header is complete,
   and total length ≥ IHL. A total length of 0 (TSO) means the captured size is used.
   Non-first fragments are rejected as `IP_FRAGMENT_NOT_REASSEMBLED`. There is
   no reassembly. The first fragment carries the ports and is used.
3. **IPv6**: check that version = 6 and the header is complete. dpkt walks the
   extension headers, and the final next-header becomes the protocol. Fragment
   headers with an offset > 0 are rejected.
4. **Transport**:
   * TCP needs a decodable header with data offset ≥ 20. It provides the ports
     and `flags & 0xFF` (FIN…CWR; the NS bit is not part of the contract).
   * UDP needs a decodable 8-byte header.
   * ICMP and ICMPv6 need at least 4 bytes. Their ports are null.
   * A transport header shorter than its minimum is rejected as
     `TRUNCATED_TRANSPORT_HEADER`. One that is present but undecodable is
     rejected as `MALFORMED_TRANSPORT_HEADER`.
5. Other IP protocols (IGMP, GRE, IPv6-in-IPv6, …) are rejected as
   `UNSUPPORTED_IP_PROTOCOL`, with the protocol number counted. With
   `--emit-other-protocols` they become flows with `protocol = OTHER` and null
   ports. Their real protocol number is kept in the flow key and in provenance,
   so different protocols are never merged.
6. Checksums are not verified, because capture offloading commonly invalidates them.

## 5. Flow identification and aggregation policy

* **Unidirectional** flows, as the Test Data document recommends for the first
  implementation.
* **Key**: `(src_ip, src_port, dst_ip, dst_port, IP protocol number)`. Ports are
  `None` where they don't apply. A→B and B→A are always different flows.
* **Start**: the first packet observed for a key.
* **Close**, in this order of evaluation when a packet arrives:
  * `IDLE_TIMEOUT`: the gap since the flow's last packet exceeds the idle timeout.
  * `ACTIVE_TIMEOUT`: the time since the flow's first packet exceeds the active
    timeout. A new flow is started and linked through `previous_flow_id`.
  * Idle flows are also expired by a sweep once per second of capture time, to
    bound memory.
  * `END_OF_CAPTURE`: flows still open at the end of the file.
  * `FLOW_TABLE_LIMIT`: when the table would exceed `max_active_flows`, the
    least recently updated flow is closed.
* TCP FIN/RST do **not** close flows. This is a documented decision that follows
  the specification's "timeout or capture boundary" rule.
* **Counters**: `packets` is the number of attributed packets. `bytes` is the sum
  of per-packet bytes (§7). `start_time` is the minimum timestamp. Duration is the
  maximum minus the minimum timestamp, at µs precision. `tcp_flags` is the
  bitwise OR of all observed flags. It is null for non-TCP flows, and for TCP
  flows without decodable flags.
* **Out-of-order timestamps** are handled: first = min, last = max, and they are
  counted per flow and per capture.
* **Incomplete observations**: `provenance.jsonl` lists `incomplete_reasons`:
  * `OPEN_AT_CAPTURE_END`
  * `CAPTURE_TRUNCATED_OR_CORRUPTED`
  * `TCP_START_NOT_OBSERVED` (the first packet has no SYN)
  * `SPLIT_BY_ACTIVE_TIMEOUT`
  * `CONTINUATION_AFTER_ACTIVE_TIMEOUT`
  * `EVICTED_FLOW_TABLE_LIMIT`
  * `SNAPLEN_TRUNCATED_PACKETS`

  `observed_portion_only = true` means that the counters describe only what was
  seen, not necessarily the whole connection.
* Flows are written when they close: in closure order during the capture, then
  in first-packet order at the end of the capture.

## 6. Flow timeout configuration

| Parameter | Default | Rationale |
|---|---|---|
| Idle timeout | **60 s** | Keeps request/response exchanges and keep-alives together without merging unrelated reuse of a 5-tuple minutes later |
| Active timeout | **1800 s** | Same as the common NetFlow/IPFIX active-timeout default. Long sessions are split into linked records |
| Flow table limit | **1,000,000** | Memory bound (about a few hundred bytes per active flow) |

Set the values with `--idle-timeout`, `--active-timeout` and `--max-active-flows`,
or with `NETGUARD_INGEST_*` environment variables. The values used are recorded
in `report.json` (`config`, `flow_table`) and in each provenance line (`timeouts_s`).

## 7. Byte-counting convention

`bytes` counts the **IP layer as captured**: from the first byte of the IPv4/IPv6
header to the end of the IP packet. That includes the network header,
extension headers, transport header and payload. For each packet the count is
`min(IP declared length, bytes captured from the IP header onwards)`.

* Link-layer headers (Ethernet, VLAN, SLL, …) and Ethernet padding, FCS and
  trailers are excluded, so the figures are comparable across link types.
* Snaplen-truncated packets contribute only the captured bytes. They are counted
  in `snaplen_truncated` and in provenance.
* Prepared datasets must use the same convention. Validation enforces the
  minimum this implies, `bytes ≥ packets × 20` (IPv4) or `× 40` (IPv6).

## 8. Normalisation rules

| Field | Rule |
|---|---|
| Timestamps | Stored as RFC 3339 UTC with fixed microsecond precision (`2010-01-07T19:38:34.341715Z`). Capture timestamps are integer ns since the epoch (UTC by format definition), truncated to µs. Datasets: an explicit offset is converted to UTC; a **naive timestamp is rejected** unless `--assume-timezone` or the profile's `timezone` names a zone; epoch formats only when declared; times before 1970 are rejected; sub-µs digits are truncated |
| IP addresses | IPv4 dotted quad, IPv6 RFC 5952 compressed lower-case (Python `ipaddress`). IPv4-mapped IPv6 is always written `::ffff:a.b.c.d` (RFC 5952 §5), independent of the Python version. Invalid text, leading-zero octets, zone indexes, and mixed IPv4/IPv6 within a flow are rejected |
| Ports | Integers 0–65535 (JSON integer or digit string). `null` = unavailable or not applicable. Floats such as `80.0`, booleans and out-of-range values are rejected. Must be null for ICMP/ICMPv6/OTHER |
| Protocol | `TCP`, `UDP`, `ICMP`, `ICMPV6` (names case-insensitive, or IANA numbers 6/17/1/58). Other valid numbers: `UNSUPPORTED_PROTOCOL`, or `OTHER` when enabled. Unknown text: `INVALID_PROTOCOL` |
| Counters | Non-negative integers with no lossy coercion (`"15"` is accepted; `15.0`, `"1.5"` and `true` are rejected). `packets ≥ 1`, `bytes ≥ packets × min IP header` |
| Duration | Finite, ≥ 0, converted to ms with 3 decimals (µs). A single-packet flow must have duration 0 |
| TCP flags | Integer 0–255. `null` = unavailable (never read as 0). Rejected for non-TCP flows |
| Scenario label | `null` unless the source provides it (dataset column, or operator `--scenario-label` for a whole capture). Must be one of the FlowEvent enum values, optionally through a profile `value_map`. Never fabricated |
| Missing vs zero | Missing CSV cells, profile null tokens and JSON `null` become `None`. `0` stays `0`. A missing required value gives `MISSING_REQUIRED_FIELD` |

## 9. Validation rules (in order)

1. **File**: it exists, is a regular file, is readable and is non-empty. Its
   format is detected from the magic number or extension, and its header is
   validated.
2. **Structure**: record/block lengths, trailers, interface references, timestamp
   ranges, and `caplen ≤ original length`.
3. **Packet**: link, network and transport checks (§4).
4. **Record**: CSV column count, JSON syntax and type, UTF-8 encoding per line,
   required columns or keys, and duplicate `flow_id` within a dataset.
5. **Values**: §8.
6. **Cross-field** (`validation.validate_flow`, the same for every source):
   * same IP version on both sides
   * ports only for TCP/UDP
   * flags only for TCP
   * at least one packet
   * minimum byte consistency
   * single-packet flows have zero duration
   * a timezone-aware start time
   * a valid label
7. **Contract**: Draft 2020-12 JSON Schema check, with format assertions, against
   `contracts/kafka/flow-event.v1.schema.json`, plus the semantic rule that
   non-TCP flows have null `tcp_flags` (as in `examples/kafka/common.py`).
   Disable it with `--no-contract-validation`. Step 6 still applies when it is
   disabled.
8. **Synthetic data guard**: dataset records with `source_type = SIMULATOR` or a
   `simulation_run_id` are rejected (`SYNTHETIC_RECORD_REJECTED`), so simulated
   records are never mixed with imported data.

## 10. Error handling

* Every problem has a stable `ErrorCode` and a category (`FILE`,
  `CAPTURE_STRUCTURE`, `MALFORMED`, `UNSUPPORTED`, `VALIDATION`, `CONTRACT`) — see `errors.py`.
* **File-level errors** end the ingestion with status `FAILED`. A `report.json`
  is still written, with `error` and `data_imported = false`.
* **Packet, record and flow errors** reject only the affected item. It is written
  to `rejects.jsonl` with its location and processing continues:
  * PCAP: packet index, file offset, timestamp, interface, caplen and wirelen.
  * Datasets: record number, line number and the raw record.
  * Flows: flow id.
* **Framing loss** (a truncated or corrupted record header) stops reading, because
  the next record cannot be located safely. Flows observed so far are emitted and
  flagged. The report shows `capture.complete = false` and a warning.
* Status is `COMPLETED` when nothing was rejected, otherwise
  `COMPLETED_WITH_REJECTIONS`. Non-IP and unsupported-protocol packets count as
  rejections (category `UNSUPPORTED`), so nothing is ignored silently.
* Rejection details are capped (`--max-reject-details`, default 100,000). All
  rejections are always counted (`details_suppressed`).
* Unexpected exceptions are logged with their traceback and give `FAILED` /
  `INTERNAL_ERROR`. A report is still written.
* Logs go to stderr as text or JSON and carry `ingestion_id` and `source_file`.

## 11. Output flow schema (FlowEvent v1, one JSON object per line)

```json
{"schema_version":1,"event_id":"evt-cd9870b0-…","trace_id":"ing-4ef5252a…","flow_id":"flow-b1296b01-…",
 "ingest_time":"2026-10-30T18:30:18.257026Z","start_time":"2010-01-07T19:38:34.341715Z","duration_ms":132.768,
 "src_ip":"172.16.16.128","src_port":2826,"dst_ip":"212.58.226.142","dst_port":80,"protocol":"TCP",
 "packets":2,"bytes":92,"tcp_flags":18,"source_type":"PCAP","dataset_id":"tcp_handshake-681bcc3526ad",
 "simulation_run_id":null,"scenario_label":null}
```

(This is a real output line from `tests/data/pcap/tcp_handshake.pcapng`.)

Identifiers:
* `flow_id` = `flow-` + UUIDv5(file SHA-256, first packet index, key), or for
  datasets UUIDv5(file SHA-256, record number). It is deterministic.
* `event_id` = UUIDv5(`flow_id`). It is deterministic, so consumers can
  deduplicate re-imports.
* `trace_id` = `ingestion_id` (`ing-<uuid4>`). It links the flow to its
  `report.json`, provenance and logs.
* `ingest_time` = the ingestion start time.
* `features` is never emitted, because that is downstream work.

## 12. Integration interfaces

* **Input**: file paths given to the CLI or to `ingest_pcap()` / `ingest_flow_dataset()`.
* **Output (designated interface)**: `flows.jsonl`. Each line is a FlowEvent v1
  message for topic `flows.normalized`. It is validated against the shared schema
  in `contracts/kafka/`, and also, in the tests, with the repository's existing
  helper `examples/kafka/common.validate`. Publishing to Kafka is outside this
  module, which writes JSON-lines only. Persistence belongs to the backend
  tier, so no database is used.
* **Traceability**: `trace_id` and `flow_id` lead to `provenance.jsonl`, and from
  there to the packet index and file offset (PCAP) or the record and line number
  (dataset). Together with `report.json` (SHA-256, file and configuration) this
  makes a flow traceable to its exact origin.

## 13. Performance and resources

* Streaming throughout: one packet record or dataset line in memory at a time.
  SHA-256 is computed in 1 MiB chunks.
* The flow table is an `OrderedDict` with O(1) updates, a periodic idle sweep
  and a hard limit.
* Addresses are converted once and cached (up to 65,536 entries).
* Files are closed by context managers. Output appears atomically.
* Measured on `synscan.pcapng` (2,011 packets, 2,002 flows; container CPU):
  * about **5,500 flows/s** with the per-flow JSON Schema check
  * about **19,000 flows/s** with `--no-contract-validation`

  The JSON Schema check (about 130 µs per flow in `jsonschema`) is the dominant cost.

## 14. Known limitations

* No IP reassembly: non-first fragments are rejected and counted, so flows that
  carry fragmented datagrams undercount packets and bytes.
* Tunnels and encapsulations (GRE, IP-in-IP, VXLAN, PPPoE) are not decapsulated.
  The outer header is used, or the packet is rejected.
* TCP connection semantics (FIN/RST, port reuse inside the idle timeout) do not
  split flows.
* Kafka publishing is not part of this module (JSON-lines output only).
* Only the `netguard-native` profile is built in. Other public dataset schemas
  need a custom mapping profile. Bidirectional dataset records (for example
  CICFlowMeter) cannot be mapped to unidirectional flows by a profile alone.
* Several link types and formats have never been run on a genuine capture:
  SLL, SLL2, NULL/LOOP, raw IP files, VLAN, MPLS, big-endian files,
  nanosecond-resolution pcap and pcapng Packet/Simple Packet blocks. They are
  implemented following the format specifications, but none of the downloaded
  captures contains them (see IMPLEMENTATION_REPORT.md, section 9).
* NFR01 (5,000 flows/s for 5 minutes) has not been load-tested, because no large
  genuine capture was available.
