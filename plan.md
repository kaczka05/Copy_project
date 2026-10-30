# NetGuard Ingestion Subsystem (Python) — plan

## 1) Objectives
- Build a **Python-only** ingestion subsystem that reads **real PCAP/PCAPNG** and **prepared NetGuard-native flow datasets (CSV/JSONL)**.
- Parse packets and extract **unidirectional flows** (5‑tuple) with configurable **idle/active timeouts**, then **normalise + validate** into **FlowEvent v1** (repo JSON Schema).
- Produce outputs to **JSON-lines file only** (no Kafka publishing) including: accepted flows, rejects/quarantine, provenance, and a summary report.
- Implement robust **error handling + malformed reporting**, and document **policies/limitations/deviations** (incl. broken repo sample and any model changes catalogued).

## 2) Implementation Steps

### Phase 1 — Core POC (prove the hard part works before building the app)
User stories (POC)
1. As a developer, I can run one command on a PCAP and see extracted unidirectional flows printed/serialized.
2. As a developer, I can run the POC on both **pcap** and **pcapng** inputs.
3. As a developer, I can see packet/parse errors counted and the run still completes.
4. As a developer, I can confirm the byte-counting policy matches documented rules.
5. As a developer, I can confirm non-IP/unsupported L2 frames don’t crash ingestion.

Steps
- **Websearch / best practices brief** (1 note in docs): dpkt limitations, pcapng timestamp handling, flow timeout norms, safe byte counting.
- Create minimal POC script `scripts/poc_pcap_to_flows.py`:
  - Read packets via dpkt (pcap + pcapng), handle common link types (Ethernet/VLAN; best-effort for others).
  - Decode IPv4/IPv6 + TCP/UDP/ICMP/ICMPv6 headers.
  - Build unidirectional flow table keyed by `(src_ip,src_port,dst_ip,dst_port,protocol)`.
  - Aggregate `start_time`, `duration_ms`, `packets`, `bytes`, `tcp_flags` OR.
  - Flush flows at end-of-capture; emit to stdout JSONL.
- Run POC against the downloaded genuine captures in `modules/pcap-importer/tests/data/pcap/` and record observed edge cases.
- Stop Phase 1 only when: POC completes for all listed captures, producing valid-looking flow rows without crashes.

### Phase 2 — V1 App Development (build the real ingestion module around proven core)
User stories (V1)
1. As a user, I can ingest a PCAP/PCAPNG into an output directory containing `flows.jsonl` and `report.json`.
2. As a user, I can ingest a NetGuard-native CSV/JSONL flow dataset and get the same FlowEvent outputs.
3. As a user, I can configure flow timeouts and output paths via CLI flags.
4. As a user, I can see which records were rejected and why (machine-readable error codes + human message).
5. As a user, I can reproduce a run using the recorded provenance and dataset catalogue.

Steps
- Create Python package `modules/pcap-importer/netguard_ingest/` with:
  - `model.py`: internal `NormalizedFlow` + helpers.
  - `errors.py`: error codes + structured reject record schema.
  - `contracts.py`: JSON Schema validation against `contracts/kafka/flow-event.v1.schema.json`.
  - `pcap_reader.py`: robust packet iteration for pcap/pcapng; capture timestamp policy.
  - `decoder.py`: L2/L3/L4 parsing; fragment handling policy (reject non-first frags); truncation handling.
  - `flow_agg.py`: timeout logic (idle/active), table size cap/eviction, end-of-capture flush.
  - `dataset_reader.py`: streaming CSV/JSONL ingestion for NetGuard-native columns; strict mapping + type coercion.
  - `normalize.py` + `validate.py`: apply rules from Test Data doc (UTC/RFC3339, ports 0–65535 or null, non-negative counters, tcp_flags null for non-TCP, missing vs 0).
  - `provenance.py`: dataset_id, source_type, ingest_time, trace_id policy, input file hash.
  - `writer.py`: atomic write (temp dir then rename), writes:
    - `flows.jsonl` (FlowEvent v1 compliant)
    - `rejects.jsonl`
    - `provenance.jsonl`
    - `report.json`
- CLI `netguard-ingest` (argparse/typer):
  - `pcap --input <file|dir> --out <dir> [--idle-timeout] [--active-timeout]`
  - `flows --input <csv|jsonl> --out <dir> [--mapping <json>]`
  - `validate-output --flows <flows.jsonl>`
- Documentation set:
  - `modules/pcap-importer/README.md` (overview, constraints, byte-counting, timeouts, fragment policy).
  - `HOW_TO_RUN.md` (exact commands).
  - `SOURCES.md` for downloaded PCAPs (URLs, license/attribution, sha256, date).
  - `MODEL_CHANGES.md` (any deviations from Test Data PDF sample flow/model; keep a changelog).
  - `IMPLEMENTATION_REPORT.md` (libs, policies, files, tests run, datasets, untested cases, limitations).
  - `KNOWN_ISSUES.md` including **broken `contracts/kafka/examples/flow.valid.json`** left as-is.

### Phase 3 — Testing, validation, and hardening
User stories (Testing)
1. As a maintainer, I can run `pytest` and see ingestion works on all bundled genuine PCAPs.
2. As a maintainer, I can verify FlowEvent schema compliance for produced outputs.
3. As a maintainer, I can confirm malformed/truncated packets are rejected with clear codes.
4. As a maintainer, I can confirm prepared-flow CSV/JSONL ingestion enforces required fields/types.
5. As a maintainer, I can read a concise test report listing datasets, cases covered, and gaps.

Steps
- Add pytest suite under `modules/pcap-importer/tests/`:
  - PCAP/PCAPNG happy-path tests using the real downloaded captures.
  - Malformed/rejection tests using **mutated copies** of real packets/frames.
  - Dataset ingestion tests using small NetGuard-native CSV/JSONL fixtures.
  - Contract validation tests using the shared schema.
- Add `TEST_REPORT.md`: cases executed, outputs verified, and explicit “not tested” list.
- Run full test pass + one end-to-end run producing output artefacts in a sample directory.

## 3) Next Actions
1. Implement Phase 1 POC script and run it across all stored PCAPs; log edge cases encountered.
2. Create `SOURCES.md` + hash catalogue for each stored PCAP.
3. Draft policy decisions (byte counting, fragments, truncation, supported link types) and lock them into `README.md`.
4. Scaffold `netguard_ingest/` modules and migrate POC logic into library functions.
5. Add CLI + atomic output writer and produce first FlowEvent v1 compliant `flows.jsonl` on one capture.

## 4) Success Criteria
- `netguard-ingest pcap ...` processes all bundled real PCAP/PCAPNG files without crashing and writes outputs.
- Every emitted flow in `flows.jsonl` validates against `contracts/kafka/flow-event.v1.schema.json`.
- Rejects are captured with stable error codes + input provenance; run summary includes counts.
- Prepared NetGuard-native CSV/JSONL ingestion works with strict validation and mapping.
- Documentation includes **HOW TO RUN**, dataset provenance, test report, and an implementation report listing limitations and deviations (including broken example contract file left unchanged).