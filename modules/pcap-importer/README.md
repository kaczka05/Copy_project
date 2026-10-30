# NetGuard — PCAP/Flow Ingestion, Extraction & Normalisation (`modules/pcap-importer`)

Python subsystem owned by *Member 1 — Network Data & Flow Processing*. It
implements requirements **F01** (import prepared PCAP/flow data and validate
input) and **F02** (convert traffic into a normalised flow model) of the NetGuard
specification, plus the provenance needed for **F15** (trace an event from input
onwards).

It converts **actual** prepared captures (pcap / pcapng) and prepared
NetGuard-native flow datasets (CSV / JSON-lines) into normalised,
**unidirectional** flows serialised as **FlowEvent v1**
(`contracts/kafka/flow-event.v1.schema.json`, topic `flows.normalized`), written
as JSON-lines files.

> It never generates, simulates or fabricates traffic. If no input is given, or
> an input contains nothing convertible, it says so explicitly
> ("No data has been imported").

## Quick start

```bash
cd modules/pcap-importer
python -m pip install -r requirements-dev.txt
python -m netguard_ingest pcap tests/data/pcap/tcp_handshake.pcapng --output-dir ./ingestion-output
python -m netguard_ingest list --output-dir ./ingestion-output
python -m pytest
```

## Documentation

| Document | Content |
|---|---|
| [docs/HOW_TO_RUN.md](docs/HOW_TO_RUN.md) | **How to run**: installation, every command, configuration, outputs, tests |
| [docs/DESIGN.md](docs/DESIGN.md) | Components, formats, parsing, flow policy, timeouts, byte counting, normalisation, validation, errors, output schema, interfaces, limitations |
| [docs/MODEL_CHANGES.md](docs/MODEL_CHANGES.md) | Catalogue of every change made to the sample flow model from *Test Data and Demonstration Environment* |
| [docs/TEST_REPORT.md](docs/TEST_REPORT.md) | Test plan, executed tests and results, untested cases |
| [IMPLEMENTATION_REPORT.md](IMPLEMENTATION_REPORT.md) | Final implementation report (files, libraries, policies, deviations, limitations) |
| [tests/data/pcap/SOURCES.md](tests/data/pcap/SOURCES.md) | Genuine public captures used for testing (URLs, SHA-256) |

## Layout

```text
modules/pcap-importer/
├── netguard_ingest/
│   ├── cli.py              # netguard-ingest pcap | flows | list | validate-output
│   ├── pipeline.py         # PCAP and dataset pipelines, shared emit/validate/report path
│   ├── capture/reader.py   # streaming pcap/pcapng record framing (dpkt header classes)
│   ├── capture/decoder.py  # link/IP/transport decoding with dpkt
│   ├── capture/aggregator.py # unidirectional flow table, timeouts
│   ├── datasets/           # CSV/JSONL readers, mapping profiles (netguard-native built in)
│   ├── normalize.py        # value normalisation rules
│   ├── validation.py       # cross-field flow rules (same for every source)
│   ├── contract.py         # FlowEvent v1 JSON Schema check (repo contract)
│   ├── model.py, errors.py, ids.py, output.py, config.py, logging_setup.py
├── tests/                  # pytest suite + genuine captures in tests/data/pcap
├── scripts/fetch_test_pcaps.sh
└── docs/
```
