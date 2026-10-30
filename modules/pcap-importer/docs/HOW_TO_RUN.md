# HOW TO RUN — NetGuard PCAP/flow ingestion

All commands are run from `modules/pcap-importer/` unless stated otherwise.
No Docker, Kafka, database or network access is needed to ingest files.

## 1. Requirements

* Python **3.10+** (developed and tested with 3.11.18)
* `pip`
* Runtime libraries: `dpkt==1.9.8`, `jsonschema[format]` (4.26.0 tested) — the
  `[format]` extra is mandatory: it enables the `date-time`/`ipv4`/`ipv6` checks of
  the FlowEvent contract; the tool refuses to run without them.
* The repository's `contracts/kafka/flow-event.v1.schema.json` (found automatically
  inside the monorepo; elsewhere set `NETGUARD_INGEST_CONTRACTS_DIR`).

## 2. Install

```bash
cd modules/pcap-importer
python3 -m venv .venv
source .venv/bin/activate              # Windows: .venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.txt     # runtime + pytest
# optional: install the `netguard-ingest` console command
python -m pip install -e .
```

Without installation use `python -m netguard_ingest ...` from this directory.

## 3. Import PCAP / PCAPNG captures

```bash
# one file
python -m netguard_ingest pcap tests/data/pcap/telnet-raw.pcap --output-dir ./ingestion-output

# several files, or a whole directory (*.pcap, *.pcapng, *.cap; one ingestion per file)
python -m netguard_ingest pcap tests/data/pcap --output-dir ./ingestion-output

# flow timeouts (seconds), flow-table limit, dataset id and a documented ground-truth label
python -m netguard_ingest pcap my_capture.pcapng --output-dir ./out \
    --idle-timeout 60 --active-timeout 1800 --max-active-flows 1000000 \
    --dataset-id lab-2026-10-scan --scenario-label PORT_SCAN
```

`--scenario-label` applies one label to **every** flow of the capture. Use it
only when the dataset's documentation states the ground truth for the whole
capture. The default is `null`, and the tool never guesses a label.

Example console output:

```text
[COMPLETED_WITH_REJECTIONS] ipv4frags.pcap -> ingestion-output/ing-3fb6...
  2 normalised flows imported.
  packets: examined=3 in_flows=2 rejected=1
  flows: extracted=2 normalized=2 rejected=0
  rejections: IP_FRAGMENT_NOT_REASSEMBLED=1
```

## 4. Import a prepared flow dataset (NetGuard-native CSV / JSON-lines)

```bash
python -m netguard_ingest flows my_flows.csv   --output-dir ./out
python -m netguard_ingest flows my_flows.jsonl --output-dir ./out
# format override, explicit timezone for timestamps without offset, custom mapping profile
python -m netguard_ingest flows export.txt --format csv --assume-timezone UTC --mapping ./my-profile.json
```

Required columns/keys (NetGuard-native): `start_time` (RFC 3339 with offset),
`duration_ms`, `src_ip`, `src_port`, `dst_ip`, `dst_port`, `protocol`, `packets`,
`bytes`. Optional: `tcp_flags`, `scenario_label`, `flow_id`, `source_type`,
`dataset_id`, `simulation_run_id`. An empty CSV cell or a JSON `null` means
*missing/unavailable* and is never treated as `0`. See DESIGN.md §3 and §7 for the
full rules and the mapping-profile format.

A `flows.jsonl` produced by the PCAP importer is itself a valid NetGuard-native
JSON-lines dataset:
`python -m netguard_ingest flows ingestion-output/<id>/flows.jsonl --output-dir ./out`.

## 5. Inspect results

```bash
python -m netguard_ingest list --output-dir ./ingestion-output         # catalogue of all ingestions
python -m netguard_ingest list --output-dir ./ingestion-output --json
python -m netguard_ingest validate-output ingestion-output/<id>/flows.jsonl   # FlowEvent v1 re-check
```

If nothing has been imported, `list` prints
`No data has been imported (no ingestions recorded in ...)`.

Output of each ingestion: `ingestion-output/<ingestion_id>/`

| File | Content |
|---|---|
| `flows.jsonl` | Normalised flows, one FlowEvent v1 JSON object per line (the integration output) |
| `provenance.jsonl` | One line per flow: source file, SHA-256, first/last packet index or record/line number, end reason, incompleteness reasons |
| `rejects.jsonl` | Every rejected/quarantined packet, record or flow with an error code, category, message and location |
| `report.json` | Ingestion metadata: ids, file, size, SHA-256, format, start/end, duration, status, counters, errors, warnings, configuration |

`ingestion-output/ingestions.jsonl` lists all ingestions. The directory is
written as `.<id>.partial` first and renamed only after it is complete.

## 6. Exit codes

| Code | Meaning |
|---|---|
| 0 | All ingestions completed (possibly with rejections) |
| 1 | At least one ingestion FAILED (file missing, unsupported or corrupted format, ...) |
| 2 | Usage or configuration error (e.g. negative timeout, schema not found) |
| 3 | Something was rejected and `--fail-on-rejections` was given |

## 7. Configuration

CLI options override environment variables, which override the defaults.

| Setting | CLI | Environment variable | Default |
|---|---|---|---|
| Output root | `--output-dir` | `NETGUARD_INGEST_OUTPUT_DIR` | `./ingestion-output` |
| Idle timeout (s) | `--idle-timeout` | `NETGUARD_INGEST_IDLE_TIMEOUT_S` | `60` |
| Active timeout (s) | `--active-timeout` | `NETGUARD_INGEST_ACTIVE_TIMEOUT_S` | `1800` |
| Flow-table limit | `--max-active-flows` | `NETGUARD_INGEST_MAX_ACTIVE_FLOWS` | `1000000` |
| Emit non-TCP/UDP/ICMP protocols as `OTHER` | `--emit-other-protocols` | `NETGUARD_INGEST_EMIT_OTHER_PROTOCOLS` | off (rejected and reported) |
| JSON Schema check per flow | `--no-contract-validation` | `NETGUARD_INGEST_VALIDATE_CONTRACT` | on |
| Contract directory | `--contracts-dir` | `NETGUARD_INGEST_CONTRACTS_DIR` | auto-detected `contracts/kafka` |
| Max reject details written | `--max-reject-details` | `NETGUARD_INGEST_MAX_REJECT_DETAILS` | `100000` (all are still counted) |
| Logging | `--log-level`, `--log-format text\|json` | – | `INFO`, `text` (stderr) |

Put global options before the sub-command:
`python -m netguard_ingest --log-level DEBUG --log-format json pcap ...`.

## 8. Run the tests

```bash
cd modules/pcap-importer
python -m pytest            # 177 tests, about 3 s
python -m pytest -v tests/test_flow_aggregation.py
```

The tests use only the genuine public captures in `tests/data/pcap/`. Their
SHA-256 is checked before use. If a capture is missing, run
`bash scripts/fetch_test_pcaps.sh` to download and verify all of them again.
If a capture is still missing, its tests are **skipped** and nothing is
fabricated in its place.

## 9. Use as a library

```python
from pathlib import Path
from netguard_ingest.config import IngestionConfig
from netguard_ingest.pipeline import ingest_pcap, ingest_flow_dataset

result = ingest_pcap("capture.pcapng", IngestionConfig(output_root=Path("out"), idle_timeout_s=30))
print(result.status, result.output_dir, result.report["flows"])
```

## 10. Handing flows to Kafka (other team members)

As agreed, this subsystem writes JSON-lines only. Each line of `flows.jsonl` is
a complete, schema-validated FlowEvent v1 message. The Flow Processor or DevOps
owner can publish the lines to `flows.normalized`. Use key `src_ip` as proposed,
and keep `event_id` / `flow_id` unchanged so consumers can deduplicate.
