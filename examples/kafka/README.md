# Kafka producer and consumer examples (Python)

This folder contains **demo clients, not implemented NetGuard modules**. The examples use the **existing v1 schemas** in `contracts/kafka/`, so they do not create new topic names or change Docker configuration. Only synthetic/lab input is supported.

## Files

| File | Purpose |
| --- | --- |
| `producer.py` | Loads sample JSON or `--file`, validates it, sends one message, checks broker delivery acknowledgement. |
| `consumer.py` | Reads messages, validates the payload, prints output and commits offsets after processing. |
| `common.py` | Central contract loading, validation, message keys and ground-truth sanitization. |
| `requirements.txt` | Python dependencies for example clients. |

## Prerequisites

- Docker Compose and the existing Kafka broker running, with `flows.normalized` and `detections.created` topics initialized.
- Python 3.10+ on your workstation.
- Execute from the **repository root**. The broker exposed on the host uses `localhost:9094`. Other containers use `kafka:9092`.

Install client dependencies in a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r examples/kafka/requirements.txt
```

On Windows PowerShell, activate with `.venv\\Scripts\\Activate.ps1` instead of `source ...`.

## Flow topic walkthrough

**Terminal A (consumer):**

```bash
python examples/kafka/consumer.py --topic flows.normalized --max-messages 1 --timeout 30
```

**Terminal B (producer):**

```bash
python examples/kafka/producer.py --topic flows.normalized
```

The producer prints `DELIVERED ...` only after Kafka acknowledges the message. The consumer prints `RECEIVED ...` and exits after one record (or after 30 seconds without receiving one). To read only fresh demo records, use a new group and start consuming while publishing: for `earliest`, a brand-new group may first receive older retained records.

## Detection topic walkthrough

**Terminal A:**

```bash
python examples/kafka/consumer.py --topic detections.created --max-messages 1 --timeout 30
```

**Terminal B:**

```bash
python examples/kafka/producer.py --topic detections.created
```

**Custom payload:**

```bash
python examples/kafka/producer.py --topic flows.normalized --file contracts/kafka/examples/flow.valid.json
```

Send the intentionally invalid sample to verify that the producer **rejects it before publishing**:

```bash
python examples/kafka/producer.py --topic flows.normalized --file contracts/kafka/examples/flow.invalid.json
```

The command should fail with a validation error. It should NOT put an invalid record on Kafka.

## Module integrations

| Module | Kafka role | Topic | Group ID suggestion | Key |
| --- | --- | --- | --- | --- |
| Flow processor | Producer | `flows.normalized` | n/a | `src_ip` |
| Analysis workers | Consumers | `flows.normalized` | **shared** `netguard-analysis` | read |
| Flow persistence | Consumer | `flows.normalized` | `netguard-flow-persistence` | read |
| Analysis workers | Producer | `detections.created` | n/a | `detection_id` |
| Backend classification / persistence | Consumer | `detections.created` | `netguard-detection-persistence` | read |

Use `--group-id netguard-analysis` for each analysis worker (both instances share a group). Use a *different group* for flow persistence to receive all flow messages independently. Do not run demo consumers using real service group IDs; they can steal partitions/advance offsets.

The suggested `src_ip` key preserves ordering per source but **does not solve destination-grouped DoS analysis**; agree on aggregation/partitioning before implementation. The consumer removes `scenario_label` before presenting flows to detector code; this example does not implement a detector. Ground truth must never influence detection decisions.

## Delivery and safety limitations

- `enable.idempotence` / `acks=all` are configured on the example producer; this does **not** make database writes or downstream processing exactly-once.
- Consumer offsets are committed **after** processing the record. Re-delivery is possible after a crash; use idempotent persistence keyed on stable identifiers (`event_id`, `detection_id`).
- Invalid received records raise an error **without committing**; real consumers need an explicit retry/backoff and DLQ/quarantine policy.
- Example messages use fixed IDs for easy comparison. Do **not** reuse the same IDs for distinct production events. For replay of the same logical event, stable IDs are useful for deduplication.
- The broker is intentionally single-node, localhost-only, PLAINTEXT without authentication. Use only in local, controlled development.
- These scripts confirm Kafka communication, **not** NetGuard anomaly detection or the 5,000 flows/s performance requirement.

See `contracts/kafka/README.md` for field definitions, schema evolution and validation policy; `docs/kafka-integration.md` for broader architecture.
