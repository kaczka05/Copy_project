# NetGuard — Kafka Integration Guide

**Audience:** NetGuard developers (data ingestion, detection, backend, frontend) and DevOps.  
**Status:** Proposed integration conventions for the local laboratory environment; team approval required for message contracts, keys, and processing semantics.  
**Applies to:** Existing single-node Apache Kafka 3.9.1 Docker Compose setup; two topics and v1 JSON Schemas.

> **Start here:** This guide answers *how to connect a module to Kafka*. For the meaning of each JSON field, see [`contracts/kafka/README.md`](../contracts/kafka/README.md). For ready-to-run Python clients, see [`examples/kafka/README.md`](../examples/kafka/README.md). You do not need to understand Kafka internals to run the examples.

## 1. What Kafka does in NetGuard

Kafka transports events between independently developed modules. An event is a JSON object (serialized as UTF-8 bytes). A **producer** publishes an event to a **topic**; a **consumer** reads it. Consumers in the **same consumer group** share partitions (work is divided), whereas consumers in **different groups** each receive their own copy of the stream. Kafka is **not** the database used to serve the dashboard.

```text
PCAP importer ─┐
               ├─> Flow extraction / normalization ─> Kafka: flows.normalized
Simulator ─────┘                                         │
                                                        ├─> Analysis worker 1 ─┐
                                                        │   Analysis worker 2 ─┴─> Kafka: detections.created
                                                        │                              │
                                                        └─> Flow persistence            └─> Backend: classification + persistence
                                                                                                  │
                                                                                             Database
                                                                                                  │
                                                                                             REST API
                                                                                                  │
                                                                                              Frontend
```

The two analysis workers use **one** consumer group. Flow persistence uses **another** group. The frontend **must call the backend API**, not connect directly to Kafka. The diagram does not prescribe a programming language or application framework.

## 2. Repository locations — which file should I open?

All paths in this guide are relative to the **repository root** (the directory with `compose.yaml`).

| Path | Purpose | Who uses it? |
| --- | --- | --- |
| `compose.yaml` | Root entry point for local infrastructure, extendable with application services. | Everyone / DevOps |
| `infrastructure/kafka/compose.yaml` | Kafka broker, listeners, storage, health check, topic initialization service. | DevOps |
| `infrastructure/kafka/init-topics.sh` | Creates/checks the two agreed topics on startup. | DevOps |
| `infrastructure/kafka/smoke-test.sh` | Sends/receives a test message using an isolated temporary topic. | Everyone |
| `contracts/kafka/flow-event.v1.schema.json` | Machine-readable validation rules for one normalized network flow. | Flow producer, analysis, flow persistence |
| `contracts/kafka/detection-event.v1.schema.json` | Machine-readable validation rules for one detection candidate. | Analysis producer, backend consumer |
| `contracts/kafka/examples/flow.valid.json` | Valid sample flow payload used for tests/demo. | Flow and analysis developers |
| `contracts/kafka/examples/flow.invalid.json` | **Intentionally invalid** sample: the validator must reject it. | Everyone testing validation |
| `contracts/kafka/examples/detection.valid.json` | Valid sample detection candidate. | Analysis and backend developers |
| `contracts/kafka/validate.py` | Validates example or user-supplied JSON *without using Kafka*. | Everyone |
| `contracts/kafka/requirements-dev.txt` | Dependencies for the standalone schema validator. | Everyone |
| `examples/kafka/producer.py` | Reference client: validates, publishes **one** JSON message, waits for delivery acknowledgement. | Producers |
| `examples/kafka/consumer.py` | Reference client: reads, validates, prints, and commits one or more messages. | Consumers |
| `examples/kafka/common.py` | Shared schema loading, semantic validation, Kafka keys, and ground-truth filtering. | Python client developers |
| `examples/kafka/requirements.txt` | Python packages for the sample Kafka clients. | Everyone testing examples |
| `tests/test_kafka_example_contracts.py` | Unit tests for schema and example-client helper behavior. | Everyone / CI |
| `docs/kafka-integration.md` | **This guide**: setup, connect, run, debug, and hand off. | Everyone |

**Important distinction:** a JSON Schema is a *rule book*, a JSON example is *sample data*, and `validate.py` is a *tool that checks the data against the rule book*. None of those files starts the broker or sends messages on its own.

## 3. Topics and ownership

| Topic | Content | Publisher | Reader(s) | Default key |
| --- | --- | --- | --- | --- |
| `flows.normalized` | `FlowEvent` v1 (one normalized unidirectional flow) | Flow processor | Analysis workers; flow persistence | `src_ip` (proposed) |
| `detections.created` | `DetectionEvent` v1 (a detection *candidate*) | Analysis workers | Backend classification/persistence | `detection_id` (proposed) |

Current development topic settings:

| Topic | Partitions | Retention | Replication factor |
| --- | ---: | --- | ---: |
| `flows.normalized` | 6 | 24 hours | 1 |
| `detections.created` | 3 | 7 days | 1 |

**Partition** means a slice of a topic. Events with the same Kafka key are typically assigned to the same partition, preserving their relative order *within that partition*. Kafka does not guarantee a total order across partitions. Six partitions do not automatically mean six actively utilized workers. This configuration is for local testing, **not a highly available cluster**.

### Consumer group rule

| Process | Topic read | Suggested `group.id` |
| --- | --- | --- |
| Analysis instance A | `flows.normalized` | `netguard-analysis` |
| Analysis instance B | `flows.normalized` | `netguard-analysis` (**same group**) |
| Backend flow writer | `flows.normalized` | `netguard-flow-persistence` |
| Backend detection writer | `detections.created` | `netguard-detection-persistence` |
| Ad hoc tutorial consumer | Either | **Random/new demo group** (default in sample script) |

**Never use the service's real group ID for a tutorial consumer.** It could take partitions away from the running service, and its commits could advance the service's offsets. The sample consumer generates a unique group if `--group-id` is omitted.

## 4. Local prerequisites and connection addresses

- Docker Engine + Docker Compose plugin.
- Python 3.10+ if you want to run the reference clients.
- Commands in the following sections are run **from the repository root**.
- Use only prepared/labeled PCAP/flow datasets and safe synthetic laboratory events. No production capture or real-world attacks.

| Where your application runs | Bootstrap servers |
| --- | --- |
| Native Python/Java service on the same Linux/Windows host | `localhost:9094` |
| Container joined to the root Compose `netguard` network | `kafka:9092` |

Example env variable: `KAFKA_BOOTSTRAP_SERVERS=localhost:9094` for a host process, or `KAFKA_BOOTSTRAP_SERVERS=kafka:9092` for a Compose service. **Do not use `localhost:9094` inside an app container**: `localhost` there points to that app container. **Do not use `kafka:9092` from your host shell** unless you have configured name resolution/networking separately.

The external listener is bound to `127.0.0.1` and advertised as `localhost` by the supplied Compose file. This is intentional for a single-machine lab; it is **not** configured for direct connections from teammates' remote machines.

## 5. First start: verify the infrastructure

```bash
# 1) Start the broker and its one-time topic initializer
docker compose up -d

# 2) Inspect services: kafka should be healthy; kafka-init may exit with code 0
docker compose ps -a

# 3) List the two topics
docker compose exec kafka /opt/kafka/bin/kafka-topics.sh \
  --bootstrap-server kafka:9092 --list

# 4) Verify the broker can actually send/receive (temporary topic)
bash infrastructure/kafka/smoke-test.sh
```

Expected: `flows.normalized`, `detections.created`, and `Smoke test PASSED: ...`. `kafka-init` reporting `Exited (0)` is normal. `Aborting on container exit...` can be printed by the script's one-shot Compose invocation without implying broker failure. Kafka may warn about topics containing periods and underscores; the current topic names use periods only, so they can remain unchanged.

**Smoke test ≠ application end-to-end test.** It proves the broker can produce/consume, not that NetGuard detects an anomaly.

## 6. Validate JSON before publishing

```bash
python3 -m venv .venv
source .venv/bin/activate       # Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -r contracts/kafka/requirements-dev.txt
python contracts/kafka/validate.py
```

The default validation run checks repository samples, including successful **rejection** of the intentionally invalid flow. Validate your own file:

```bash
python contracts/kafka/validate.py \
  --topic flows.normalized --file /path/to/my-flow.json
```

The contract requires `schema_version: 1`. The file name `.v1.schema.json` identifies the matching schema. Validation catches missing fields, wrong types, invalid IPs/timestamps and other schema rules. Some **semantic rules** (e.g., exact time-window duration, non-TCP `tcp_flags`) are checked by `examples/kafka/common.py` when using the demo clients. Every real module must use equivalent business-level validation, even if implemented in Java, Python, or another language.

## 7. Send and receive a real Kafka message — reproducible demo

Install example dependencies (the requirements include the Python Kafka client and validation package):

```bash
python -m pip install -r examples/kafka/requirements.txt
```

**Terminal A — start a tutorial consumer** (starts reading existing retained events if any; it uses a unique group by default):

```bash
python examples/kafka/consumer.py \
  --topic flows.normalized --max-messages 1 --timeout 30
```

**Terminal B — publish an example:**

```bash
python examples/kafka/producer.py --topic flows.normalized
```

Expected producer output starts with `DELIVERED topic=flows.normalized`; consumer output starts with `RECEIVED topic=flows.normalized`. Partition and offset values can vary. If the consumer's unique group reads an older retained message first, that's normal for `auto.offset.reset=earliest`; for an exact sample match, use an otherwise empty test topic/environment or correlate with `event_id`.

Repeat the same process for the detection topic:

```bash
# Terminal A
python examples/kafka/consumer.py --topic detections.created --max-messages 1 --timeout 30

# Terminal B
python examples/kafka/producer.py --topic detections.created
```

Publish a custom valid payload:

```bash
python examples/kafka/producer.py \
  --topic flows.normalized \
  --file contracts/kafka/examples/flow.valid.json
```

Check that invalid data never reaches Kafka through the reference producer:

```bash
python examples/kafka/producer.py \
  --topic flows.normalized \
  --file contracts/kafka/examples/flow.invalid.json
```

This **should fail** with a validation error; that is the expected result. A sample script's `DELIVERED` means broker acknowledgement, *not* that a detector or database processed the record.

### Example using an application container

A future Python analysis service can be added to the **root** `compose.yaml` (example only; the image/build and command must match your actual module):

```yaml
services:
  analysis:
    build: ./modules/analysis
    environment:
      KAFKA_BOOTSTRAP_SERVERS: kafka:9092
      KAFKA_INPUT_TOPIC: flows.normalized
      KAFKA_OUTPUT_TOPIC: detections.created
      KAFKA_GROUP_ID: netguard-analysis
    depends_on:
      kafka:
        condition: service_healthy
    networks:
      - netguard
```

`netguard` is a named network defined in the included Kafka Compose file; make sure the complete Compose model is valid after adding services (`docker compose config`). **Environment variable names apart from `KAFKA_BOOTSTRAP_SERVERS` are proposed conventions**; the current demo scripts accept `--topic` and `--group-id` CLI options rather than reading every variable listed above. Implement those variables in your actual module if you adopt them.

## 8. Instructions by module owner

### PCAP importer + traffic simulator (input team)

Produce **laboratory** data only. The importer validates PCAP/flow inputs; the simulator generates synthetic flows. Both must converge on the *same* normalized flow model. You can implement flow extraction inside your assigned component; the agreed publisher to `flows.normalized` is the Flow Processor.

### Flow Processor (publishes `flows.normalized`)

1. Normalize to a **unidirectional** flow with fields required by `flow-event.v1.schema.json`.
2. Set a stable `flow_id`, unique emission `event_id`, and correlation `trace_id`. Carry dataset/run provenance when present.
3. Assign `schema_version=1`; validate before send. Use UTF-8 JSON.
4. Produce to `flows.normalized`; proposed Kafka key is `src_ip`.
5. Wait for delivery acknowledgement; log topic/partition/offset and correlation IDs, avoiding secrets and sensitive contents.
6. Set timestamp fields consistently, preferably RFC 3339 UTC; agree on byte-counting and flow timeout conventions.

### Analysis workers (consume flows; publish detections)

1. Both instances subscribe to `flows.normalized` with `group.id=netguard-analysis`.
2. Validate input; **remove `scenario_label` before any decision logic** (see `prepare_flow_for_detection` in the sample).
3. Aggregate the mandated **1 s, 10 s and 60 s** windows and run deterministic rules plus a statistical/ML method.
4. Use configured grouping and late-event policies. **Proposed key `src_ip` does not by itself support complete destination-grouped DoS analysis.** Document repartitioning/state-sharing strategy before claiming full detection coverage.
5. Publish a validated `DetectionEvent` to `detections.created`, key `detection_id`, preserving traceability and `related_flow_ids`.
6. Only commit consumed offsets after the required processing/output step succeeds; implement a recovery strategy for failures between output publication and commit.

### Backend (two independent Kafka roles + REST API)

- Flow persistence consumer (`group.id=netguard-flow-persistence`) reads `flows.normalized` and stores normalized flow history.
- Detection consumer (`group.id=netguard-detection-persistence`) reads `detections.created`, performs **final classification/severity assignment**, stores evidence and all mandatory alert fields, and exposes them through REST endpoints.
- A `DetectionEvent` is a candidate, **not** a guaranteed final alert. Its `confidence` is required; its `severity` may be omitted or preliminary.
- Use idempotent writes keyed by stable IDs; database success must precede offset commit. Details of transaction/retry behavior require agreement.

### Frontend

Call the backend REST API for current traffic, alerts, history and filters. The frontend does **not** require Kafka credentials, consumer group, or topic subscription. Do not claim records are live when the backend reports delayed/stale data.

### DevOps / infrastructure

Maintain Compose, broker/topic initialization, contracts, CI validation, isolated test fixtures, broker/consumer diagnostics, and repeatable integration/performance tests. Keep the default broker local-only (PLAINTEXT for lab use); do not expose Kafka publicly.

## 9. Message lifecycle, IDs, and responsibility boundaries

| Field | Meaning | Owner / guidance |
| --- | --- | --- |
| `schema_version` | Contract revision (v1 = integer 1). | All producers |
| `event_id` | Identifier of a published event. | Producer; stable for replay/retry of same logical event |
| `flow_id` | Normalized flow identity. | Flow Processor |
| `trace_id` | Joins logs/events across modules. | Originating ingestion path; propagate unchanged |
| `detection_id` | Identity of an anomaly detection. | Analysis worker; stable across retry |
| `related_flow_ids` | Flow evidence for a detection. | Analysis worker |
| `scenario_label` | **Ground-truth label**, not an input feature. | Dataset/simulator evaluation tooling only |

`FlowEvent` fields include source/destination IP and ports, protocol, timestamps, duration, packet/byte counts, optional TCP flags, and provenance. `DetectionEvent` includes detection type, method (`RULE` / `STATISTICAL` / `ML`), confidence (0–1), window, feature values, explanation and related flow IDs. See the canonical JSON Schemas for the **exact required/optional field list**; this prose is not an alternative contract.

**Key behavioral rules:**

- `tcp_flags` must be null or absent for non-TCP flows; absent values must not be confused with zero.
- Time-window `duration_seconds` must be one of `1`, `10`, or `60`; application validation must also check `end - start = duration_seconds` and chronological consistency.
- Keep correlation and timing metadata in all stages. Benchmark latency is measured from **data acceptance to detection creation**, not UI rendering.
- Retention is finite and Kafka is not the long-term source of truth; backend persists required history.

## 10. Handling errors and restarts

**Delivery semantics:** Assume *at least once*, not exactly once. Producer idempotence and `acks=all` reduce certain duplicate send risks; they **do not** eliminate duplicate downstream processing, and replication factor 1 has no broker-node fault tolerance.

- **Producer:** validate first; retry transient connection errors with bounded backoff; report/track permanent failures. Preserve logical IDs when retrying the same event.
- **Consumer:** validate message; perform business logic; commit offset **only after success**. The Python example prints a message and commits; a real backend must finish its durable write before committing.
- **Bad input:** do not silently discard or endlessly crash on one poison pill. Team must define retry limit, quarantine/DLQ policy and operator visibility. No DLQ topic is configured in the starter.
- **Late/out-of-order flows:** decide event-time versus processing-time, allowed lateness and window finalization. JSON Schema cannot determine window correctness for your algorithm.
- **Restart:** other instances in the same analysis group may take over assigned partitions after rebalance. Verify processing continuity, replay behavior and deduplicated persisted results.

## 11. Troubleshooting and observability

| Symptom | Typical cause | What to check |
| --- | --- | --- |
| `Connection refused` from host | Broker stopped or wrong address | `docker compose ps -a`; use `localhost:9094` |
| `Name or service not known: kafka` from host | Container-only DNS name used on host | Switch to `localhost:9094` |
| Container cannot connect to `localhost:9094` | Loopback points to itself | Use `kafka:9092`; ensure service is on `netguard` network |
| `UNKNOWN_TOPIC_OR_PART` | Topic missing/misspelled | Run initializer; list topics; auto-create is off |
| Consumer receives nothing | New consumer group/offset position, wrong topic, partitions owned by another group member | Group info; topic; offsets; use dedicated group |
| Consumer receives an older example | Unique group starts from `earliest` | Compare `event_id`; know retention/offset settings |
| Validation error | Payload doesn't match v1 contract / semantic rule | Run validator; inspect schema and sample JSON |
| Duplicate alerts after restart | At-least-once delivery and non-idempotent writes | Stable IDs, transaction boundaries, deduplication |
| Throughput/latency degrades | High consumer lag, CPU pressure, network/storage bottleneck | Group lag, resource usage, timestamps, logs |

Useful commands (repository root):

```bash
docker compose ps -a
docker compose logs --tail=100 kafka
docker compose logs kafka-init

docker compose exec kafka /opt/kafka/bin/kafka-topics.sh \
  --bootstrap-server kafka:9092 --describe --topic flows.normalized

docker compose exec kafka /opt/kafka/bin/kafka-consumer-groups.sh \
  --bootstrap-server kafka:9092 --list

docker compose exec kafka /opt/kafka/bin/kafka-consumer-groups.sh \
  --bootstrap-server kafka:9092 --all-groups --describe

docker compose config
```

Consumer lag is meaningful only for groups that have committed offsets; a brand-new or idle group may not appear as expected. Logs should include `trace_id`, `event_id`, `flow_id`/`detection_id`, topic, partition, offset, processing stage and clear error context. Do not log credentials or production traffic. Optional Kafka UI can help developers, but is **not** part of the current starter.

## 12. Test plan: what we have and what remains

| Check | How to run / observe | Scope |
| --- | --- | --- |
| Broker ready | `docker compose ps -a` | Infrastructure health |
| Topics initialized | `kafka-topics.sh --list` | Topic existence |
| Broker send/receive | `bash infrastructure/kafka/smoke-test.sh` | Temporary topic transport |
| Schema samples | `python contracts/kafka/validate.py` | JSON contracts only |
| Python client helpers | `python -m pytest tests/test_kafka_example_contracts.py -v` | Unit tests (install `pytest`) |
| Real sample through Kafka | Producer and consumer commands in §7 | One event on each application topic |
| End-to-end application flow | Import/simulator → analysis → backend → API/UI | **Not implemented by reference clients** |
| Resilience | Two analysis instances; restart one during flow replay | Must be implemented/evaluated |
| Performance | 5,000 normalized flows/s for 300 s; p95 detection creation ≤3 s | Must be measured on fixed hardware/configuration |

**Integration readiness checklist:**

- [ ] Both schemas reviewed/approved; both topic names frozen for v1.
- [ ] Each module uses correct bootstrap address and topic.
- [ ] Two analysis workers use one consumer group; independent persistence uses different group(s).
- [ ] Producer validates before publishing; consumer validates before processing.
- [ ] Example event can be traced with stable IDs from producer to persistence.
- [ ] Ground truth never influences detector outputs.
- [ ] Lateness, grouping, deduplication and offset-commit policies documented.
- [ ] Errors and restarts tested with lab fixtures.
- [ ] CI validates contracts and tests; final throughput/latency evidence captured separately.

## 13. Open decisions before production-quality integration

These are **team decisions**, not claims that NetGuard has already implemented them:

1. Partition/grouping strategy for per-source scans **and** per-destination floods across parallel workers.
2. Event-time versus processing-time windows; handling of late/out-of-order flows and window closure.
3. Byte counting, flow timeout, and connection-counting definitions.
4. Retries, DLQ/quarantine, invalid message handling, and offset commits when output or DB writes fail.
5. Final severity mapping, detection deduplication identity, and evidence/history retention.
6. Schema evolution procedure (new `.v2.schema.json` and `schema_version=2`; coordinated rollout because v1 uses `additionalProperties: false`).
7. Local benchmark hardware, observability metrics, evaluation datasets and performance acceptance records.

## 14. Security and project boundaries

NetGuard is a **defensive laboratory project**. Use only synthetic traffic and authorized prepared PCAP/flow datasets. Never point the simulator or tests at third-party networks, and never run real attacks. The starter Kafka broker uses unauthenticated `PLAINTEXT`, a single replica, and a host port bound to loopback; keep it on trusted developer machines. Authentication/authorization and API abuse protection are required at the **backend REST API** boundary and are not supplied by Kafka's lab configuration.

---

**Document ownership:** DevOps maintains connection settings, Compose, broker testing and this guide. The flow, detection and backend owners jointly approve payload fields and processing semantics. Update this file in the same pull request whenever topic names, group IDs, contracts or example commands change.
