# NetGuard monorepo starter — Kafka infrastructure

An **infrastructure-only scaffold** for the NetGuard controlled-laboratory anomaly-detection project. It does not implement the importer, processing, detection, persistence, API, or dashboard modules yet.

## Directory layout

```text
netguard/
├── compose.yaml                       # entry point for the future full platform
├── .env.example
├── infrastructure/
│   └── kafka/
│       ├── compose.yaml               # broker and one-off topic initializer
│       ├── init-topics.sh             # desired topic inventory
│       └── smoke-test.sh              # broker and produce/consume test
├── backend/                           # future REST API + persistence consumers
├── frontend/                          # future dashboard
├── modules/
│   ├── pcap-importer/                 # future importer
│   ├── flow-processor/                # future normalization/features
│   ├── traffic-simulator/             # future synthetic flow producer
│   └── analysis/                      # future windowing + detectors
├── tests/
└── docs/
```

## Prerequisites

- Docker Engine + Docker Compose v2 with support for the top-level `include` directive (Compose 2.20+).
- Sufficient free disk and RAM for a local Kafka JVM.
- Bash for the included smoke test (Git Bash / WSL recommended on Windows).

## Start / stop

Run from the monorepo root:

```bash
cp .env.example .env   # optional
# Starts the broker and runs the topic-init one-shot container
docker compose up -d
# Check the one-shot init job completed successfully
docker compose ps -a
docker compose logs kafka-init
# Show topics
docker compose exec kafka /opt/kafka/bin/kafka-topics.sh --bootstrap-server kafka:9092 --list
# Integration smoke test (Linux, macOS, WSL, Git Bash)
bash infrastructure/kafka/smoke-test.sh
# Stop without removing Kafka history
docker compose down
```

**To reset local Kafka data** (destructive): `docker compose down -v`.

## Topics — aligned to the communication diagram

| Topic | Producer | Consumers / groups | Partitions | Retention |
|---|---|---|---:|---|
| `flows.normalized` | Flow extraction / normalization / features | Analysis workers (`netguard-analysis`), independent flow persistence (`netguard-flow-persistence`) | 6 | 24 h |
| `detections.created` | Analysis workers publishing detection candidates | Backend classification/persistence (`netguard-detection-persistence`) | 3 | 7 d |

Topic names are established by the provided **Message broker communication diagram**. Partition counts, consumer-group IDs, and retention are **proposed technical defaults**, not mandatory project requirements. The backend classifies and persists detections after consuming detection events, as shown in that diagram. If the implementation team chooses to publish fully classified records instead, update the contract and diagram together.

**IMPORTANT:** The network-flow model is detailed in *Test Data and Demonstration Environment*, section 3. Payload format, event versioning, and detection-candidate schema need team agreement; this starter does not invent them. Preserve `flow_id` / event / trace correlation metadata and event timestamps across Kafka and storage. Never expose simulation ground-truth labels as detector features.

## Connection settings

| Client location | Bootstrap servers |
|---|---|
| Container joined to `netguard` network | `kafka:9092` |
| Process running on your host | `localhost:9094` (or configured `KAFKA_HOST_PORT`) |

All Kafka listeners use PLAINTEXT. The external listener is bound to **127.0.0.1** for a local demo only. Do not expose the broker to an untrusted network. For production use, add authentication, authorization, TLS, and multiple brokers/replicas.

### Add application modules

Add services to root `compose.yaml` using this structure (once Dockerfiles exist):

```yaml
services:
  analysis:
    build: ./modules/analysis
    environment:
      KAFKA_BOOTSTRAP_SERVERS: kafka:9092
      KAFKA_INPUT_TOPIC: flows.normalized
      KAFKA_OUTPUT_TOPIC: detections.created
      KAFKA_GROUP_ID: netguard-analysis
    networks: [netguard]
    depends_on:
      kafka:
        condition: service_healthy
      kafka-init:
        condition: service_completed_successfully
```

Once implemented, run multiple instances with `docker compose up -d --scale analysis=2` (do not use `container_name` on the analysis service). Both instances must use the same Kafka consumer group ID; the flow-persistence consumer must use a **different** group to receive its own copy of every flow. Kafka guarantees ordering **within a partition only**; select a stable flow-related record key after defining the window grouping strategy.

Create additional Docker services for the importer, simulator, backend, database, and frontend. They can share the declared `netguard` network. The frontend should call backend REST APIs; it should not connect directly to Kafka.

## Semantics and limitations

- Kafka single-node KRaft broker: suitable for development / lab demonstrations, **not broker high availability**.
- Six input partitions permit two or more active analysis consumers; capacity/latency **must still be benchmarked**.
- Default broker auto-topic creation is disabled. `kafka-init` creates known topics idempotently; changing partition count later is a separate migration (topic creation won't resize existing topics).
- Use consumer manual offset commits after successful processing and durable writes, producer acknowledgements/idempotence, unique event/detection IDs, and DB upsert/deduplication for at-least-once processing. Do not claim exactly-once end-to-end persistence without additional design.
- Event-time windows **1 s, 10 s, 60 s**, late-event rules, restart recovery, and consistent aggregate ownership must be implemented and tested in analysis services; Kafka alone does not provide them. Partitioning by source IP might work for per-source detectors, but per-destination detectors need an explicit repartitioning or shared-state strategy.
- Test plan thresholds are **5,000 normalized flows/s for 300 seconds** and **p95 acceptance-to-detection creation ≤ 3 s** at the same rate. This Compose setup does **not** demonstrate compliance until load tests are run.
- Controlled synthetic traffic and prepared PCAP/flow datasets only. No production traffic or actual network attacks.

## Runbook checks

```bash
# Live state
docker compose ps -a
# Broker diagnostics
docker compose logs --tail=100 kafka
# Topic status
docker compose exec kafka /opt/kafka/bin/kafka-topics.sh --bootstrap-server kafka:9092 --describe --topic flows.normalized
# Consumer group lag (after applications create groups)
docker compose exec kafka /opt/kafka/bin/kafka-consumer-groups.sh --bootstrap-server kafka:9092 --all-groups --describe
```

See the project's specification (F04, F05, F15; NFR01–05 and NFR08), test plan (TC-005, TC-020–025), and message-broker communication diagram.

## Developer Documentation

- [Kafka Integration Guide](docs/kafka-integration.md)
- [Kafka Message Contracts](contracts/kafka/README.md)
- [Kafka Producer & Consumer Examples](examples/kafka/README.md)