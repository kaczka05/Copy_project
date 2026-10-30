# NetGuard — Kafka UI and Diagnostics

## 1. Purpose and scope

This adds an **optional, read-only web interface** and CLI diagnostics to the existing
single-broker Kafka development environment. Kafka remains independently usable when
the UI is off. It does **not** add authentication, a production-grade broker cluster,
metrics history, alerting, or an end-to-end NetGuard application.

The NetGuard messaging paths are:

- `flows.normalized` — produced by Flow Processor; consumed by `netguard-analysis`
  (multiple analysis workers) and `netguard-flow-persistence` (independent group).
- `detections.created` — produced by analysis workers; consumed by
  `netguard-detection-persistence` (backend consumer group).

These consumer-group names are recommended conventions; a group only appears in Kafka
once an application actually starts consuming and committing offsets. The topics are
created by the existing `kafka-init` service.

## 2. Files

| File | Purpose |
| --- | --- |
| `infrastructure/kafka/compose.yaml` | Existing Kafka services **plus optional** `kafka-ui` service |
| `infrastructure/kafka/diagnostics.sh` | Read-only status, topic, group, lag and logs commands |
| `docs/kafka-ui-diagnostics.md` | This integration/operations guide |

The root `compose.yaml` uses `include` to load `infrastructure/kafka/compose.yaml`.
Do not add `kafka-ui` to root `compose.yaml` a second time.

## 3. Install without losing broker data

From repository root, copy the supplied files to the matching paths. If you have
modified your `infrastructure/kafka/compose.yaml`, **merge only the `kafka-ui:` service**
from the supplied file rather than overwriting your edits.

Review the Compose config (requires a recent Docker Compose v2):

```bash
docker compose --profile tools config --quiet
```

Start only the optional UI while keeping the existing Kafka broker:

```bash
docker compose --profile tools up -d kafka-ui
docker compose --profile tools ps
```

Open **http://localhost:8085** in a browser running on the Docker host. Override the
localhost-bound UI port (if already occupied) using:

```bash
KAFKA_UI_HOST_PORT=8086 docker compose --profile tools up -d kafka-ui
```

The UI talks to `kafka:9092` inside Docker, **not** to `localhost:9094`.
External developer processes on the host still use `localhost:9094`.

Stop only the UI without stopping Kafka:

```bash
docker compose --profile tools stop kafka-ui
```

**Do not run `docker compose down -v`** unless you intentionally want to delete Kafka's
named volume and all locally retained messages.

## 4. Using the UI

1. Open **Clusters → netguard-local**.
2. Open **Topics** to inspect `flows.normalized` (6 partitions; 1-day retention) and
   `detections.created` (3 partitions; 7-day retention), per the current topic initializer.
3. Open a topic's **Messages** to inspect records and keys. Message values should be
   valid JSON conforming to files in `contracts/kafka/`.
4. Open **Consumer Groups** to inspect live groups and their offsets/lag.

Kafka UI is explicitly configured for read-only operations
(`KAFKA_CLUSTERS_0_READONLY=true`), so developers cannot edit/delete topics or produce
messages through the panel. If a browser action is unavailable, use the example Python
producer or existing smoke test to send test records.

> IMPORTANT: The UI has **no login** and Kafka uses `PLAINTEXT` in this lab setup.
> The host port binds to `127.0.0.1` only. Do not expose it publicly or use it against
> non-laboratory clusters. Anyone able to use the local dashboard can inspect test data.

## 5. CLI diagnostics

Run from the NetGuard repository root:

```bash
bash infrastructure/kafka/diagnostics.sh status
bash infrastructure/kafka/diagnostics.sh broker
bash infrastructure/kafka/diagnostics.sh topics
bash infrastructure/kafka/diagnostics.sh topic flows.normalized
bash infrastructure/kafka/diagnostics.sh topic detections.created
bash infrastructure/kafka/diagnostics.sh groups
bash infrastructure/kafka/diagnostics.sh lag netguard-analysis
bash infrastructure/kafka/diagnostics.sh lag netguard-flow-persistence
bash infrastructure/kafka/diagnostics.sh lag netguard-detection-persistence
bash infrastructure/kafka/diagnostics.sh logs
bash infrastructure/kafka/diagnostics.sh ui-logs
```

The `lag` command reports offsets **only if the group exists and has committed offsets**.
At startup, before any application consumers connect, it is normal for the group list
to be empty. A blank lag column or `-` does not automatically mean zero lag. A growing
positive lag suggests consumers are falling behind, but interpret it together with
traffic rate, partition assignment, idle consumers, and recent rebalances.

### Consumer-group separation

- `netguard-analysis` workers **share** a group so Kafka distributes `flows.normalized`
  partitions among them.
- Flow persistence uses a **different** group to see the same flow events independently.
- Detection persistence consumes `detections.created` using another independent group.
- Debug/test consumers should use **fresh, disposable groups**, not application group IDs,
  because sharing an application group can redistribute partitions and disrupt processing.

## 6. Troubleshooting

| Symptom | Check / likely cause |
| --- | --- |
| UI is not running after `docker compose up -d` | Expected: it is under optional `tools` profile. Start with `docker compose --profile tools up -d kafka-ui`. |
| Can't open localhost:8085 | Check `docker compose --profile tools ps`, `ui-logs`, and port collision. |
| Kafka UI cannot connect to broker | UI must use `kafka:9092` on the Compose network. Check `status`, `broker`, and `logs`. |
| Topics are not visible | Check `docker compose logs kafka-init`, then `topics`; broker may be fine but initializer was not run. |
| No consumer groups | Expected until application consumers actually connect/commit. |
| Message not visible in UI | Check topic, partition, retention window, producer acknowledgements and UI pagination/offset position. |
| Consumer lag continues increasing | Verify consumer is alive, commits offsets after successful processing, and has sufficient processing capacity. |
| Broker restarted | `kafka-init` is a one-shot container; `Exited (0)` is expected. It is safe to rerun its idempotent topic setup. |
| Port 9094 works locally but not in another container | Containers must use `kafka:9092`. Host listeners and internal listeners are different. |

## 7. Tests and limitations

Smoke-test the broker without the UI:

```bash
bash infrastructure/kafka/smoke-test.sh
```

Run the contract validator and producer/consumer tests using the separate scripts
already documented in `contracts/kafka/README.md` and `docs/kafka-integration.md`.

This diagnostics layer supports NFR08 (observability), NFR03 (checking multiple
processing consumers), NFR04 (watching lag across worker restart), and the NetGuard
integration test cases. **It does not by itself demonstrate** the required 5,000 flows/s
for 300 seconds, p95 detection latency <= 3 s, failover, or correctness of alerts.
Those require instrumented application-level tests and documented results.

The UI image is pinned to `provectuslabs/kafka-ui:v0.7.2` to avoid a moving `latest` tag.
Before broader deployment, review its upstream maintenance/security status and consider
a supported version. Read-only mode is a UI-level restriction, **not broker ACLs**.
