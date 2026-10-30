# NetGuard Kafka CI: contracts and integration

This workflow verifies Kafka topic provisioning and actual JSON producer → Kafka → consumer round trips for both `flows.normalized` and `detections.created`. All test payloads come from controlled synthetic fixtures; no real-network traffic is used.

## Where the files go

```text
.github/workflows/kafka-integration.yml
scripts/test-kafka-ci.sh
tests/test_kafka_integration.py
docs/kafka-ci.md
```

The files above are an **additive patch** to the existing repository. They depend on its existing `compose.yaml`, `infrastructure/kafka`, `contracts/kafka`, `examples/kafka`, and `tests/test_kafka_example_contracts.py`. Do not replace your colleagues' modules or existing Compose configuration.

## What the GitHub Actions job does

1. Checks out the repository and installs Python 3.12 dependencies.
2. Validates both v1 schemas and checks that the deliberately invalid flow example is rejected.
3. Runs the offline unit tests (including semantic checks beyond JSON Schema).
4. Boots the existing single-node Kafka container and runs the existing topic initialization job.
5. Creates a unique Kafka consumer group for each integration case, waits for partition assignment, then publishes and reads one **new uniquely identified** event in each topic. Confirms the decoded payload, key, partition, offset, and trace ID, and commits after validation. Also checks `scenario_label` is removed before detector-facing processing.
6. Dumps broker logs on failure and runs `docker compose down -v` to clean the **ephemeral GitHub-hosted CI runner**.

This is a real Kafka integration test, but **not** proof that all NetGuard application services work together; it does not measure 5,000 flows/s, p95 latency, resilience, API security, persistence, or detector accuracy. These require separate suites.

## Run locally (Linux / WSL)

From the repository root (preferably within an activated virtual environment):

```bash
bash scripts/test-kafka-ci.sh
```

It installs Python dependencies, runs validation/unit tests, starts/reuses the Kafka broker, initializes topics and executes integration tests. Local script **keeps Kafka and its data volume running** (unlike the GitHub CI cleanup). Python, pip, Docker Engine and Docker Compose v2 are required.

To run only the broker-dependent tests against your already-running Kafka:

```bash
python3 -m pip install -r examples/kafka/requirements.txt pytest
KAFKA_BOOTSTRAP_SERVERS=localhost:9094 python3 -m pytest tests/test_kafka_integration.py -v -s
```

Run the tests only in a lab/development Kafka instance: they add test messages to the two shared topics. Do not point them at production-like application workloads without coordinating with the team. Use separate test namespaces/clusters if the team wants full isolation.

## GitHub setup

1. Commit these new files alongside the previously created Kafka files.
2. Push a branch and create a Pull Request into `main` (or `master`); the workflow runs when a matching Kafka-related path changes. You can also run it manually under **Actions → Kafka contracts and integration → Run workflow**.
3. For mandatory PR gates, protect the default branch and require the **Contract and broker integration tests** check. Workflow success alone does not enforce merge protection.
4. The job runs with `contents: read`. It needs no Kafka secrets because its broker listens only inside the ephemeral runner (host `127.0.0.1:9094`).

**Security:** This is lab-only PLAINTEXT Kafka, not a hardened multi-node deployment. No external listener or production datasets are required.

## Consumer groups and delivery expectations

The test uses per-run `netguard-ci-<uuid>` groups to avoid taking partitions from `netguard-analysis` or backend persistence groups. It uses `auto.offset.reset=latest` **only after** waiting for partition assignment, preventing a first-subscription race; fixture messages carry fresh `event_id`s. Consumers turn off auto-commit and manually commit after verification.

The test cannot guarantee exactly-once business processing; application services still need idempotency and recovery rules. CI uses uniquely generated identifiers to allow repeated runs.

## Troubleshooting

- **Connection refused / timeouts:** `docker compose ps -a`; `docker compose logs kafka`; check host port `9094` and ensure no other service occupies it.
- **Unknown topic:** `docker compose logs kafka-init`; ensure init finished with exit code 0 and topic names match the contracts.
- **No partition assignment:** inspect group/network state, broker health, listener addresses; `localhost:9094` is for programs on your Linux/WSL host, not other Docker containers (those use `kafka:9092`).
- **Schema rejection:** `python3 contracts/kafka/validate.py`; make sure fixtures and schemas are from the same contract version.
- **Failure only on GitHub:** inspect the `Dump Kafka diagnostics on failure` step. Ensure the repository has all prior NetGuard starter files, not just this patch.

## Source alignment

F04 (message broker inter-component communication), F15 (trace identifiers), NFR05 (reproducible startup), NFR07 (automated tests) and the test plan's broker integration cases are the immediate targets. Later end-to-end and nonfunctional acceptance tests are separate work.
