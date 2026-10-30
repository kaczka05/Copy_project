#!/usr/bin/env bash
# Run from any directory. WARNING: stop and remove local NetGuard Kafka containers/volume?
# No: intentionally preserve existing local state by default.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
python3 -m pip install -r contracts/kafka/requirements-dev.txt -r examples/kafka/requirements.txt pytest
python3 contracts/kafka/validate.py
python3 -m pytest tests/test_kafka_example_contracts.py -v
docker compose up -d --wait kafka
docker compose up --exit-code-from kafka-init kafka-init
python3 -m pytest tests/test_kafka_integration.py -v -s
echo 'Kafka contract and integration checks passed.'
# Unlike CI, local script does NOT tear down Kafka or delete Kafka volumes.
