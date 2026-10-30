#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
DC=(docker compose -f compose.yaml)
"${DC[@]}" up -d --wait kafka
"${DC[@]}" up --exit-code-from kafka-init kafka-init
for topic in flows.normalized detections.created; do
  "${DC[@]}" exec -T kafka /opt/kafka/bin/kafka-topics.sh \
    --bootstrap-server kafka:9092 --describe --topic "$topic"
done
# Isolated temporary topic: doesn't send fake FlowEvents to application consumers.
TOPIC="netguard.smoke.$(date +%s).$$"
"${DC[@]}" exec -T kafka /opt/kafka/bin/kafka-topics.sh \
  --bootstrap-server kafka:9092 --create --topic "$TOPIC" \
  --partitions 1 --replication-factor 1
trap '"${DC[@]}" exec -T kafka /opt/kafka/bin/kafka-topics.sh --bootstrap-server kafka:9092 --delete --topic "$TOPIC" >/dev/null 2>&1 || true' EXIT
printf 'netguard-smoke-test\n' | "${DC[@]}" exec -T kafka /opt/kafka/bin/kafka-console-producer.sh \
  --bootstrap-server kafka:9092 --topic "$TOPIC"
OUTPUT="$("${DC[@]}" exec -T kafka /opt/kafka/bin/kafka-console-consumer.sh \
  --bootstrap-server kafka:9092 --topic "$TOPIC" --from-beginning \
  --max-messages 1 --timeout-ms 15000 2>/dev/null)"
[[ "$OUTPUT" == *netguard-smoke-test* ]] || { echo "Smoke test FAILED: $OUTPUT" >&2; exit 1; }
echo 'Smoke test PASSED: Kafka is reachable; configured topics exist; produce/consume works.'
