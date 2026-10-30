#!/usr/bin/env bash
set -euo pipefail

BOOTSTRAP="kafka:9092"
CLI="/opt/kafka/bin/kafka-topics.sh"

create_topic() {
  local name="$1" partitions="$2" retention="$3"
  echo "Ensuring topic ${name} (partitions=${partitions}, retention.ms=${retention})"
  "$CLI" --bootstrap-server "$BOOTSTRAP" --create --if-not-exists \
    --topic "$name" --partitions "$partitions" --replication-factor 1 \
    --config "retention.ms=${retention}"
  "$CLI" --bootstrap-server "$BOOTSTRAP" --describe --topic "$name"
}

# Both names come from the project's message-broker communication diagram.
# 3 partitions allow analysis-group workers to share input partitions.
# The different consumer groups read the same topic independently.
create_topic 'flows.normalized' 6 86400000
create_topic 'detections.created' 3 604800000

echo 'NetGuard Kafka topics ready.'
