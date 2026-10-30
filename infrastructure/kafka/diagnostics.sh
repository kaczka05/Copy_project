#!/usr/bin/env bash
set -Eeuo pipefail

# Run at repository root (where compose.yaml lives).
usage() {
  cat <<'USAGE'
Usage: bash infrastructure/kafka/diagnostics.sh <command> [name]
Commands:
  status                   Container statuses and health
  topics                   List Kafka topics
  topic <topic>            Inspect topic partitions/configs
  groups                   List consumer groups
  lag <group>              Show committed offsets, log-end offsets and lag
  broker                   Check Kafka broker API versions
  logs                     Tail 100 Kafka broker log lines
  ui-logs                  Tail 100 Kafka UI log lines (if started)

Examples:
  bash infrastructure/kafka/diagnostics.sh topic flows.normalized
  bash infrastructure/kafka/diagnostics.sh lag netguard-analysis
USAGE
}

if ! command -v docker >/dev/null 2>&1; then
  echo 'ERROR: Docker is not installed/in PATH.' >&2; exit 1
fi
if [[ ! -f compose.yaml ]]; then
  echo 'ERROR: Run this script from the NetGuard repository root (compose.yaml).' >&2; exit 1
fi
kafka_cli() { docker compose exec -T kafka "/opt/kafka/bin/$1" --bootstrap-server kafka:9092 "${@:2}"; }

command_name="${1:-}"
case "$command_name" in
  status) docker compose ps -a ;;
  topics) kafka_cli kafka-topics.sh --list ;;
  topic)
    [[ $# == 2 && "$2" =~ ^[A-Za-z0-9._-]+$ ]] || { usage >&2; exit 2; }
    kafka_cli kafka-topics.sh --describe --topic "$2" ;;
  groups) kafka_cli kafka-consumer-groups.sh --list ;;
  lag)
    [[ $# == 2 && "$2" =~ ^[A-Za-z0-9._-]+$ ]] || { usage >&2; exit 2; }
    kafka_cli kafka-consumer-groups.sh --describe --group "$2" ;;
  broker) kafka_cli kafka-broker-api-versions.sh ;;
  logs) docker compose logs --tail=100 kafka ;;
  ui-logs) docker compose --profile tools logs --tail=100 kafka-ui ;;
  *) usage; [[ -z "$command_name" ]] && exit 2 || exit 2 ;;
esac
