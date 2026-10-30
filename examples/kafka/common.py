"""Shared JSON Schema validation helpers; never imports the Kafka client."""
import json
from pathlib import Path
from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[2]
CONTRACTS = ROOT / 'contracts' / 'kafka'
SCHEMAS = {
    'flows.normalized': 'flow-event.v1.schema.json',
    'detections.created': 'detection-event.v1.schema.json',
}
VALIDATORS = {}


def validator(topic):
    if topic not in SCHEMAS:
        raise ValueError(f'Unsupported topic {topic!r}; expected one of {list(SCHEMAS)}')
    if topic not in VALIDATORS:
        schema = json.loads((CONTRACTS / SCHEMAS[topic]).read_text(encoding='utf-8'))
        Draft202012Validator.check_schema(schema)
        VALIDATORS[topic] = Draft202012Validator(schema, format_checker=FormatChecker())
    return VALIDATORS[topic]


def validate(topic, message):
    validator(topic).validate(message)
    # A semantic validation that JSON Schema alone cannot express.
    if topic == 'flows.normalized' and message['protocol'] != 'TCP' and message.get('tcp_flags') is not None:
        raise ValueError('tcp_flags must be null/omitted for non-TCP flows')
    if topic == 'detections.created':
        from datetime import datetime
        w = message['window']
        start = datetime.fromisoformat(w['start'].replace('Z', '+00:00'))
        end = datetime.fromisoformat(w['end'].replace('Z', '+00:00'))
        if (end - start).total_seconds() != w['duration_seconds']:
            raise ValueError('window length does not match duration_seconds')
    return message


def kafka_key(topic, message):
    return message['src_ip'] if topic == 'flows.normalized' else message['detection_id']


def prepare_flow_for_detection(message):
    """Ground truth must never reach detector decision logic."""
    return {key: value for key, value in message.items() if key not in {'scenario_label'}}
