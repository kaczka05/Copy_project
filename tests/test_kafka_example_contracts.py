"""Offline contract/unit tests; do not require Kafka or confluent-kafka installed."""
import json
import sys
from pathlib import Path
import pytest
from jsonschema import ValidationError

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'examples' / 'kafka'))
from common import CONTRACTS, kafka_key, prepare_flow_for_detection, validate


def payload(name):
    return json.loads((CONTRACTS / 'examples' / name).read_text(encoding='utf-8'))


def test_valid_flow():
    msg = payload('flow.valid.json')
    assert validate('flows.normalized', msg) == msg
    assert kafka_key('flows.normalized', msg) == msg['src_ip']
    assert 'scenario_label' not in prepare_flow_for_detection(msg)
    assert 'scenario_label' in msg


def test_valid_detection():
    msg = payload('detection.valid.json')
    assert validate('detections.created', msg) == msg
    assert kafka_key('detections.created', msg) == msg['detection_id']


def test_invalid_flow():
    with pytest.raises(ValidationError):
        validate('flows.normalized', payload('flow.invalid.json'))


def test_non_tcp_flags_rejected():
    msg = payload('flow.valid.json')
    msg['protocol'] = 'UDP'
    with pytest.raises(ValueError):
        validate('flows.normalized', msg)


def test_inconsistent_window_rejected():
    msg = payload('detection.valid.json')
    msg['window']['duration_seconds'] = 60
    with pytest.raises(ValueError):
        validate('detections.created', msg)
