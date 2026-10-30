"""Real broker integration test; requires KAFKA_BOOTSTRAP_SERVERS and running topics.

No service-specific consumer group is reused. All payloads use reserved test IPs.
"""
import json
import os
import sys
import time
import uuid
from pathlib import Path

import pytest
from confluent_kafka import Consumer, Producer, KafkaException

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'examples' / 'kafka'))
from common import CONTRACTS, kafka_key, validate, prepare_flow_for_detection

BOOTSTRAP = os.getenv('KAFKA_BOOTSTRAP_SERVERS', 'localhost:9094')


@pytest.mark.parametrize('topic,filename', [
    ('flows.normalized', 'flow.valid.json'),
    ('detections.created', 'detection.valid.json'),
])
def test_produce_consume_real_kafka(topic, filename):
    """Verify real producer delivery, group subscription, JSON, key, and trace data."""
    payload = json.loads((CONTRACTS / 'examples' / filename).read_text(encoding='utf-8'))
    token = uuid.uuid4().hex
    payload['event_id'] = f'ci-event-{token}'
    payload['trace_id'] = f'ci-trace-{token}'
    if topic == 'flows.normalized':
        payload['flow_id'] = f'ci-flow-{token}'
    else:
        payload['detection_id'] = f'ci-detection-{token}'
    validate(topic, payload)
    key = kafka_key(topic, payload)

    consumer = Consumer({
        'bootstrap.servers': BOOTSTRAP,
        'group.id': f'netguard-ci-{token}',
        'auto.offset.reset': 'latest',
        'enable.auto.commit': False,
        'session.timeout.ms': 10000,
    })
    producer = Producer({
        'bootstrap.servers': BOOTSTRAP,
        'enable.idempotence': True,
        'acks': 'all',
        'message.timeout.ms': 15000,
    })
    try:
        consumer.subscribe([topic])
        # Ensure the group has assigned partitions BEFORE publishing: latest otherwise
        # risks skipping the message when a new group first gets its assignment.
        deadline = time.monotonic() + 30
        while not consumer.assignment() and time.monotonic() < deadline:
            record = consumer.poll(0.5)
            if record is not None and record.error():
                raise KafkaException(record.error())
        assert consumer.assignment(), f'Kafka group never obtained partitions for {topic}'

        deliveries = []
        producer.produce(
            topic,
            key=key.encode('utf-8'),
            value=json.dumps(payload, ensure_ascii=False).encode('utf-8'),
            on_delivery=lambda error, record: deliveries.append((error, record)),
        )
        assert producer.flush(20) == 0, 'Producer timed out before delivery'
        assert len(deliveries) == 1 and deliveries[0][0] is None, f'Delivery failed: {deliveries}'
        sent = deliveries[0][1]

        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            record = consumer.poll(1)
            if record is None:
                continue
            if record.error():
                raise KafkaException(record.error())
            decoded = json.loads(record.value().decode('utf-8'))
            if decoded.get('event_id') != payload['event_id']:
                continue  # Other CI runs / test writers might use the same topic.
            assert record.topic() == topic
            assert record.key() == key.encode('utf-8')
            assert record.partition() == sent.partition()
            assert record.offset() == sent.offset()
            assert validate(topic, decoded) == payload
            assert decoded['trace_id'] == payload['trace_id']
            if topic == 'flows.normalized':
                assert 'scenario_label' not in prepare_flow_for_detection(decoded)
            consumer.commit(message=record, asynchronous=False)
            print(f'PASS {topic} partition={record.partition()} offset={record.offset()}')
            return
        pytest.fail(f'Timed out receiving our event_id={payload["event_id"]} on {topic}')
    finally:
        consumer.close()
