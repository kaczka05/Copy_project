#!/usr/bin/env python3
"""Publish one validated example/file payload to the running NetGuard Kafka broker."""
import argparse
import json
import os
from pathlib import Path
from confluent_kafka import Producer, KafkaException
from common import CONTRACTS, SCHEMAS, kafka_key, validate


def main():
    p = argparse.ArgumentParser(description='Send validated NetGuard message (lab data only).')
    p.add_argument('--topic', choices=list(SCHEMAS), default='flows.normalized')
    p.add_argument('--file', type=Path, help='JSON payload file; defaults to example for topic')
    p.add_argument('--bootstrap-servers', default=os.getenv('KAFKA_BOOTSTRAP_SERVERS', 'localhost:9094'))
    args = p.parse_args()
    default_name = 'flow.valid.json' if args.topic == 'flows.normalized' else 'detection.valid.json'
    path = args.file or CONTRACTS / 'examples' / default_name
    message = validate(args.topic, json.loads(path.read_text(encoding='utf-8')))
    key = kafka_key(args.topic, message)
    producer = Producer({'bootstrap.servers': args.bootstrap_servers,
                         'enable.idempotence': True, 'acks': 'all',
                         'message.timeout.ms': 10000})
    errors = []
    delivered = []

    def on_delivery(err, record):
        if err:
            errors.append(err)
        else:
            delivered.append((record.topic(), record.partition(), record.offset()))

    producer.produce(args.topic, key=key.encode('utf-8'),
                     value=json.dumps(message, ensure_ascii=False).encode('utf-8'),
                     on_delivery=on_delivery)
    remaining = producer.flush(15)
    if errors or remaining or not delivered:
        raise KafkaException(f'Delivery failed: errors={errors}, pending={remaining}')
    topic, partition, offset = delivered[0]
    print(f'DELIVERED topic={topic} partition={partition} offset={offset} key={key} event_id={message["event_id"]}')


if __name__ == '__main__':
    main()
