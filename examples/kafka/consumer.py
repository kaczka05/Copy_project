#!/usr/bin/env python3
"""Consume NetGuard messages with validation, explicitly committed offsets and clean exit."""
import argparse
import json
import os
import uuid
from confluent_kafka import Consumer, KafkaException, KafkaError
from common import SCHEMAS, prepare_flow_for_detection, validate


def main():
    p = argparse.ArgumentParser(description='Receive NetGuard lab messages.')
    p.add_argument('--topic', choices=list(SCHEMAS), default='flows.normalized')
    p.add_argument('--group-id', default=None, help='Use dedicated group for each service role')
    p.add_argument('--bootstrap-servers', default=os.getenv('KAFKA_BOOTSTRAP_SERVERS', 'localhost:9094'))
    p.add_argument('--max-messages', type=int, default=1, help='0 means continuous')
    p.add_argument('--timeout', type=float, default=15, help='Exit after inactivity in seconds; 0 means keep waiting')
    args = p.parse_args()
    if args.max_messages < 0 or args.timeout < 0:
        p.error('--max-messages and --timeout must be non-negative')
    group = args.group_id or f'netguard-example-{uuid.uuid4().hex[:12]}'
    consumer = Consumer({'bootstrap.servers': args.bootstrap_servers,
                         'group.id': group,
                         'auto.offset.reset': 'earliest',
                         'enable.auto.commit': False})
    consumer.subscribe([args.topic])
    count = 0
    from time import monotonic
    deadline = monotonic() + args.timeout if args.timeout else None
    print(f'Listening topic={args.topic} group={group}; Ctrl+C to stop', flush=True)
    try:
        while args.max_messages == 0 or count < args.max_messages:
            if deadline is not None and monotonic() >= deadline:
                print('Timed out with no further messages')
                break
            record = consumer.poll(1.0)
            if record is None:
                continue
            if record.error():
                if record.error().code() == KafkaError._PARTITION_EOF:
                    continue
                raise KafkaException(record.error())
            try:
                payload = json.loads(record.value().decode('utf-8'))
                validate(args.topic, payload)
            except (ValueError, UnicodeError, json.JSONDecodeError) as exc:
                # Do not silently commit unparseable records; quarantine/DLQ is future work.
                print(f'INVALID message topic={record.topic()} partition={record.partition()} offset={record.offset()}: {exc}', flush=True)
                raise
            safe_payload = (prepare_flow_for_detection(payload) if args.topic == 'flows.normalized' else payload)
            print(f'RECEIVED topic={record.topic()} partition={record.partition()} offset={record.offset()} '
                  f'key={record.key().decode("utf-8") if record.key() else None} '
                  f'event_id={payload["event_id"]}\n{json.dumps(safe_payload, indent=2)}', flush=True)
            # A real service commits only after the business operation/persistence succeeds.
            consumer.commit(message=record, asynchronous=False)
            count += 1
            if deadline is not None:
                deadline = monotonic() + args.timeout
    except KeyboardInterrupt:
        print('Interrupted')
    finally:
        consumer.close()
    print(f'Processed {count} message(s)')


if __name__ == '__main__':
    main()
