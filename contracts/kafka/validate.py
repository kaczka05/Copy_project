#!/usr/bin/env python3
"""Validate NetGuard sample messages or one JSON payload using JSON Schema."""
import argparse
import json
from pathlib import Path
import sys
from jsonschema import Draft202012Validator, FormatChecker

HERE = Path(__file__).resolve().parent
SCHEMAS = {
    "flows.normalized": HERE / "flow-event.v1.schema.json",
    "detections.created": HERE / "detection-event.v1.schema.json",
}

def check(topic: str, payload_path: Path, expect_valid: bool = True) -> bool:
    schema = json.loads(SCHEMAS[topic].read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    payload = json.loads(payload_path.read_text(encoding="utf-8"))
    errors = list(Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(payload))
    outcome = not errors
    if outcome != expect_valid:
        for error in errors:
            print(f"  {'.'.join(map(str, error.absolute_path)) or '$'}: {error.message}")
        print(f"FAIL: {payload_path} ({topic}), expected valid={expect_valid}")
        return False
    print(f"PASS: {payload_path.name} ({topic}), valid={outcome}")
    return True

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--topic", choices=SCHEMAS)
    parser.add_argument("--file", type=Path)
    args = parser.parse_args()
    if bool(args.topic) != bool(args.file):
        parser.error("Specify both --topic and --file or neither")
    if args.topic:
        return 0 if check(args.topic, args.file) else 1
    tests = [("flows.normalized", "flow.valid.json", True),
             ("detections.created", "detection.valid.json", True),
             ("flows.normalized", "flow.invalid.json", False)]
    return 0 if all(check(topic, HERE / "examples" / name, valid) for topic, name, valid in tests) else 1

if __name__ == "__main__":
    sys.exit(main())
