"""Logging configuration: key=value text or one JSON object per line."""
from __future__ import annotations

import json
import logging
import sys

LOGGER_NAME = "netguard_ingest"


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key in ("ingestion_id", "source_file"):
            if hasattr(record, key):
                payload[key] = getattr(record, key)
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def configure_logging(level: str = "INFO", fmt: str = "text") -> None:
    handler = logging.StreamHandler(sys.stderr)
    if fmt == "json":
        handler.setFormatter(_JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    logger = logging.getLogger(LOGGER_NAME)
    logger.handlers[:] = [handler]
    logger.setLevel(level.upper())
    logger.propagate = False


def get_logger(ingestion_id: str | None = None, source_file: str | None = None) -> logging.LoggerAdapter:
    extra = {}
    if ingestion_id:
        extra["ingestion_id"] = ingestion_id
    if source_file:
        extra["source_file"] = source_file
    return logging.LoggerAdapter(logging.getLogger(LOGGER_NAME), extra)
