"""NetGuard PCAP/flow ingestion, flow extraction, validation and normalisation.

This package converts *actual* prepared PCAP/PCAPNG captures and prepared
NetGuard-native flow datasets into normalised, unidirectional FlowEvent v1
records (``contracts/kafka/flow-event.v1.schema.json``).

It never generates, simulates or fabricates network traffic.
"""

__all__ = ["TOOL_NAME", "__version__"]

__version__ = "1.0.0"
TOOL_NAME = "netguard-ingest"
