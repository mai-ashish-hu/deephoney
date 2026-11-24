"""DeepHoney - multi-honeypot threat monitoring and analysis.

The package is intentionally split into small modules:

``parsers``      source-specific Cowrie/Dionaea log parsing
``ingestion``    tolerant, idempotent import pipeline
``storage``      SQLAlchemy models and query repository
``sessions``     evidence-preserving session reconstruction
``features``     deterministic behavioural feature extraction
``detection``    rules, classical ML, and optional sequence models
``explainability`` evidence and approximate model explanations
``pcap``         metadata-only PCAP flow extraction
``dashboard``    Streamlit analyst interface
"""

from __future__ import annotations

__version__ = "1.0.0"
__project_period__ = "March-August 2024 (academic reconstruction)"
__version_baseline__ = "2024-08-31"
