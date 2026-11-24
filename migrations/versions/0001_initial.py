"""Initial DeepHoney schema.

Revision ID: 0001_initial
Revises:
Create Date: 2024-08-30 12:00:00+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

JSONType = sa.JSON().with_variant(sa.dialects.postgresql.JSONB(), "postgresql")

revision: str = "0001_initial"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "events",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("event_hash", sa.String(length=64), nullable=False),
        sa.Column("source_engine", sa.String(length=16), nullable=False),
        sa.Column("source_event_id", sa.String(length=255), nullable=True),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=True),
        sa.Column("src_ip", sa.String(length=45), nullable=True),
        sa.Column("src_port", sa.Integer(), nullable=True),
        sa.Column("dst_ip", sa.String(length=45), nullable=True),
        sa.Column("dst_port", sa.Integer(), nullable=True),
        sa.Column("protocol", sa.String(length=32), nullable=True),
        sa.Column("session_id", sa.String(length=255), nullable=True),
        sa.Column("username", sa.String(length=255), nullable=True),
        sa.Column("command", sa.Text(), nullable=True),
        sa.Column("artifact_sha256", sa.String(length=64), nullable=True),
        sa.Column("raw_payload", JSONType, nullable=False),
        sa.Column("details", JSONType, nullable=False),
        sa.Column("source_file", sa.Text(), nullable=False),
        sa.Column("source_line", sa.Integer(), nullable=True),
        sa.Column("parser_version", sa.String(length=64), nullable=False),
        sa.Column("ingested_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_events_event_hash", "events", ["event_hash"], unique=True)
    op.create_index("ix_events_source_engine", "events", ["source_engine"])
    op.create_index("ix_events_event_type", "events", ["event_type"])
    op.create_index("ix_events_timestamp", "events", ["timestamp"])
    op.create_index("ix_events_src_ip", "events", ["src_ip"])
    op.create_index("ix_events_protocol", "events", ["protocol"])
    op.create_index("ix_events_session_id", "events", ["session_id"])
    op.create_index("ix_events_username", "events", ["username"])
    op.create_index("ix_events_artifact_sha256", "events", ["artifact_sha256"])
    op.create_index("ix_events_ingested_at", "events", ["ingested_at"])
    op.create_index("ix_events_engine_timestamp", "events", ["source_engine", "timestamp"])
    op.create_index("ix_events_session_engine", "events", ["session_id", "source_engine"])
    op.create_index("ix_events_type_timestamp", "events", ["event_type", "timestamp"])
    op.create_index("ix_events_src_ip_timestamp", "events", ["src_ip", "timestamp"])

    op.create_table(
        "sessions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("source_engine", sa.String(length=16), nullable=False),
        sa.Column("source_session_id", sa.String(length=255), nullable=False),
        sa.Column("src_ip", sa.String(length=45), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("event_count", sa.Integer(), nullable=False),
        sa.Column("session_metadata", JSONType, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "source_engine", "source_session_id", name="uq_sessions_engine_source_id"
        ),
    )
    op.create_index("ix_sessions_source_engine", "sessions", ["source_engine"])
    op.create_index("ix_sessions_src_ip", "sessions", ["src_ip"])
    op.create_index("ix_sessions_first_seen_at", "sessions", ["first_seen_at"])
    op.create_index("ix_sessions_last_seen_at", "sessions", ["last_seen_at"])
    op.create_index("ix_sessions_engine_first_seen", "sessions", ["source_engine", "first_seen_at"])
    op.create_index("ix_sessions_src_ip_first_seen", "sessions", ["src_ip", "first_seen_at"])

    op.create_table(
        "artifacts",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("source_engine", sa.String(length=16), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("file_size", sa.Integer(), nullable=True),
        sa.Column("detected_type", sa.String(length=128), nullable=True),
        sa.Column("storage_path", sa.Text(), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("artifact_metadata", JSONType, nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("source_engine", "sha256", name="uq_artifacts_engine_sha256"),
    )
    op.create_index("ix_artifacts_source_engine", "artifacts", ["source_engine"])
    op.create_index("ix_artifacts_sha256", "artifacts", ["sha256"])
    op.create_index("ix_artifacts_sha256_first_seen", "artifacts", ["sha256", "first_seen_at"])

    op.create_table(
        "detections",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("event_id", sa.Uuid(), nullable=True),
        sa.Column("session_id", sa.Uuid(), nullable=True),
        sa.Column("detection_method", sa.String(length=32), nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("risk_level", sa.String(length=16), nullable=False),
        sa.Column("model_version", sa.String(length=128), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.Column("evidence", JSONType, nullable=False),
        sa.Column("explanation", JSONType, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["event_id"], ["events.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["session_id"], ["sessions.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "session_id",
            "detection_method",
            "model_version",
            name="uq_detections_session_method_version",
        ),
    )
    op.create_index("ix_detections_event_id", "detections", ["event_id"])
    op.create_index("ix_detections_session_id", "detections", ["session_id"])
    op.create_index("ix_detections_detection_method", "detections", ["detection_method"])
    op.create_index("ix_detections_risk_score", "detections", ["risk_score"])
    op.create_index("ix_detections_risk_level", "detections", ["risk_level"])
    op.create_index("ix_detections_created_at", "detections", ["created_at"])
    op.create_index("ix_detections_risk_created", "detections", ["risk_score", "created_at"])
    op.create_index(
        "ix_detections_method_created", "detections", ["detection_method", "created_at"]
    )

    op.create_table(
        "ingestion_runs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("source_engine", sa.String(length=16), nullable=False),
        sa.Column("source_file", sa.Text(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("records_read", sa.Integer(), nullable=False),
        sa.Column("records_created", sa.Integer(), nullable=False),
        sa.Column("records_skipped", sa.Integer(), nullable=False),
        sa.Column("records_failed", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("error_summary", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_ingestion_runs_source_engine", "ingestion_runs", ["source_engine"])
    op.create_index("ix_ingestion_runs_started_at", "ingestion_runs", ["started_at"])
    op.create_index("ix_ingestion_runs_status", "ingestion_runs", ["status"])

    op.create_table(
        "parser_failures",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("source_engine", sa.String(length=16), nullable=False),
        sa.Column("source_file", sa.Text(), nullable=False),
        sa.Column("line_number", sa.Integer(), nullable=True),
        sa.Column("error", sa.Text(), nullable=False),
        sa.Column("raw_excerpt", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_parser_failures_source_engine", "parser_failures", ["source_engine"])
    op.create_index("ix_parser_failures_created_at", "parser_failures", ["created_at"])

    op.create_table(
        "ingestion_offsets",
        sa.Column("source_file", sa.Text(), nullable=False),
        sa.Column("source_engine", sa.String(length=16), nullable=False),
        sa.Column("byte_offset", sa.Integer(), nullable=False),
        sa.Column("file_size", sa.Integer(), nullable=False),
        sa.Column("mtime", sa.Float(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("source_file"),
    )
    op.create_index("ix_ingestion_offsets_source_engine", "ingestion_offsets", ["source_engine"])

    op.create_table(
        "pcap_captures",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("filename", sa.Text(), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("file_size", sa.Integer(), nullable=False),
        sa.Column("packet_count", sa.Integer(), nullable=False),
        sa.Column("flow_count", sa.Integer(), nullable=False),
        sa.Column("truncated", sa.Boolean(), nullable=False),
        sa.Column("imported_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("capture_metadata", JSONType, nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_pcap_captures_sha256", "pcap_captures", ["sha256"], unique=True)
    op.create_index("ix_pcap_captures_imported_at", "pcap_captures", ["imported_at"])

    op.create_table(
        "pcap_flows",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("capture_id", sa.Uuid(), nullable=False),
        sa.Column("src_ip", sa.String(length=45), nullable=False),
        sa.Column("src_port", sa.Integer(), nullable=True),
        sa.Column("dst_ip", sa.String(length=45), nullable=False),
        sa.Column("dst_port", sa.Integer(), nullable=True),
        sa.Column("protocol", sa.String(length=32), nullable=False),
        sa.Column("packet_count", sa.Integer(), nullable=False),
        sa.Column("byte_count", sa.Integer(), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("flow_metadata", JSONType, nullable=False),
        sa.ForeignKeyConstraint(["capture_id"], ["pcap_captures.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_pcap_flows_capture_id", "pcap_flows", ["capture_id"])
    op.create_index("ix_pcap_flows_src_ip", "pcap_flows", ["src_ip"])
    op.create_index("ix_pcap_flows_dst_ip", "pcap_flows", ["dst_ip"])
    op.create_index("ix_pcap_flows_dst_port", "pcap_flows", ["dst_port"])
    op.create_index(
        "ix_pcap_flows_capture_flow",
        "pcap_flows",
        ["capture_id", "src_ip", "dst_ip", "dst_port"],
    )


def downgrade() -> None:
    op.drop_table("pcap_flows")
    op.drop_table("pcap_captures")
    op.drop_table("ingestion_offsets")
    op.drop_table("parser_failures")
    op.drop_table("ingestion_runs")
    op.drop_table("detections")
    op.drop_table("artifacts")
    op.drop_table("sessions")
    op.drop_table("events")
