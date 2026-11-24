"""Stage A baseline detection.

Every rule is a documented, observable heuristic.  The resulting score is a
prioritisation aid only: a high score is not proof that a source is
malicious, and a low score is not proof that it is benign.
"""

from __future__ import annotations

from typing import Any

from deephoney.features.extractor import FEATURE_VERSION, SessionFeatures
from deephoney.schemas.detections import (
    DetectionMethod,
    DetectionResult,
    EvidenceItem,
    risk_level_for_score,
)

RULES_VERSION = "2024.1.0"

RULE_WEIGHTS: dict[str, int] = {
    "DH-R001": 25,
    "DH-R002": 20,
    "DH-R003": 10,
    "DH-R004": 15,
    "DH-R005": 25,
    "DH-R006": 20,
    "DH-R007": 30,
    "DH-R008": 20,
    "DH-R009": 10,
    "DH-R010": 15,
    "DH-R011": 20,
    "DH-R012": 10,
    "DH-R013": 15,
    "DH-R014": 15,
    "DH-R015": 10,
    "DH-R016": 10,
}

_RULE_DEFINITIONS: dict[str, tuple[str, str]] = {
    "DH-R001": (
        "Repeated authentication failures",
        "At least 10 failed authentication attempts were observed in the session.",
    ),
    "DH-R002": (
        "Successful authentication with failures",
        "The session recorded a successful login and at least three failed attempts.",
    ),
    "DH-R003": (
        "Reconnaissance command pattern",
        "The session contains commands commonly used for host or account discovery.",
    ),
    "DH-R004": (
        "File-transfer tooling",
        "The session contains a command associated with downloading or moving files.",
    ),
    "DH-R005": (
        "Persistence-related command",
        "The session contains a command associated with scheduled tasks, services, or SSH keys.",
    ),
    "DH-R006": (
        "Destructive command pattern",
        "The session contains a command associated with destructive host actions.",
    ),
    "DH-R007": (
        "Cryptomining indicators",
        "The session contains strings associated with cryptocurrency mining.",
    ),
    "DH-R008": (
        "Artifact download or capture",
        "The session includes at least one downloaded, offered, or captured artifact.",
    ),
    "DH-R009": (
        "High event volume",
        "The session contains at least 50 normalized events.",
    ),
    "DH-R010": (
        "Multi-service probing",
        "The session contacted at least three distinct destination ports.",
    ),
    "DH-R011": (
        "Executable artifact",
        "A captured or downloaded file has an executable-looking name/type.",
    ),
    "DH-R012": (
        "Rapid activity",
        "The session produced at least ten events per minute.",
    ),
    "DH-R013": (
        "Broad username spraying",
        "The session used at least five distinct usernames.",
    ),
    "DH-R014": (
        "Lateral-movement tooling",
        "The session contains commands associated with remote access or network scanning.",
    ),
    "DH-R015": (
        "Repeated source across sessions",
        "The same source IP appeared in at least three sessions in the comparison window.",
    ),
    "DH-R016": (
        "Successful login with command activity",
        "The session recorded a successful login and shell command activity.",
    ),
}


def evaluate_rules(
    features: SessionFeatures,
    *,
    medium_threshold: int = 25,
    high_threshold: int = 60,
    rules_version: str = RULES_VERSION,
    max_evidence_items: int = 30,
) -> DetectionResult:
    """Evaluate all Stage A rules against one session feature row."""

    hits: list[EvidenceItem] = []
    observed: dict[str, Any] = {
        "event_count": features.event_count,
        "auth_failures": features.auth_failures,
        "auth_successes": features.auth_successes,
        "distinct_usernames": features.distinct_usernames,
        "command_count": features.command_count,
        "download_count": features.download_count,
        "artifact_count": features.artifact_count,
        "distinct_dst_ports": features.distinct_dst_ports,
        "events_per_minute": features.events_per_minute,
        "src_ip_session_count": features.src_ip_session_count,
    }

    def add(rule_id: str, condition: bool, **values: Any) -> None:
        if not condition:
            return
        title, description = _RULE_DEFINITIONS[rule_id]
        hits.append(
            EvidenceItem(
                rule_id=rule_id,
                title=title,
                weight=RULE_WEIGHTS[rule_id],
                description=description,
                observed=dict(values),
            )
        )

    add("DH-R001", features.auth_failures >= 10, failures=features.auth_failures)
    add(
        "DH-R002",
        features.auth_successes >= 1 and features.auth_failures >= 3,
        successes=features.auth_successes,
        failures=features.auth_failures,
    )
    add("DH-R003", features.recon_command_count >= 1, matches=features.recon_command_count)
    add(
        "DH-R004",
        features.file_transfer_command_count >= 1,
        matches=features.file_transfer_command_count,
    )
    add(
        "DH-R005",
        features.persistence_command_count >= 1,
        matches=features.persistence_command_count,
    )
    add(
        "DH-R006",
        features.destructive_command_count >= 1,
        matches=features.destructive_command_count,
    )
    add("DH-R007", features.crypto_command_count >= 1, matches=features.crypto_command_count)
    add(
        "DH-R008",
        features.download_count >= 1 or features.artifact_count >= 1,
        downloads=features.download_count,
        artifacts=features.artifact_count,
    )
    add("DH-R009", features.event_count >= 50, event_count=features.event_count)
    add(
        "DH-R010",
        features.distinct_dst_ports >= 3,
        distinct_dst_ports=features.distinct_dst_ports,
    )
    add(
        "DH-R011",
        features.has_executable_artifact == 1,
        executable_artifact=features.has_executable_artifact,
    )
    add(
        "DH-R012",
        features.events_per_minute >= 10,
        events_per_minute=features.events_per_minute,
    )
    add(
        "DH-R013",
        features.distinct_usernames >= 5,
        distinct_usernames=features.distinct_usernames,
    )
    add(
        "DH-R014",
        features.lateral_command_count >= 1,
        matches=features.lateral_command_count,
    )
    add(
        "DH-R015",
        features.src_ip_session_count >= 3,
        sessions_for_source=features.src_ip_session_count,
    )
    add(
        "DH-R016",
        features.auth_successes >= 1 and features.command_count >= 1,
        successes=features.auth_successes,
        commands=features.command_count,
    )

    raw_score = sum(hit.weight for hit in hits)
    risk_score = min(100, raw_score)
    risk_level = risk_level_for_score(risk_score, medium_threshold, high_threshold)
    displayed = hits[: max(0, max_evidence_items)]

    summary = (
        "No Stage A heuristic fired. This is not evidence of benign intent."
        if not hits
        else "; ".join(hit.title for hit in hits)
    )
    evidence = {
        "summary": summary,
        "rules": [hit.model_dump(mode="json") for hit in displayed],
        "evidence_truncated": len(displayed) < len(hits),
        "raw_weight_sum": raw_score,
        "score_capped": raw_score > 100,
        "observed_facts": observed,
        "feature_version": FEATURE_VERSION,
        "rules_version": rules_version,
        "thresholds": {"medium": medium_threshold, "high": high_threshold},
        "disclaimer": (
            "Rules are transparent heuristics for prioritisation. "
            "They do not prove attribution, intent, or compromise."
        ),
    }

    return DetectionResult(
        session_id=features.session_id,
        source_engine=features.source_engine,
        detection_method=DetectionMethod.RULE,
        model_version=rules_version,
        risk_score=risk_score,
        risk_level=risk_level,
        confidence=None,
        evidence=evidence,
        explanation=None,
    )


__all__ = ["RULE_WEIGHTS", "RULES_VERSION", "evaluate_rules"]
