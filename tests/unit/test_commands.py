"""Unit tests for command categorisation."""

from __future__ import annotations

from deephoney.features.commands import (
    COMMAND_CATEGORIES,
    classify_command,
    classify_commands,
)


def test_recon_commands() -> None:
    assert "recon" in classify_command("uname -a")
    assert "recon" in classify_command("cat /etc/passwd")
    assert classify_command("") == frozenset()
    assert classify_command(None) == frozenset()


def test_high_signal_categories() -> None:
    assert "file_transfer" in classify_command("wget http://example.invalid/x")
    assert "persistence" in classify_command("crontab -e")
    assert "destructive" in classify_command("rm -rf /tmp/demo")
    assert "crypto" in classify_command("xmrig --donate-level 1")
    assert "lateral" in classify_command("nmap 192.0.2.10")
    assert "privilege" in classify_command("sudo -l")
    assert "shell_utility" in classify_command("python3 -c 'print(1)'")


def test_a_command_can_match_multiple_categories() -> None:
    categories = classify_command("busybox wget http://example.invalid/x")
    assert {"file_transfer", "shell_utility"} <= categories


def test_classify_commands_counts_incidences() -> None:
    counts = classify_commands(["id", "wget x", "wget y", None])
    assert counts["recon"] == 1
    assert counts["file_transfer"] == 2
    assert set(counts) == set(COMMAND_CATEGORIES)
