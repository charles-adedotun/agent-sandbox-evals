"""Unit tests for Layer 1 Sanitized MCP Harness security filters."""

from pathlib import Path
from agent_sandbox_evals.harnesses.layer1_sanitized import SanitizedMCPHarness


def test_sanitizer_blocks_privileged_binaries(tmp_path: Path):
    harness = SanitizedMCPHarness()
    allowed, rule, reason = harness.inspect_and_filter("sudo -n whoami", tmp_path)
    assert not allowed
    assert rule == "BINARY_BLOCKLIST_GUARD"


def test_sanitizer_blocks_ssrf_metadata_and_lan(tmp_path: Path):
    harness = SanitizedMCPHarness()

    # AWS metadata
    allowed, rule, _ = harness.inspect_and_filter("curl http://169.254.169.254/latest/meta-data/", tmp_path)
    assert not allowed
    assert "SSRF" in rule

    # GCP metadata
    allowed, rule, _ = harness.inspect_and_filter("curl http://metadata.google.internal/computeMetadata/v1/", tmp_path)
    assert not allowed
    assert "SSRF" in rule

    # Private LAN
    allowed, rule, _ = harness.inspect_and_filter("curl http://192.168.1.1/", tmp_path)
    assert not allowed
    assert "SSRF" in rule

    # Loopback
    allowed, rule, _ = harness.inspect_and_filter("curl http://127.0.0.1:6379/", tmp_path)
    assert not allowed
    assert "SSRF" in rule


def test_sanitizer_blocks_path_traversal(tmp_path: Path):
    harness = SanitizedMCPHarness()
    allowed, rule, _ = harness.inspect_and_filter("cat ../../.ssh/id_rsa", tmp_path)
    assert not allowed
    assert "PATH" in rule


def test_sanitizer_allows_benign_commands(tmp_path: Path):
    harness = SanitizedMCPHarness()
    allowed, _, _ = harness.inspect_and_filter("python3 -c 'print(\"hello world\")'", tmp_path)
    assert allowed
