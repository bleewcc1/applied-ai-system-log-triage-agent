"""
test_agent.py

Exercises triage_agent.process_log() against the three sample logs in
logs/:
  - a clean Snort intrusion alert       -> must return valid JSON
  - a clean Netdata resource anomaly    -> must return valid JSON
  - a corrupted/garbled text file       -> must raise a controlled
                                            ValueError (safe fallback),
                                            never crash with an
                                            unhandled exception.
"""

import json
from pathlib import Path

import pytest

from triage_agent import process_log

LOGS_DIR = Path(__file__).parent / "logs"
REQUIRED_KEYS = {"severity", "confidence_score", "mitigation"}


def _read_log(filename: str) -> str:
    """Read a log file the same way triage_agent.py's CLI entrypoint does."""
    return (LOGS_DIR / filename).read_bytes().decode("utf-8", errors="replace")


def _assert_valid_result(result: dict) -> None:
    assert isinstance(result, dict)
    assert REQUIRED_KEYS.issubset(result.keys())
    assert isinstance(result["severity"], str) and result["severity"]
    assert isinstance(result["confidence_score"], (int, float))
    assert 0.0 <= result["confidence_score"] <= 1.0
    assert isinstance(result["mitigation"], str) and result["mitigation"]
    # Must be strictly JSON-serializable, as required by the spec.
    serialized = json.dumps(result)
    assert json.loads(serialized) == result


def test_snort_intrusion_log_returns_valid_json():
    content = _read_log("snort_alert_clean.log")
    result = process_log(content)
    _assert_valid_result(result)
    assert result["severity"] == "critical"  # "Priority: 1" appears in the sample
    assert "192.168.1.50" in result["mitigation"] or "203.0.113.77" in result["mitigation"]


def test_netdata_anomaly_log_returns_valid_json():
    content = _read_log("netdata_anomaly_clean.json")
    result = process_log(content)
    _assert_valid_result(result)
    # The sample's "status": "CRITICAL" should drive severity classification.
    assert result["severity"] == "critical"


def test_corrupted_log_triggers_safe_fallback_error_not_a_crash():
    content = _read_log("corrupted_log.txt")
    # A controlled ValueError is the "safe fallback" - the agent explicitly
    # refuses to guess at garbled evidence. Any other exception type here
    # would mean the corruption guardrail didn't catch it and the function
    # crashed instead.
    with pytest.raises(ValueError, match="Corrupted or unparseable"):
        process_log(content)


def test_corrupted_log_trace_is_still_written(tmp_path, monkeypatch):
    """Even on the guardrail path, the Plan/Act/Check trace must be logged."""
    monkeypatch.chdir(tmp_path)
    content = _read_log("corrupted_log.txt")
    with pytest.raises(ValueError):
        process_log(content)
    trace_file = tmp_path / "ai_interactions.md"
    assert trace_file.exists()
    assert "Guardrail triggered" in trace_file.read_text(encoding="utf-8")
