"""
triage_agent.py

A small log-triage agent that classifies a single log entry as either a
network-intrusion alert (e.g. Snort) or a resource/anomaly alert (e.g.
Netdata), assigns a severity, and returns a strict JSON-serializable
result.

The agent follows an explicit Plan -> Act -> Retrieve -> Check loop:

  PLAN     - decide what signals to look for based on a quick scan of the
             content (does it look like Snort, Netdata, or neither?).
  ACT      - extract evidence: log type, severity signal, and every IP
             address literally present in the text.
  RETRIEVE - before any mitigation is suggested, read the playbook that
             matches the log type (playbooks/snort_playbook.md or
             playbooks/netdata_playbook.md) and extract the section for
             the determined severity. The mitigation text is built only
             from this retrieved excerpt plus evidence from ACT - never
             invented from scratch.
  CHECK    - verify the output before returning it:
               1. every IP address used in the mitigation text actually
                  appeared in the source content (no hallucinated IPs).
               2. the required output keys are present (guardrail).

Two guardrails raise a ValueError instead of guessing:
  - PLAN:     the content decodes with replacement characters or an
              abnormal share of non-printable bytes (corrupted input).
  - RETRIEVE: the matching playbook file, or the section for the
              determined severity within it, cannot be found.

Every call appends a human-readable trace of these phases - including
which playbook (and severity section) was retrieved - to
`ai_interactions.md` in the current working directory.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

LOG_FILE = Path("ai_interactions.md")
PLAYBOOKS_DIR = Path("playbooks")

IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Which playbook file answers for which log_type. "unknown" (a log that
# doesn't match the Snort/Netdata signal keywords, but isn't corrupted
# either - see PLAN's corruption guardrail for that case) falls back to
# the general playbook rather than skipping retrieval entirely.
PLAYBOOK_BY_LOG_TYPE = {
    "network_intrusion": "snort_playbook.md",
    "resource_anomaly": "netdata_playbook.md",
    "unknown": "general_playbook.md",
}

# Each playbook groups its steps under "## Severity: <HEADING>" sections.
SEVERITY_TO_HEADING = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW / UNKNOWN",
    "unknown": "LOW / UNKNOWN",
}

# Keyword signals used during PLAN/ACT to tell the two log families apart.
INTRUSION_SIGNALS = (
    "snort",
    "[**]",
    "classification:",
    "priority:",
    "ttl:",
    "dgmlen:",
    "nmap",
    "brute force",
    "attack",
)

ANOMALY_SIGNALS = (
    "netdata",
    "\"alarm\"",
    "alarm:",
    "anomaly_rate",
    "cpu usage",
    "cpu_usage",
    "mem.available",
    "\"status\"",
)

# Severity keywords, highest-priority match wins.
SEVERITY_RULES = (
    ("critical", ["critical", "priority: 1", "priority:1"]),
    ("high", ["priority: 2", "priority:2", "error"]),
    ("medium", ["warning", "priority: 3", "priority:3"]),
    ("low", ["info", "notice"]),
)


@dataclass
class AgentTrace:
    """Accumulates the Plan/Act/Retrieve/Check narrative for one process_log() call."""

    plan: list[str] = field(default_factory=list)
    act: list[str] = field(default_factory=list)
    retrieve: list[str] = field(default_factory=list)
    check: list[str] = field(default_factory=list)

    def render(self, result: dict[str, Any] | None, error: str | None) -> str:
        ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
        lines = [f"## Run @ {ts}", ""]

        lines.append("### Plan")
        lines.extend(f"- {step}" for step in self.plan)
        lines.append("")

        lines.append("### Act")
        lines.extend(f"- {step}" for step in self.act)
        lines.append("")

        lines.append("### Retrieve")
        lines.extend(f"- {step}" for step in self.retrieve)
        lines.append("")

        lines.append("### Check")
        lines.extend(f"- {step}" for step in self.check)
        lines.append("")

        lines.append("### Outcome")
        if error:
            lines.append(f"- **Guardrail triggered:** {error}")
        else:
            lines.append(f"- Final output: `{json.dumps(result)}`")
        lines.append("")
        lines.append("---")
        lines.append("")
        return "\n".join(lines)


def _log_trace(trace: AgentTrace, result: dict[str, Any] | None, error: str | None) -> None:
    """Append this run's Plan/Act/Check narrative to ai_interactions.md."""
    with LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(trace.render(result, error))


def _detect_corruption(content: str) -> tuple[bool, str]:
    """
    Guardrail check: decide whether content is too garbled to classify
    safely. Triggers on Unicode replacement characters (a sign the bytes
    were not valid UTF-8 and had to be patched by the decoder) or on an
    abnormal share of non-printable characters.
    """
    if not content.strip():
        return True, "content is empty or whitespace-only"

    replacement_count = content.count("�")
    if replacement_count > 0:
        return True, f"{replacement_count} Unicode replacement character(s) found (invalid encoding)"

    allowed_whitespace = {"\n", "\r", "\t", " "}
    non_printable = sum(1 for ch in content if not ch.isprintable() and ch not in allowed_whitespace)
    ratio = non_printable / len(content)
    if ratio > 0.05:
        return True, f"{ratio:.1%} non-printable characters exceeds the corruption threshold"

    return False, ""


def _plan(content: str, trace: AgentTrace) -> dict[str, Any]:
    """PLAN: validate the input, then decide which signal families to look for."""
    is_corrupted, reason = _detect_corruption(content)
    trace.plan.append(
        "Pre-check input integrity: " + (f"FAILED - {reason}." if is_corrupted else "passed.")
    )
    if is_corrupted:
        raise ValueError(
            f"Corrupted or unparseable log content detected ({reason}); "
            "refusing to classify rather than guess from garbled evidence."
        )

    lower = content.lower()
    looks_like_intrusion = any(sig in lower for sig in INTRUSION_SIGNALS)
    looks_like_anomaly = any(sig in lower for sig in ANOMALY_SIGNALS)

    trace.plan.append(f"Received {len(content)} chars of log content.")
    trace.plan.append(
        f"Scanning for intrusion signals ({looks_like_intrusion}) "
        f"and anomaly signals ({looks_like_anomaly})."
    )
    if looks_like_intrusion and not looks_like_anomaly:
        trace.plan.append("Plan: treat as a network-intrusion log; extract IPs and priority.")
    elif looks_like_anomaly and not looks_like_intrusion:
        trace.plan.append("Plan: treat as a resource-anomaly log; extract metric/status fields.")
    elif looks_like_intrusion and looks_like_anomaly:
        trace.plan.append("Plan: mixed signals detected; will classify by signal count.")
    else:
        trace.plan.append("Plan: no reliable signals found; will mark as unknown/corrupted.")

    return {"looks_like_intrusion": looks_like_intrusion, "looks_like_anomaly": looks_like_anomaly}


def _act(content: str, plan_result: dict[str, Any], trace: AgentTrace) -> dict[str, Any]:
    """ACT: extract concrete evidence from the content."""
    lower = content.lower()
    observed_ips = IP_PATTERN.findall(content)
    trace.act.append(f"Extracted IP addresses present in content: {observed_ips or 'none'}.")

    intrusion_hits = sum(sig in lower for sig in INTRUSION_SIGNALS)
    anomaly_hits = sum(sig in lower for sig in ANOMALY_SIGNALS)
    trace.act.append(f"Intrusion signal hits: {intrusion_hits}; anomaly signal hits: {anomaly_hits}.")

    if intrusion_hits == 0 and anomaly_hits == 0:
        log_type = "unknown"
    elif intrusion_hits >= anomaly_hits:
        log_type = "network_intrusion"
    else:
        log_type = "resource_anomaly"
    trace.act.append(f"Determined log_type = '{log_type}'.")

    severity = "unknown"
    for level, keywords in SEVERITY_RULES:
        if any(kw in lower for kw in keywords):
            severity = level
            break
    trace.act.append(f"Determined severity = '{severity}' from keyword match.")

    # Confidence is a simple function of how much usable evidence we found.
    evidence_points = intrusion_hits + anomaly_hits + (1 if observed_ips else 0)
    if log_type == "unknown":
        confidence_score = 0.1
    else:
        confidence_score = round(min(0.5 + 0.08 * evidence_points, 0.98), 2)
    trace.act.append(f"Computed confidence_score = {confidence_score} from {evidence_points} evidence point(s).")

    return {
        "log_type": log_type,
        "severity": severity,
        "confidence_score": confidence_score,
        "observed_ips": observed_ips,
    }


def _extract_section(markdown_text: str, heading_label: str) -> str | None:
    """Pull the body of a '## Severity: <heading_label>' section out of a playbook."""
    start_pattern = re.compile(rf"^## Severity: {re.escape(heading_label)}\s*$", re.MULTILINE)
    start_match = start_pattern.search(markdown_text)
    if not start_match:
        return None

    rest = markdown_text[start_match.end():]
    next_heading = re.search(r"^## ", rest, re.MULTILINE)
    body = rest[: next_heading.start()] if next_heading else rest
    body = body.strip()
    return body or None


def _retrieve(act_result: dict[str, Any], trace: AgentTrace) -> dict[str, Any]:
    """
    RETRIEVE: before any mitigation is composed, read the playbook matching
    this log's type and pull out the section for its determined severity.
    Raises ValueError if the required playbook or section is missing -
    the agent must not fabricate mitigation steps it couldn't retrieve.
    """
    log_type = act_result["log_type"]
    severity = act_result["severity"]

    playbook_name = PLAYBOOK_BY_LOG_TYPE.get(log_type)
    if playbook_name is None:
        trace.retrieve.append(f"No playbook mapped for log_type '{log_type}'; skipping retrieval.")
        return {"playbook_file": None, "excerpt": None}

    playbook_path = PLAYBOOKS_DIR / playbook_name
    trace.retrieve.append(f"Retrieving playbook '{playbook_path}' for log_type '{log_type}'.")

    try:
        playbook_text = playbook_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        trace.retrieve.append(f"FAILED: playbook '{playbook_path}' not found.")
        raise ValueError(
            f"Required playbook '{playbook_path}' is missing; refusing to fabricate mitigation steps."
        )

    heading_label = SEVERITY_TO_HEADING.get(severity, "LOW / UNKNOWN")
    excerpt = _extract_section(playbook_text, heading_label)
    if excerpt is None:
        trace.retrieve.append(
            f"FAILED: no 'Severity: {heading_label}' section found in '{playbook_path}'."
        )
        raise ValueError(
            f"Playbook '{playbook_path}' has no section for severity '{severity}'; "
            "refusing to fabricate mitigation steps."
        )

    trace.retrieve.append(
        f"Retrieved playbook '{playbook_path}', section 'Severity: {heading_label}' "
        f"({len(excerpt)} chars extracted)."
    )
    return {"playbook_file": str(playbook_path), "excerpt": excerpt}


def _build_mitigation(act_result: dict[str, Any], retrieval_result: dict[str, Any]) -> str:
    """Compose a mitigation string from ACT evidence plus the RETRIEVE excerpt."""
    log_type = act_result["log_type"]
    ips = act_result["observed_ips"]
    excerpt = retrieval_result["excerpt"]

    if excerpt is None:
        return "Insufficient or corrupted log data; escalate for manual review before taking action."

    if log_type == "network_intrusion":
        if ips:
            targets = ", ".join(sorted(set(ips)))
            preamble = f"Observed IP address(es) involved: {targets}. "
        else:
            preamble = "No specific IP address was present in the log. "
    else:
        preamble = ""

    return f"{preamble}Per playbook guidance:\n{excerpt}"


def _check(content: str, act_result: dict[str, Any], mitigation: str, trace: AgentTrace) -> None:
    """CHECK: verify no IP address in the mitigation was hallucinated."""
    observed_ips = set(act_result["observed_ips"])
    mitigation_ips = set(IP_PATTERN.findall(mitigation))

    hallucinated = mitigation_ips - observed_ips
    if hallucinated:
        # Defensive: this should be unreachable since _build_mitigation only
        # ever reuses observed_ips, but we verify explicitly as a guardrail.
        trace.check.append(f"FAILED IP verification: {hallucinated} not present in source content.")
        raise ValueError(
            f"Hallucinated IP address(es) detected in mitigation text: {hallucinated}"
        )

    trace.check.append(
        f"Verified every IP in mitigation text ({mitigation_ips or 'none'}) "
        f"is a subset of observed IPs ({observed_ips or 'none'})."
    )
    trace.check.append("IP hallucination check: PASSED.")


def process_log(file_content: str) -> dict[str, Any]:
    """
    Run the Plan-Act-Retrieve-Check agent loop over a single log's content
    and return a dict with 'severity', 'confidence_score', 'mitigation',
    'playbook_file' (the path of the playbook RETRIEVE read to build the
    mitigation, or None when no playbook applies - e.g. log_type
    'unknown'), and 'observed_ips' (the sorted, deduplicated list of IP
    addresses literally present in the log, for external lookups - never
    more than what ACT actually found in the content).

    Raises:
        ValueError: if the content is detected as corrupted/unparseable,
                    if the matching playbook (or its severity section)
                    cannot be retrieved,
                    if the final result is missing 'confidence_score',
                    or if the CHECK phase detects a hallucinated IP.
    """
    trace = AgentTrace()
    result: dict[str, Any] | None = None
    error: str | None = None

    try:
        plan_result = _plan(file_content, trace)
        act_result = _act(file_content, plan_result, trace)

        # RETRIEVE phase: read the matching playbook before composing mitigation.
        retrieval_result = _retrieve(act_result, trace)
        mitigation = _build_mitigation(act_result, retrieval_result)

        # CHECK phase: verify no hallucinated IPs before returning anything.
        _check(file_content, act_result, mitigation, trace)

        result = {
            "severity": act_result["severity"],
            "confidence_score": act_result["confidence_score"],
            "mitigation": mitigation,
            "playbook_file": retrieval_result["playbook_file"],
            "observed_ips": sorted(set(act_result["observed_ips"])),
        }

        # Guardrail: never return a result missing confidence_score.
        if "confidence_score" not in result or result["confidence_score"] is None:
            raise ValueError("Guardrail violation: 'confidence_score' is missing from agent output.")

        trace.check.append("Guardrail check: 'confidence_score' present. PASSED.")
        return result

    except ValueError as exc:
        error = str(exc)
        raise
    finally:
        _log_trace(trace, result, error)


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python triage_agent.py <path-to-log-file>")
        raise SystemExit(1)

    path = Path(sys.argv[1])
    raw = path.read_bytes().decode("utf-8", errors="replace")
    try:
        output = process_log(raw)
    except ValueError as exc:
        print(f"Agent refused to classify this log safely: {exc}")
        raise SystemExit(1)
    print(json.dumps(output, indent=2))
