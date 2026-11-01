# Log Triage Agent

A small agentic tool that classifies a single security/ops log as either a
**network intrusion** (e.g. Snort) or a **resource anomaly** (e.g. Netdata),
assigns a severity and confidence score, and recommends a mitigation —
via a transparent Plan → Act → Retrieve → Check loop, with a Streamlit UI
and a human-in-the-loop approval step on top.

## Architecture Overview

```
User (browser)
      │ uploads a log file
      ▼
Streamlit App (streamlit_app.py)
      │ decodes bytes to text (utf-8, errors="replace")
      ▼
triage_agent.process_log(content)
      │
      ├─ PLAN      corruption guardrail check, then scan for
      │            intrusion vs. anomaly signal keywords
      │
      ├─ ACT       extract IP addresses, classify log_type,
      │            determine severity, compute confidence_score
      │
      ├─ RETRIEVE  read the matching playbook (playbooks/snort_playbook.md
      │            or playbooks/netdata_playbook.md) and extract the
      │            section for the determined severity; the mitigation
      │            is built only from this excerpt, never invented
      │
      └─ CHECK     verify no IP in the mitigation text was
                   hallucinated; verify confidence_score is present
      │
      ▼
JSON output: { "severity", "confidence_score", "mitigation" }
      │
      ▼
Streamlit App renders the result (or a safe error if a guardrail
rejected the log) and asks the user to Approve or Reject it
      │
      ▼
Human decision appended to logs/human_evaluations.csv
```

See [`diagrams/architecture.mmd`](diagrams/architecture.mmd) for the
Mermaid flowchart of the data flow (note: predates the Retrieve step and
the human-in-the-loop feedback buttons added since).

Every call to `process_log()` also appends a human-readable trace of its
Plan/Act/Retrieve/Check reasoning — including which playbook and severity
section were retrieved — to `ai_interactions.md`, so each classification
is auditable after the fact.

### Human-in-the-loop feedback

After a log is classified, the Streamlit app shows **✅ Approve Assessment**
and **❌ Reject Assessment** buttons. Clicking either appends a row (log
filename, the agent's severity, the human decision, and a timestamp) to
`logs/human_evaluations.csv`, which is created on first use.

### Project structure

```
triage_agent.py     # core agent: process_log(file_content) -> dict
streamlit_app.py    # Streamlit UI wrapping process_log() + HITL feedback
test_agent.py       # pytest suite exercising process_log() on sample logs
playbooks/          # incident-response steps retrieved during RETRIEVE
logs/               # sample log files (clean, corrupted) +
                     # human_evaluations.csv (written at runtime)
diagrams/           # architecture diagrams (Mermaid source)
assets/             # static assets
```

## Setup Instructions

```bash
# From the project root
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Running the tests

```bash
python -m pytest test_agent.py -v
```

This verifies that:
- the clean Snort log (`logs/snort_alert_clean.log`) and the clean Netdata
  log (`logs/netdata_anomaly_clean.json`) both return valid, JSON-serializable
  output with `severity`, `confidence_score`, and `mitigation`.
- the corrupted log (`logs/corrupted_log.txt`) triggers a controlled
  `ValueError` (the safe fallback) instead of crashing.

## Running the Streamlit app

```bash
streamlit run streamlit_app.py
```

Then open the local URL Streamlit prints (typically `http://localhost:8501`),
upload one of the sample files in `logs/`, and use the Approve/Reject
buttons under the result to record your feedback.

## Sample interactions

**Input:** `logs/snort_alert_clean.log` (Snort fast-alert format, includes an
Nmap scan alert and an SSH brute-force alert, both `Priority: 1`)

**Output:**
```json
{
  "severity": "critical",
  "confidence_score": 0.98,
  "mitigation": "Observed IP address(es) involved: 10.0.0.15, 192.168.1.50, 203.0.113.77. Per playbook guidance:\n1. Isolate the source and destination hosts from the network immediately\n   (disable switch port or apply a host-level block).\n2. Block the offending IP address(es) at the perimeter firewall.\n3. Preserve a packet capture and the Snort alert log for forensic review —\n   do not rotate or delete logs covering the incident window.\n4. Escalate to the on-call security lead within 15 minutes.\n5. Begin a timeline of lateral-movement indicators (auth logs, new\n   processes, outbound connections) on the affected host."
}
```

---

**Input:** `logs/netdata_anomaly_clean.json` (Netdata CPU-usage alarm,
`"status": "CRITICAL"`, 97.4% utilization)

**Output:**
```json
{
  "severity": "critical",
  "confidence_score": 0.9,
  "mitigation": "Per playbook guidance:\n1. Check the affected host's current CPU, memory, disk I/O, and load\n   average immediately.\n2. Determine whether the resource exhaustion is caused by a runaway\n   process, a traffic spike, or a stuck job, and identify the top\n   consumer.\n3. Scale out (add capacity) or fail over to a standby instance if the\n   service is customer-facing and degraded.\n4. Restart the offending process/service only after capturing diagnostic\n   data (stack dump, logs) if a restart is required to restore service.\n5. Notify the on-call engineer within 15 minutes if the host is\n   production-critical."
}
```
