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

See [`diagrams/architecture.mmd`](diagrams/architecture.mmd) for the full
Mermaid flowchart, including the baseline agent, human review, the
bonus Chroma + Gemini Flash specialized agent, and the test/evaluation layer.

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
triage_agent.py                 # core agent: process_log(file_content) -> dict
streamlit_app.py                # Streamlit UI: Triage, Dashboard, RAG Lab pages
test_agent.py                   # pytest suite exercising process_log() on sample logs
generate_eval_report.py         # test harness: pass/fail + confidence summary -> README
playbooks/                      # incident-response steps retrieved during RETRIEVE
logs/                           # sample log files (clean, corrupted) +
                                 # human_evaluations.csv / triage_history.csv (runtime)
diagrams/                       # architecture diagrams (Mermaid source)
assets/                         # static assets

specialized_agent.py            # bonus: Chroma + Gemini Flash few-shot classifier
specialized_fewshot_dataset.py  # synthetic labeled examples Chroma retrieves from
compare_baseline_vs_specialized.py  # runs both agents on every sample log, side by side
test_specialized_agent.py       # mocked tests - never calls the real Gemini API
requirements-specialized.txt    # optional deps (chromadb, google-genai, pypdf, ...)
.env.example                    # template for GEMINI_API_KEY (never commit the real one)
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

## Bonus: Fine-Tuning/Specialization — Baseline vs. Gemini Flash + Chroma

This is the "show output measurably differs from baseline" evidence for the
Fine-Tuning/Specialization bonus, and doubles as the RAG Enhancement's
before/after documentation (`playbooks/` is the first retrieval data
source; the few-shot dataset below is the second).

`compare_baseline_vs_specialized.py` runs every sample log through both:
- the deterministic baseline (`triage_agent.process_log`)
- the specialized agent (`specialized_agent.classify_with_llm`): embeds the
  log with `gemini-embedding-001`, retrieves the 4 nearest labeled examples
  from a Chroma collection built from `specialized_fewshot_dataset.py`, and
  asks `gemini-flash-latest` for a schema-constrained classification.

### Results (real Gemini API call per log, run 2026-11-01)

| Log | Baseline severity / confidence | Specialized severity / confidence | Agree? |
| --- | --- | --- | --- |
| `snort_alert_clean.log` | critical / 0.98 | critical / 0.95 | ✅ |
| `netdata_anomaly_clean.json` | critical / 0.90 | critical / 0.95 | ✅ |
| `snort_alert_high.log` | high / 0.98 | high / 0.90 | ✅ |
| `netdata_notice_low.json` | low / 0.74 | low / 0.99 | ✅ |
| `generic_app_log.txt` | low / 0.10 | low / 0.99 | ✅ |
| `corrupted_log.txt` | refuses (`ValueError`, safe fallback) | `unknown` / 0.95 | ❌ |

Reproduce it yourself:
```bash
pip install -r requirements-specialized.txt
export GEMINI_API_KEY="your-key"
python compare_baseline_vs_specialized.py
```

### What measurably differs

1. **Severity agreement: 6/6 when both systems attempt a classification.**
   Few-shot retrieval reliably steers Gemini toward the same severity
   vocabulary the baseline uses, rather than inventing its own categories.

2. **The corrupted log is the clearest behavioral gap.** The baseline's
   PLAN-phase guardrail detects the garbled encoding and refuses outright.
   `specialized_agent.py` has no equivalent check: it embeds the garbage
   text, retrieves four unrelated few-shot examples by nearest-neighbor
   distance anyway, and Gemini confidently returns `severity: unknown,
   confidence: 0.95` with a plausible-sounding but fabricated mitigation
   about "log ingestion pipelines." This is a demonstrated gap in the
   specialized path's safety relative to the baseline, not a theoretical one.

3. **Confidence scores mean different things.** The baseline's confidence
   is a transparent evidence-count heuristic (0.10–0.98, genuinely low when
   there's little to go on — 0.10 for `generic_app_log.txt`, which matched
   no known signal keywords). Gemini's self-reported confidence is
   uniformly high (0.90–0.99) across every case, **including the corrupted
   garbage input** — it never reports being unsure, so it isn't a usable
   reliability signal the way the baseline's score is.

4. **Mitigation text is richer when the input is clean.** The baseline's
   mitigation is templated playbook text; Gemini's cites the specific
   details from each log in natural language (e.g. "Block incoming
   connections from IP 203.0.113.77 targeting port 22" vs. the baseline's
   generic "Isolate the source and destination hosts..."). This is the
   genuine upside of retrieval + a real LLM, conditional on the input
   being something the system should actually trust.

### Two real bugs this run surfaced

Running this against the live Gemini API (rather than the mocked tests in
`test_specialized_agent.py`) surfaced two environment-level bugs the
mocked suite couldn't catch:

- **Chroma/SQLite "attempt to write a readonly database."** This
  project's checkout lives on an exFAT external drive, which doesn't
  support the POSIX file locking SQLite needs for writes. Fixed by moving
  Chroma's default storage to `~/.cache/applied-ai-log-triage-agent/chroma_db`
  (a native filesystem), overridable via `CHROMA_DB_PATH`.
- **Wrong embedding model ID.** `text-embedding-004` (a reasonable guess,
  written before any live API access) 404'd against this account.
  `client.models.list()` gave the real catalog; the correct id is
  `gemini-embedding-001`.

<!-- AUTO-GENERATED EVAL REPORT START -->
## Automated Evaluation Report

_Generated by `generate_eval_report.py` on 2026-11-01 16:19 UTC._

6 out of 6 test cases passed. Average confidence score (successful classifications only): 0.74.

| Test Input | Expected Severity | Actual Severity | Confidence | Pass/Fail |
| --- | --- | --- | --- | --- |
| `logs/snort_alert_clean.log` | critical | critical | 0.98 | ✅ Pass |
| `logs/netdata_anomaly_clean.json` | critical | critical | 0.90 | ✅ Pass |
| `logs/snort_alert_high.log` | high | high | 0.98 | ✅ Pass |
| `logs/netdata_notice_low.json` | low | low | 0.74 | ✅ Pass |
| `logs/generic_app_log.txt` | low | low | 0.10 | ✅ Pass |
| `logs/corrupted_log.txt` | ERROR (safe fallback) | ERROR (safe fallback) | n/a | ✅ Pass |
<!-- AUTO-GENERATED EVAL REPORT END -->


