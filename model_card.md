# Model Card: Log Triage Agent

## Overview

- **What it does:** Classifies incoming system logs as either network intrusions (e.g., Snort alerts) or resource/system anomalies (e.g., Netdata alarms), assigns an incident severity rating (`critical`, `high`, `medium`, `low`, or `unknown`), computes a confidence rating, and produces an actionable, grounded mitigation recommendation. The baseline agent operates via a deterministic Plan → Act → Retrieve → Check cycle, while an optional specialized agent enhances this using Chroma vector retrieval (few-shot examples and indexed PDF/text runbooks) paired with Gemini Flash.
- **Intended users:** Tier 1 and Tier 2 Security Operations Center (SOC) analysts, Site Reliability Engineers (SREs), and incident response trainees.
- **Intended use cases:** Rapid triage of high-volume log streams, initial indicator of compromise (IOC) extraction, standardized playbook retrieval, and serving as a decision-support copilot where human operators review and approve assessments before taking operational action.

## Limitations

**What are the limitations or biases in your system?**

- **Heuristic rigidity in the baseline:** The core baseline agent relies on static keyword matching (`INTRUSION_SIGNALS`, `ANOMALY_SIGNALS`, and priority markers). It struggles with novel log schemas, unstructured application logs, or adversarial log tampering where known keywords are absent or obfuscated.
- **Log format coverage:** The system was specifically developed and evaluated against Snort fast-alert and Netdata JSON alarm formats. It has not been benchmarked on Windows Event Logs (EVTX), cloud audit trails (AWS CloudTrail, GCP Cloud Audit Logs), or complex multi-line container crash dumps.
- **Single-log context window:** The agent currently evaluates one log entry in isolation. It cannot correlate distributed multi-stage attacks across time, trace lateral movement across multiple hosts, or evaluate chronic operational degradation over days.
- **LLM overconfidence:** In the specialized Gemini path, the model's self-reported confidence score is poorly calibrated. Gemini consistently reports confidence between 0.90 and 0.99 even when presented with ambiguous or generic logs where the baseline appropriately drops confidence to 0.10.
- **Scale and throughput:** The current architecture uses synchronous in-process file parsing and local SQLite-backed Chroma storage, making it suited for exploratory and interactive analysis rather than multi-gigabyte real-time event streaming pipelines.

## Misuse Prevention

**Could your AI be misused, and how would you prevent that?**

- **Risk of autonomous execution:** If connected directly to firewall APIs (e.g., automated `iptables` or cloud security group blocks), false positives or hallucinated IP addresses could accidentally isolate critical infrastructure or lock out authorized users.
  - *Prevention:* The system enforces a strict Human-In-The-Loop (HITL) approval gate in the UI. No mitigation action can execute autonomously; all classifications require analyst review and explicit sign-off, which is audited in `logs/human_evaluations.csv`.
- **Hallucinated IOC prevention:** Generative models often fabricate plausible-looking IP addresses when summarizing security incidents.
  - *Prevention:* The CHECK phase validates that every IP address mentioned in the mitigation text is a strict subset of the IP addresses literally extracted during the ACT phase (`mitigation_ips - observed_ips == set()`). If any foreign IP is detected, the agent raises a `ValueError` rather than serving the recommendation.
- **Input integrity guardrail:** Adversarial attackers or degraded networks can feed malformed, non-UTF-8, or binary payloads into log pipelines.
  - *Prevention:* The pre-flight corruption guardrail (`_detect_corruption`) scans for Unicode replacement characters (`\ufffd`) and calculates the ratio of non-printable bytes. If the corruption threshold (>5%) is breached, the agent safely refuses to classify the input.
- **Required confidence scoring:** A strict schema guardrail rejects any agent output that fails to provide a bounded confidence score, preventing downstream systems from mistaking low-certainty guesses for definitive classifications.

## Reliability Surprises

**What surprised you while testing your AI's reliability?**

- **The corrupted log behavioral divergence:** The starkest contrast between the baseline and the specialized LLM agent occurred on `logs/corrupted_log.txt`. The baseline's Plan-phase guardrail immediately caught the garbage characters and threw a controlled `ValueError` (the intended safe fallback). In contrast, prior to porting the corruption guardrail into the specialized agent, Gemini embedded the garbled bytes, retrieved nearest neighbors from Chroma, and returned `severity: unknown` with a **0.95 confidence score** and a completely fabricated mitigation recommending "repairs to the log ingestion pipeline." This demonstrated that LLMs will confidently rationalize garbage input unless bounded by explicit pre-flight validation.
- **Confidence score meaning:** In the baseline agent, confidence is a transparent, evidence-grounded heuristic tied to the number of corroborating indicators and IP matches (0.10 for generic logs up to 0.98 for high-fidelity alerts). Gemini's self-reported confidence was uniformly near 1.0 across all inputs, showing that model self-assessment cannot be relied upon as an operational metric without external calibration.
- **Storage and model environment bugs:** When testing against live APIs rather than mocked fixtures, two subtle operational failures emerged: Chroma's SQLite backend failed on exFAT external drives due to lack of POSIX advisory file locking (requiring moving Chroma storage to `~/.cache`), and standard model naming conventions differed from the live catalog (requiring `gemini-embedding-001` over `text-embedding-004`).

## AI Collaboration

**Describe your collaboration with AI during this project. Identify one suggestion you accepted and one you did not accept as written, and say why you rejected or changed it.**

- **Accepted Suggestion:**
  - *Adopting the Plan → Act → Retrieve → Check loop with Pydantic schema validation:* Structuring the workflow into distinct phases with intermediate state tracing in `ai_interactions.md` dramatically improved observability. Using Pydantic's `Literal` enum for severities (`critical`, `high`, `medium`, `low`, `unknown`) within `response_schema` forced the LLM to adhere strictly to the baseline's category vocabulary, preventing schema drift.

- **Revised / Rejected Suggestion:**
  - *Allowing the LLM to freely synthesize mitigation steps from broad general knowledge:* An early AI recommendation proposed letting Gemini generate comprehensive, tailored incident response recommendations using its training data.
  - *Why it was rejected and revised:* In security operations, ungrounded advice poses severe operational risk (e.g., suggesting outdated containment commands, recommending disruptive service reboots, or inventing attacker IP addresses). This approach was rejected in favor of strict RAG: the baseline agent is restricted to extracting excerpts from vetted runbooks (`playbooks/*.md`), and the specialized agent was retrofitted with the baseline's anti-hallucination IP verification check to ensure no invented indicators of compromise could reach the analyst.
