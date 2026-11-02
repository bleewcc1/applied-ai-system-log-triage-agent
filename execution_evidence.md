# Reproducible Execution Evidence

This document provides reproducible command outputs, interaction logs, test harness reports, and agent traces demonstrating the operational correctness of the **Log Triage Agent**.

---

## 1. Automated Evaluation Harness Output

Command:
```bash
python generate_eval_report.py
```

Output:
```
6 out of 6 test cases passed.
Average confidence score (successful classifications only): 0.74

  [PASS] logs/snort_alert_clean.log          expected=critical               actual=critical               confidence=0.98
  [PASS] logs/netdata_anomaly_clean.json     expected=critical               actual=critical               confidence=0.90
  [PASS] logs/snort_alert_high.log           expected=high                   actual=high                   confidence=0.98
  [PASS] logs/netdata_notice_low.json        expected=low                    actual=low                    confidence=0.74
  [PASS] logs/generic_app_log.txt            expected=low                    actual=low                    confidence=0.10
  [PASS] logs/corrupted_log.txt              expected=ERROR (safe fallback)  actual=ERROR (safe fallback)  confidence=n/a

README.md updated with the Automated Evaluation Report section.
```

---

## 2. Unit & Integration Test Suite (`pytest`)

Command:
```bash
pytest -v
```

Output:
```
============================= test session starts ==============================
platform darwin -- Python 3.11.6, pytest-9.2.0, pluggy-1.7.0
rootdir: /Volumes/T7Shield/CodePath/AppliedAI/AI110/applied-ai-system-log-triage-agent
plugins: anyio-4.16.0
collected 58 items

test_agent.py::test_snort_intrusion_log_returns_valid_json PASSED        [  1%]
test_agent.py::test_netdata_anomaly_log_returns_valid_json PASSED        [  3%]
test_agent.py::test_corrupted_log_triggers_safe_fallback_error_not_a_crash PASSED [  5%]
test_agent.py::test_corrupted_log_trace_is_still_written PASSED          [  6%]
test_specialized_agent.py::test_missing_api_key_raises_runtime_error_before_any_network_call PASSED [  8%]
test_specialized_agent.py::test_add_custom_document_missing_api_key_raises_runtime_error PASSED [ 10%]
test_specialized_agent.py::test_embed_texts_sends_one_request_when_under_the_batch_limit PASSED [ 12%]
test_specialized_agent.py::test_embed_texts_splits_into_multiple_requests_over_the_batch_limit PASSED [ 13%]
test_specialized_agent.py::test_embed_texts_handles_exact_multiple_of_batch_limit PASSED [ 15%]
test_specialized_agent.py::test_build_prompt_includes_examples_and_new_log_content PASSED [ 17%]
test_specialized_agent.py::test_build_prompt_omits_custom_docs_section_when_none_retrieved PASSED [ 18%]
test_specialized_agent.py::test_build_prompt_includes_custom_docs_section_when_present PASSED [ 20%]
test_specialized_agent.py::test_build_prompt_cites_page_number_for_pdf_custom_docs PASSED [ 22%]
test_specialized_agent.py::test_add_custom_document_chunks_and_embeds_into_its_own_collection PASSED [ 24%]
test_specialized_agent.py::test_add_custom_document_empty_text_adds_nothing PASSED [ 25%]
test_specialized_agent.py::test_add_custom_document_pdf_extracts_per_page_with_page_numbers PASSED [ 27%]
test_specialized_agent.py::test_extract_pdf_pages_real_extraction_from_minimal_pdf PASSED [ 29%]
test_specialized_agent.py::test_extract_pdf_pages_raises_value_error_for_corrupted_bytes PASSED [ 31%]
test_specialized_agent.py::test_extract_document_chunks_raises_value_error_for_image_only_pdf PASSED [ 32%]
test_specialized_agent.py::test_add_custom_document_corrupted_pdf_raises_value_error_not_a_crash PASSED [ 34%]
test_specialized_agent.py::test_extract_document_chunks_reports_num_pages_for_pdf PASSED [ 36%]
test_specialized_agent.py::test_extract_document_chunks_num_pages_none_for_text PASSED [ 37%]
test_specialized_agent.py::test_chunk_paragraphs_keeps_short_text_as_one_chunk PASSED [ 39%]
test_specialized_agent.py::test_chunk_paragraphs_splits_when_paragraphs_exceed_chunk_size PASSED [ 41%]
test_specialized_agent.py::test_chunk_paragraphs_falls_back_to_fixed_size_for_oversized_paragraph PASSED [ 43%]
test_specialized_agent.py::test_chunk_paragraphs_empty_text_returns_no_chunks PASSED [ 44%]
test_specialized_agent.py::test_list_custom_documents_empty_when_nothing_uploaded PASSED [ 46%]
test_specialized_agent.py::test_list_custom_documents_groups_by_filename_with_type_and_pages PASSED [ 48%]
test_specialized_agent.py::test_delete_custom_document_removes_only_matching_chunks PASSED [ 50%]
test_specialized_agent.py::test_delete_custom_document_unknown_filename_deletes_nothing PASSED [ 51%]
test_specialized_agent.py::test_clear_knowledge_base_removes_everything_and_returns_count PASSED [ 53%]
test_specialized_agent.py::test_clear_knowledge_base_empty_returns_zero PASSED [ 55%]
test_specialized_agent.py::test_retrieve_custom_doc_context_empty_when_nothing_uploaded PASSED [ 56%]
test_specialized_agent.py::test_retrieve_custom_doc_context_returns_matches_when_populated PASSED [ 58%]
test_specialized_agent.py::test_classify_with_llm_include_custom_docs_false_skips_custom_collection_entirely PASSED [ 60%]
test_specialized_agent.py::test_classify_with_llm_include_custom_docs_true_uses_custom_collection PASSED [ 62%]
test_specialized_agent.py::test_classify_with_llm_reuses_cached_client_and_chroma_client_across_calls PASSED [ 63%]
test_specialized_agent.py::test_retrieve_few_shot_formats_chroma_query_result PASSED [ 65%]
test_specialized_agent.py::test_get_or_build_collection_embeds_and_adds_dataset_when_empty PASSED [ 67%]
test_specialized_agent.py::test_get_or_build_collection_skips_rebuild_when_already_populated PASSED [ 68%]
test_specialized_agent.py::test_classify_with_llm_success_returns_expected_shape PASSED [ 70%]
test_specialized_agent.py::test_classify_with_llm_out_of_range_confidence_raises_value_error PASSED [ 72%]
test_specialized_agent.py::test_classify_with_llm_malformed_response_raises_value_error PASSED [ 74%]
test_specialized_agent.py::test_classify_with_llm_corrupted_content_refuses_before_any_network_call PASSED [ 75%]
test_specialized_agent.py::test_classify_with_llm_clean_content_passes_corruption_guard PASSED [ 77%]
test_specialized_agent.py::test_classify_with_llm_hallucinated_ip_in_mitigation_raises_value_error PASSED [ 79%]
test_specialized_agent.py::test_classify_with_llm_mitigation_ips_matching_log_pass_the_check PASSED [ 81%]
test_specialized_agent.py::test_triage_result_rejects_out_of_vocabulary_severity PASSED [ 82%]
test_specialized_agent.py::test_triage_result_accepts_each_canonical_severity PASSED [ 84%]
test_specialized_agent.py::test_embed_texts_requests_configured_output_dimensionality PASSED [ 86%]
test_specialized_agent.py::test_get_or_build_collection_rebuilds_when_stored_dimension_differs PASSED [ 87%]
test_specialized_agent.py::test_get_or_build_collection_keeps_collection_when_dimension_matches PASSED [ 89%]
test_specialized_agent.py::test_add_custom_document_dimension_mismatch_raises_clear_error_without_deleting PASSED [ 91%]
test_specialized_agent.py::test_query_knowledge_base_missing_api_key_raises_runtime_error PASSED [ 93%]
test_specialized_agent.py::test_query_knowledge_base_empty_query_raises_value_error PASSED [ 94%]
test_specialized_agent.py::test_query_knowledge_base_empty_kb_raises_value_error PASSED [ 96%]
test_specialized_agent.py::test_query_knowledge_base_success_returns_answer_and_sources PASSED [ 98%]
test_specialized_agent.py::test_query_knowledge_base_includes_prior_chat_history_in_prompt PASSED [100%]

============================== 58 passed in 1.15s ==============================
```

---

## 3. Direct CLI Command Executions

### Case A: Clean Snort Intrusion Alert
Command:
```bash
python triage_agent.py logs/snort_alert_clean.log
```

Output:
```json
{
  "severity": "critical",
  "confidence_score": 0.98,
  "mitigation": "Observed IP address(es) involved: 10.0.0.15, 192.168.1.50, 203.0.113.77. Per playbook guidance:\n1. Isolate the source and destination hosts from the network immediately\n   (disable switch port or apply a host-level block).\n2. Block the offending IP address(es) at the perimeter firewall.\n3. Preserve a packet capture and the Snort alert log for forensic review —\n   do not rotate or delete logs covering the incident window.\n4. Escalate to the on-call security lead within 15 minutes.\n5. Begin a timeline of lateral-movement indicators (auth logs, new\n   processes, outbound connections) on the affected host.",
  "playbook_file": "playbooks/snort_playbook.md",
  "observed_ips": [
    "10.0.0.15",
    "192.168.1.50",
    "203.0.113.77"
  ]
}
```

### Case B: Clean Netdata Anomaly Alarm
Command:
```bash
python triage_agent.py logs/netdata_anomaly_clean.json
```

Output:
```json
{
  "severity": "critical",
  "confidence_score": 0.9,
  "mitigation": "Per playbook guidance:\n1. Check the affected host's current CPU, memory, disk I/O, and load\n   average immediately.\n2. Determine whether the resource exhaustion is caused by a runaway\n   process, a traffic spike, or a stuck job, and identify the top\n   consumer.\n3. Scale out (add capacity) or fail over to a standby instance if the\n   service is customer-facing and degraded.\n4. Restart the offending process/service only after capturing diagnostic\n   data (stack dump, logs) if a restart is required to restore service.\n5. Notify the on-call engineer within 15 minutes if the host is\n   production-critical.",
  "playbook_file": "playbooks/netdata_playbook.md",
  "observed_ips": []
}
```

### Case C: Corrupted Log (Integrity Guardrail Trigger)
Command:
```bash
python triage_agent.py logs/corrupted_log.txt
```

Output (Exit Code: 1):
```
Agent refused to classify this log safely: Corrupted or unparseable log content detected (15 Unicode replacement character(s) found (invalid encoding)); refusing to classify rather than guess from garbled evidence.
```

---

## 4. Agent Reasoning Trace Log Sample (`ai_interactions.md`)

Each run of `triage_agent.process_log()` appends its full Plan → Act → Retrieve → Check audit trace:

```markdown
## Run @ 2026-11-01T16:19:31+00:00

### Plan
- Pre-check input integrity: passed.
- Received 645 chars of log content.
- Scanning for intrusion signals (True) and anomaly signals (False).
- Plan: treat as a network-intrusion log; extract IPs and priority.

### Act
- Extracted IP addresses present in content: ['192.168.1.50', '10.0.0.15', '203.0.113.77', '10.0.0.15'].
- Intrusion signal hits: 8; anomaly signal hits: 0.
- Determined log_type = 'network_intrusion'.
- Determined severity = 'critical' from keyword match.
- Computed confidence_score = 0.98 from 9 evidence point(s).

### Retrieve
- Retrieving playbook 'playbooks/snort_playbook.md' for log_type 'network_intrusion'.
- Retrieved playbook 'playbooks/snort_playbook.md', section 'Severity: CRITICAL' (513 chars extracted).

### Check
- Verified every IP in mitigation text ({'203.0.113.77', '192.168.1.50', '10.0.0.15'}) is a subset of observed IPs ({'203.0.113.77', '192.168.1.50', '10.0.0.15'}).
- IP hallucination check: PASSED.
- Guardrail check: 'confidence_score' present. PASSED.

### Outcome
- Final output: `{"severity": "critical", "confidence_score": 0.98, "mitigation": "Observed IP address(es) involved: 10.0.0.15, 192.168.1.50, 203.0.113.77. Per playbook guidance:\n1. Isolate the source and destination hosts from the network immediately\n   (disable switch port or apply a host-level block).\n2. Block the offending IP address(es) at the perimeter firewall.\n3. Preserve a packet capture and the Snort alert log for forensic review —\n   do not rotate or delete logs covering the incident window.\n4. Escalate to the on-call security lead within 15 minutes.\n5. Begin a timeline of lateral-movement indicators (auth logs, new\n   processes, outbound connections) on the affected host.", "playbook_file": "playbooks/snort_playbook.md", "observed_ips": ["10.0.0.15", "192.168.1.50", "203.0.113.77"]}`
---
```

---

## 5. Human Evaluation Audit Trail (`logs/human_evaluations.csv`)

```csv
timestamp,log_filename,ai_severity,human_decision
2026-11-01T01:16:32+00:00,snort_alert_clean.log,critical,approved
2026-11-01T01:16:41+00:00,netdata_anomaly_clean.json,critical,approved
2026-11-01T10:45:12+00:00,snort_alert_high.log,high,approved
```

---

## 6. Baseline vs. Specialized Benchmark Summary Table

| Test Log Fixture | Baseline Severity / Confidence | Specialized (Chroma + Gemini) Severity / Confidence | Severity Agreement | Guardrail Behavior |
| :--- | :--- | :--- | :---: | :--- |
| `snort_alert_clean.log` | `critical` / 0.98 | `critical` / 0.95 | ✅ Match | Both identify SSH brute-force & Nmap probes |
| `netdata_anomaly_clean.json` | `critical` / 0.90 | `critical` / 0.95 | ✅ Match | Both identify 97.4% CPU exhaustion |
| `snort_alert_high.log` | `high` / 0.98 | `high` / 0.90 | ✅ Match | Both flag Priority: 2 scan activity |
| `netdata_notice_low.json` | `low` / 0.74 | `low` / 0.99 | ✅ Match | Both categorize notice alert as low |
| `generic_app_log.txt` | `low` / 0.10 | `low` / 0.99 | ✅ Match | Baseline reflects 0.10 low evidence score |
| `corrupted_log.txt` | Refuses (`ValueError`) | Refuses (`ValueError`) | ✅ Match | Pre-flight guardrail prevents garbage ingestion |

