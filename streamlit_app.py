"""
streamlit_app.py

UI for the log-triage agent, with a sidebar navigation panel choosing
between three pages:

  Triage    - upload a log file, hand its content to
              `triage_agent.process_log`, show the resulting severity /
              confidence / mitigation, its Plan/Act/Retrieve/Check
              reasoning trace, and collect a human-in-the-loop
              Approve/Reject decision (logged to logs/human_evaluations.csv).
              The agent runs exactly once per upload: the result and trace
              are cached in st.session_state by Streamlit's file_id, so a
              rerun triggered by an unrelated widget (e.g. the threat-intel
              dropdowns) never re-triages the same file or double-logs it.

  Dashboard - every triage attempt (success or safe-fallback error) is
              logged to logs/triage_history.csv as it happens; this page
              reads that file back and shows upload volume, a severity
              breakdown, and the full history table, alongside the human
              review decisions collected on the Triage page - including an
              AI/human agreement rate, overall and broken down by severity.

  RAG Lab   - the bonus Fine-Tuning/Specialization module (specialized_agent.py),
              split into three modes:
                - Upload Document: runs the extract/chunk/embed/index
                  pipeline on a .txt/.md/.pdf file and reports metrics per
                  stage (timings, chunk stats, embedding dimension).
                - Manage Knowledge Base: list, delete, or clear what's
                  indexed - purely local Chroma operations, no API key
                  needed for this mode.
                - Test Retrieval vs. Baseline: run a log through both the
                  deterministic baseline and the Chroma + Gemini Flash
                  classifier side by side.
              Imports specialized_agent lazily so the Triage/Dashboard
              pages keep working with no extra dependencies required.
"""

import csv
import json
import os
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import streamlit as st

from triage_agent import process_log

HUMAN_EVAL_FILE = Path("logs") / "human_evaluations.csv"
HUMAN_EVAL_FIELDS = ["timestamp", "log_filename", "ai_severity", "human_decision"]

# Public lookup pages for pivoting on an observed IP. No API key required;
# each is just a GUI search URL the analyst opens themselves.
THREAT_INTEL_SERVICES = {
    "VirusTotal": "https://www.virustotal.com/gui/ip-address/{ip}",
    "AbuseIPDB": "https://www.abuseipdb.com/check/{ip}",
    "Shodan": "https://www.shodan.io/host/{ip}",
}

TRIAGE_HISTORY_FILE = Path("logs") / "triage_history.csv"
TRIAGE_HISTORY_FIELDS = ["timestamp", "log_filename", "status", "severity", "confidence_score", "detail"]


def _append_csv_row(path: Path, fieldnames: list[str], row: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    file_is_new = not path.exists()
    with path.open("a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        if file_is_new:
            writer.writeheader()
        writer.writerow(row)


def _save_human_evaluation(log_filename: str, ai_severity: str, human_decision: str) -> None:
    """Append one human-in-the-loop decision to logs/human_evaluations.csv."""
    _append_csv_row(
        HUMAN_EVAL_FILE,
        HUMAN_EVAL_FIELDS,
        {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "log_filename": log_filename,
            "ai_severity": ai_severity,
            "human_decision": human_decision,
        },
    )


def _log_triage_history(log_filename: str, status: str, severity: str | None, confidence_score, detail: str) -> None:
    """Append one triage attempt (success or safe-fallback error) to logs/triage_history.csv."""
    _append_csv_row(
        TRIAGE_HISTORY_FILE,
        TRIAGE_HISTORY_FIELDS,
        {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "log_filename": log_filename,
            "status": status,
            "severity": severity if severity is not None else "",
            "confidence_score": confidence_score if confidence_score is not None else "",
            "detail": detail,
        },
    )


def _load_csv(path: Path, fieldnames: list[str]) -> pd.DataFrame:
    if not path.exists():
        return pd.DataFrame(columns=fieldnames)
    return pd.read_csv(path)


TRACE_FILE = Path("ai_interactions.md")


def _run_triage_with_trace(content: str) -> dict:
    """
    Call process_log() exactly once and capture exactly the Plan/Act/
    Retrieve/Check trace block it appends to ai_interactions.md, by
    diffing the file's size before and after the call. Returns a dict
    the caller can cache in st.session_state, so a later Streamlit rerun
    (e.g. changing the threat-intel dropdowns) never re-runs the agent or
    re-logs the same triage attempt.
    """
    before_size = TRACE_FILE.stat().st_size if TRACE_FILE.exists() else 0
    try:
        result = process_log(content)
    except ValueError as exc:
        appended = TRACE_FILE.read_text(encoding="utf-8")[before_size:].strip()
        return {"status": "error", "result": None, "error": str(exc), "trace": appended}
    else:
        appended = TRACE_FILE.read_text(encoding="utf-8")[before_size:].strip()
        return {"status": "success", "result": result, "error": None, "trace": appended}


st.set_page_config(page_title="Log Triage Agent", page_icon="🛡️")

with st.sidebar:
    st.title("🛡️ Log Triage Agent")
    page = st.radio(
        "Navigate",
        ["🔍 Triage", "📊 Dashboard", "🧬 RAG Lab (Gemini)"],
        label_visibility="collapsed",
    )
    st.markdown("---")
    st.caption(
        "A Plan → Act → Retrieve → Check loop that classifies Snort/Netdata "
        "logs, retrieves the matching playbook, and logs human review "
        "decisions alongside every triage attempt."
    )

st.title(page)

if page == "🔍 Triage":
    st.caption(
        "Upload a Snort intrusion alert or a Netdata anomaly log. The agent runs a "
        "Plan → Act → Retrieve → Check loop and returns a severity, confidence score, "
        "and mitigation recommendation."
    )

    uploaded_file = st.file_uploader("Upload a log file", type=["log", "txt", "json"])

    if uploaded_file is not None:
        raw_bytes = uploaded_file.read()
        content = raw_bytes.decode("utf-8", errors="replace")

        with st.expander("Raw log content"):
            st.text(content)

        # Cache per upload (keyed by Streamlit's own file_id) so a rerun
        # triggered by an unrelated widget - e.g. the threat-intel
        # dropdowns below - never re-runs the agent or double-logs this
        # same upload to triage_history.csv.
        triage_cache = st.session_state.setdefault("triage_cache", {})
        if uploaded_file.file_id not in triage_cache:
            run = _run_triage_with_trace(content)
            if run["status"] == "error":
                _log_triage_history(uploaded_file.name, "error", None, None, run["error"])
            else:
                result = run["result"]
                _log_triage_history(
                    uploaded_file.name,
                    "success",
                    result["severity"],
                    result["confidence_score"],
                    result["mitigation"][:200],
                )
            triage_cache[uploaded_file.file_id] = run

        run = triage_cache[uploaded_file.file_id]

        with st.expander("🧠 Agent reasoning trace (Plan → Act → Retrieve → Check)"):
            st.markdown(run["trace"] if run["trace"] else "_No trace captured._")

        if run["status"] == "error":
            st.error(f"Agent refused to classify this log safely: {run['error']}")
        else:
            result = run["result"]
            severity = result["severity"]
            severity_color = {
                "critical": "red",
                "high": "orange",
                "medium": "blue",
                "low": "green",
                "unknown": "gray",
            }.get(severity, "gray")

            st.markdown(f"### Severity: :{severity_color}[{severity.upper()}]")
            st.metric("Confidence score", f"{result['confidence_score']:.2f}")
            st.markdown("**Mitigation:**")
            st.write(result["mitigation"])

            playbook_file = result.get("playbook_file")
            if playbook_file is not None:
                playbook_path = Path(playbook_file)
                st.download_button(
                    f"⬇️ Download playbook ({playbook_path.name})",
                    data=playbook_path.read_text(encoding="utf-8"),
                    file_name=playbook_path.name,
                    mime="text/markdown",
                    use_container_width=True,
                )

            observed_ips = result.get("observed_ips") or []
            if observed_ips:
                st.markdown("**🔎 Threat intelligence lookup**")
                st.caption(
                    "Pick an IP and a service, then open the lookup in a new tab. "
                    "Only the selected IP address is sent to that service - "
                    "not the rest of the log - and only when you click the button."
                )
                sel_col1, sel_col2 = st.columns(2)
                with sel_col1:
                    selected_ip = st.selectbox("IP address", observed_ips)
                with sel_col2:
                    selected_service = st.selectbox("Service", list(THREAT_INTEL_SERVICES.keys()))

                lookup_url = THREAT_INTEL_SERVICES[selected_service].format(ip=selected_ip)
                st.link_button(
                    f"🔗 Open {selected_ip} on {selected_service} (new tab)",
                    lookup_url,
                    use_container_width=True,
                )

            with st.expander("Raw JSON output"):
                st.code(json.dumps(result, indent=2), language="json")

            st.markdown("---")
            st.markdown("**Human review:** does this assessment look right?")
            col1, col2 = st.columns(2)
            with col1:
                approve_clicked = st.button("✅ Approve Assessment", use_container_width=True)
            with col2:
                reject_clicked = st.button("❌ Reject Assessment", use_container_width=True)

            if approve_clicked or reject_clicked:
                decision = "approved" if approve_clicked else "rejected"
                _save_human_evaluation(uploaded_file.name, result["severity"], decision)
                st.success(f"Feedback saved: '{decision}' recorded for {uploaded_file.name}.")
    else:
        st.info("Waiting for a log file to be uploaded.")

elif page == "📊 Dashboard":
    st.caption("Every file uploaded on the Triage page is logged here as it's processed.")

    history_df = _load_csv(TRIAGE_HISTORY_FILE, TRIAGE_HISTORY_FIELDS)

    if history_df.empty:
        st.info("No files have been triaged yet. Upload one on the Triage page to see it here.")
    else:
        total = len(history_df)
        successes = (history_df["status"] == "success").sum()
        errors = (history_df["status"] == "error").sum()

        c1, c2, c3 = st.columns(3)
        c1.metric("Files triaged", total)
        c2.metric("Classified", int(successes))
        c3.metric("Safe-fallback errors", int(errors))

        severity_counts = (
            history_df.loc[history_df["status"] == "success", "severity"]
            .value_counts()
            .rename("count")
        )
        if not severity_counts.empty:
            st.markdown("**Severity breakdown**")
            st.bar_chart(severity_counts)

        st.markdown("**Triage history**")
        st.dataframe(
            history_df.sort_values("timestamp", ascending=False),
            use_container_width=True,
            hide_index=True,
        )

    st.markdown("---")
    st.markdown("**Human review decisions**")
    human_eval_df = _load_csv(HUMAN_EVAL_FILE, HUMAN_EVAL_FIELDS)
    if human_eval_df.empty:
        st.info("No Approve/Reject decisions recorded yet.")
    else:
        approved = (human_eval_df["human_decision"] == "approved").sum()
        rejected = (human_eval_df["human_decision"] == "rejected").sum()
        total_reviewed = approved + rejected
        agreement_rate = (approved / total_reviewed * 100) if total_reviewed else None

        c1, c2, c3 = st.columns(3)
        c1.metric("Approved", int(approved))
        c2.metric("Rejected", int(rejected))
        c3.metric(
            "AI/human agreement rate",
            f"{agreement_rate:.0f}%" if agreement_rate is not None else "n/a",
        )

        agreement_by_severity = (
            human_eval_df.groupby("ai_severity")["human_decision"]
            .apply(lambda decisions: (decisions == "approved").mean() * 100)
            .rename("agreement_%")
            .sort_values()
        )
        if not agreement_by_severity.empty:
            st.markdown("**Agreement rate by AI severity call**")
            st.caption(
                "Share of human reviews that approved the agent's assessment, "
                "broken down by the severity it assigned. A low bar here "
                "flags a severity level worth tightening up."
            )
            st.bar_chart(agreement_by_severity)

        st.dataframe(
            human_eval_df.sort_values("timestamp", ascending=False),
            use_container_width=True,
            hide_index=True,
        )

elif page == "🧬 RAG Lab (Gemini)":
    st.caption(
        "Bonus Fine-Tuning/Specialization module: a few-shot classifier built on "
        "Chroma (vector retrieval) + Gemini Flash, kept separate from the "
        "deterministic baseline above."
    )

    try:
        import specialized_agent
    except ImportError as exc:
        st.error(
            f"The specialized-agent dependencies aren't installed ({exc}). "
            "Run `pip install -r requirements-specialized.txt` to use this page."
        )
        st.stop()

    rag_mode = st.radio(
        "Mode",
        ["⬆️ Upload Document", "🗂️ Manage Knowledge Base", "🧪 Test Retrieval vs. Baseline"],
        horizontal=True,
    )
    st.markdown("---")

    if rag_mode == "⬆️ Upload Document":
        st.markdown("### ⬆️ Upload a document")
        st.caption(
            "Runs it through the ingestion pipeline - extract → chunk → embed → "
            "index into Chroma - and reports metrics on each stage. Adds to its "
            "own collection, separate from the curated few-shot examples, as a "
            "second retrieval data source for Test Retrieval vs. Baseline."
        )

        if not os.environ.get("GEMINI_API_KEY"):
            st.warning(
                "GEMINI_API_KEY is not set, so documents can't be embedded yet. "
                "Copy `.env.example` to `.env` and fill in a Google AI Studio key, "
                "or `export GEMINI_API_KEY=\"your-key\"` before launching the app."
            )

        uploaded_docs = st.file_uploader(
            "Upload .txt, .md, or .pdf reference documents",
            type=["txt", "md", "pdf"],
            accept_multiple_files=True,
            key="rag_lab_doc_uploader",
        )
        if uploaded_docs and st.button("➕ Run ingestion pipeline", use_container_width=True):
            for doc in uploaded_docs:
                doc_bytes = doc.read()  # raw bytes - add_custom_document handles .pdf vs text internally
                try:
                    metrics = specialized_agent.add_custom_document(doc.name, doc_bytes)
                except RuntimeError as exc:
                    # Missing API key affects every remaining file the same way - stop the batch.
                    st.error(str(exc))
                    break
                except ValueError as exc:
                    # A problem specific to THIS file (corrupted/encrypted/image-only
                    # PDF, etc.) - report it and keep trying the rest of the batch.
                    st.error(f"Could not index '{doc.name}': {exc}")
                    continue

                if metrics["num_chunks"] == 0:
                    st.warning(f"'{doc.name}' produced 0 chunks (empty file) - nothing indexed.")
                    continue

                page_note = f" across {metrics['num_pages']} page(s)" if metrics["num_pages"] else ""
                st.success(f"Indexed '{doc.name}': {metrics['num_chunks']} chunk(s){page_note}.")

                st.markdown(f"**Pipeline metrics — {doc.name}**")
                m1, m2, m3, m4 = st.columns(4)
                m1.metric("Chunks", metrics["num_chunks"])
                m2.metric("Avg chunk size", f"{metrics['avg_chunk_size']:.0f} chars")
                m3.metric("Embedding dim", metrics["embedding_dimension"])
                m4.metric("Total time", f"{metrics['timings_ms']['total']:.0f} ms")

                with st.expander(f"Pipeline stage timings — {doc.name}"):
                    st.dataframe(
                        pd.DataFrame(
                            [
                                {"Stage": "Extraction", "Time (ms)": metrics["timings_ms"]["extraction"]},
                                {"Stage": "Embedding", "Time (ms)": metrics["timings_ms"]["embedding"]},
                                {"Stage": "Chroma insert", "Time (ms)": metrics["timings_ms"]["chroma_insert"]},
                                {"Stage": "Total", "Time (ms)": metrics["timings_ms"]["total"]},
                            ]
                        ),
                        use_container_width=True,
                        hide_index=True,
                    )
                    st.caption(
                        f"{metrics['num_chunks']} chunk(s), {metrics['total_chars']} total characters "
                        f"(min {metrics['min_chunk_size']} / max {metrics['max_chunk_size']} chars per chunk)."
                    )

    elif rag_mode == "🗂️ Manage Knowledge Base":
        st.markdown("### 🗂️ Manage the knowledge base")
        st.caption(
            "Purely local Chroma operations - no Gemini API key or network "
            "access needed to view or delete what's already indexed."
        )

        docs = specialized_agent.list_custom_documents()
        if not docs:
            st.info("Knowledge base is empty. Switch to Upload Document to add reference documents.")
        else:
            c1, c2 = st.columns(2)
            c1.metric("Documents indexed", len(docs))
            c2.metric("Total chunks", sum(d["num_chunks"] for d in docs))
            st.dataframe(pd.DataFrame(docs), use_container_width=True, hide_index=True)

            st.markdown("---")
            filenames = [d["filename"] for d in docs]
            to_delete = st.selectbox("Delete a document", filenames)
            if st.button(f"🗑️ Delete '{to_delete}'", use_container_width=True):
                deleted = specialized_agent.delete_custom_document(to_delete)
                st.success(f"Deleted {deleted} chunk(s) for '{to_delete}'.")
                st.rerun()

            st.markdown("---")
            confirm_clear = st.checkbox("I understand this removes every uploaded document")
            if st.button(
                "⚠️ Clear entire knowledge base", use_container_width=True, disabled=not confirm_clear
            ):
                cleared = specialized_agent.clear_knowledge_base()
                st.success(f"Cleared {cleared} chunk(s). Knowledge base is now empty.")
                st.rerun()

    elif rag_mode == "🧪 Test Retrieval vs. Baseline":
        st.markdown("### 🧪 Test retrieval + Gemini against the baseline")

        if not os.environ.get("GEMINI_API_KEY"):
            st.warning(
                "GEMINI_API_KEY is not set, so this page can't call Gemini yet. "
                "Copy `.env.example` to `.env` and fill in a Google AI Studio key, "
                "or `export GEMINI_API_KEY=\"your-key\"` before launching the app."
            )

        source_choice = st.radio(
            "Log source", ["Pick a sample log", "Paste your own"], horizontal=True
        )
        if source_choice == "Pick a sample log":
            sample_logs = sorted(p.name for p in Path("logs").glob("*") if p.is_file() and not p.name.endswith(".csv"))
            chosen = st.selectbox("Sample log", sample_logs)
            test_content = (Path("logs") / chosen).read_bytes().decode("utf-8", errors="replace") if chosen else ""
            with st.expander("Log content"):
                st.text(test_content)
        else:
            test_content = st.text_area("Paste log content to classify", height=150)

        include_custom_docs = st.checkbox(
            "Include uploaded reference documents in retrieval", value=True
        )

        if st.button("▶️ Run baseline vs. specialized comparison", use_container_width=True) and test_content.strip():
            col_baseline, col_specialized = st.columns(2)

            with col_baseline:
                st.markdown("**Baseline (triage_agent.py)**")
                try:
                    baseline_result = process_log(test_content)
                    st.json(baseline_result)
                except ValueError as exc:
                    st.error(f"Safe-fallback error: {exc}")

            with col_specialized:
                st.markdown("**Specialized (Chroma + Gemini Flash)**")
                try:
                    specialized_result = specialized_agent.classify_with_llm(
                        test_content, include_custom_docs=include_custom_docs
                    )
                except RuntimeError as exc:
                    st.error(str(exc))
                except ValueError as exc:
                    st.error(f"Gemini response rejected: {exc}")
                else:
                    st.json(specialized_result)

                    if specialized_result["few_shot_examples_used"]:
                        st.markdown("**Few-shot examples retrieved:**")
                        st.dataframe(
                            pd.DataFrame(specialized_result["few_shot_examples_used"]),
                            use_container_width=True,
                            hide_index=True,
                        )
                    if specialized_result["custom_docs_used"]:
                        st.markdown("**Custom document context retrieved:**")
                        st.dataframe(
                            pd.DataFrame(specialized_result["custom_docs_used"]),
                            use_container_width=True,
                            hide_index=True,
                        )
