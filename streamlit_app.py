"""
streamlit_app.py

UI for the log-triage agent, with a sidebar navigation panel choosing
between five pages:

  Baseline Triage               - upload a log file, hand its content to
                                  `triage_agent.process_log`, show the resulting severity /
                                  confidence / mitigation, its Plan/Act/Retrieve/Check
                                  reasoning trace, threat intelligence lookup, and collect
                                  a human-in-the-loop Approve/Reject decision (logged to
                                  logs/human_evaluations.csv).

  Specialized (Chroma + Gemini) - few-shot vector retrieval + Gemini Flash classifier with
                                  custom document citations, full JSON output, threat intel,
                                  and human evaluation review.

  Test Retrieval vs. Baseline   - side-by-side comparison running any log through BOTH the
                                  deterministic baseline and the Specialized agent,
                                  with agreement metrics and confidence comparison.

  RAG Knowledge Base            - three modes for managing reference documents:
                                    - Upload Document: extract/chunk/embed/index pipeline.
                                    - Manage Knowledge Base: inspect, delete, or clear Chroma.
                                    - Chat with Knowledge Base: conversational Q&A citing
                                      uploaded reference documents.

  Dashboard                     - historical triage attempts, severity breakdown, and
                                  human/AI agreement rate analytics.
"""

import csv
import json
import os
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import streamlit as st

from triage_agent import IP_PATTERN, process_log

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

# Extensions accepted by every log-upload widget. All are plain text under
# the hood (decoded as UTF-8 with errors="replace"), so the agent doesn't
# care which one it's handed - this list is just the file-picker filter.
LOG_UPLOAD_TYPES = ["log", "txt", "json", "csv", "tsv", "md", "out", "conf", "cfg"]


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
        [
            "🔍 Baseline Triage",
            "🧬 Specialized (Chroma + Gemini Flash)",
            "🧪 Test Retrieval vs. Baseline",
            "📚 RAG Knowledge Base",
            "📊 Dashboard",
        ],
        label_visibility="collapsed",
    )
    st.markdown("---")
    st.caption(
        "A dual-agent log triage suite featuring a deterministic "
        "Plan → Act → Retrieve → Check baseline and a Chroma + Gemini Flash "
        "specialized classifier with RAG and human evaluation logging."
    )
    with st.expander("📖 Menu Overview & Guide"):
        st.markdown(
            "**🔍 Baseline Triage:** Deterministic Plan → Act → Retrieve → Check classifier with zero external dependencies and auditable traces.\n\n"
            "**🧬 Specialized Agent:** Few-shot LLM triage using Chroma vector retrieval + Gemini Flash with RAG document citations.\n\n"
            "**🧪 Test vs. Baseline:** Head-to-head comparison evaluating severity agreement, confidence calibration, and guardrail behavior.\n\n"
            "**📚 RAG Knowledge Base:** Upload `.txt`/`.md`/`.pdf` reference docs, inspect Chroma collections, and chat directly with your runbooks.\n\n"
            "**📊 Dashboard:** Operational triage metrics, severity distribution, and human-in-the-loop approval analytics."
        )

st.title(page)

if page in ("🔍 Baseline Triage", "🔍 Triage"):
    st.caption(
        "Upload a Snort intrusion alert or a Netdata anomaly log. The agent runs a "
        "Plan → Act → Retrieve → Check loop and returns a severity, confidence score, "
        "and mitigation recommendation."
    )

    with st.expander("📖 User Guide: Baseline Triage", expanded=False):
        st.markdown(
            """
            ### What This Menu Does
            Provides **fast, 100% deterministic, zero-hallucination log triage** using a transparent
            **Plan → Act → Retrieve → Check** agent loop. Operates completely locally without requiring an API key.

            ---
            ### How the Agent Works:
            1. **PLAN:** Validates UTF-8 encoding integrity. If more than 5% non-printable characters or replacement characters are detected, the agent safely refuses to classify (controlled `ValueError` safe fallback).
            2. **ACT:** Scans for signature keywords (Snort alerts vs. Netdata resource alarms), extracts all observed IPv4 addresses, determines incident severity (`critical`, `high`, `medium`, `low`, `unknown`), and calculates an evidence-grounded confidence score.
            3. **RETRIEVE:** Pulls the exact severity section from vetted local playbooks (`playbooks/snort_playbook.md`, `netdata_playbook.md`, or `general_playbook.md`). Mitigations are built strictly from retrieved text—never invented.
            4. **CHECK:** Enforces an anti-hallucination verification ensuring no IP address in the mitigation text was fabricated (`mitigation_ips - observed_ips == ∅`).

            ---
            ### Step-by-Step Instructions:
            1. **Upload a Log:** Drag & drop any `.log`, `.txt`, `.json`, `.csv`, `.tsv`, `.md`, `.out`, `.conf`, or `.cfg` file (sample logs are located in the `logs/` directory).
            2. **Review Reasoning Trace:** Open the **🧠 Agent reasoning trace** expander to inspect the full audit trail written to `ai_interactions.md`.
            3. **Inspect Output:** Review the color-coded severity badge, confidence score, and actionable mitigation procedure.
            4. **Download Playbook:** Click the download button to export the full incident playbook for the incident type.
            5. **Threat Intelligence Pivot:** For logs containing observed IP addresses, pick an IP and launch a search on VirusTotal, AbuseIPDB, or Shodan.
            6. **Human Review Sign-off:** Click **✅ Approve Assessment** or **❌ Reject Assessment** to record your decision into `logs/human_evaluations.csv`.
            """
        )

    uploaded_file = st.file_uploader("Upload a log file", type=LOG_UPLOAD_TYPES)

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

    with st.expander("📖 User Guide: Operational Dashboard", expanded=False):
        st.markdown(
            """
            ### What This Menu Does
            Provides **high-level operational observability** into all triage activities, tracking processed incident volumes,
            severity breakdowns, safe-fallback error frequencies, and **human-in-the-loop (HITL) agreement rates**.

            ---
            ### Metrics & Visualizations:
            - **Triage Volume:** Counts total processed logs, successful classifications, and controlled safe-fallback refusals (from `logs/triage_history.csv`).
            - **Severity Distribution:** Bar chart showing the operational volume of `critical`, `high`, `medium`, `low`, and `unknown` events.
            - **Human Review Analytics:** Aggregates human analyst **Approved** vs. **Rejected** decisions (from `logs/human_evaluations.csv`).
            - **Agreement Rate by AI Severity:** Visualizes analyst alignment per severity level. A lower approval rate on a specific tier (e.g. `medium`) flags heuristic or prompt areas needing tuning.
            - **Audit Log Tables:** Interactive, timestamped tables recording full incident histories and analyst sign-offs for SOC auditing.
            """
        )

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

elif page in ("📚 RAG Knowledge Base", "🧬 RAG Lab (Gemini)"):
    st.caption(
        "Upload reference documents (.txt, .md, .pdf), inspect and manage "
        "your Chroma vector store, or chat directly with your knowledge base."
    )

    with st.expander("📖 User Guide: RAG Knowledge Base", expanded=False):
        st.markdown(
            """
            ### What This Menu Does
            Enables **Retrieval-Augmented Generation (RAG)** by indexing technical manuals, internal runbooks,
            and compliance standards (e.g. NIST guidelines) into a dedicated Chroma vector collection (`custom_uploaded_docs`).

            ---
            ### Sub-Mode Instructions:
            1. **⬆️ Upload Document:**
               - **Supported formats:** `.txt`, `.md`, and `.pdf` files.
               - **Ingestion Pipeline:** Uses `pypdf` for page-aware extraction, applies paragraph-aware chunking (up to 1,500 characters with 200-character overlap), embeds text via `gemini-embedding-001` (batched in sets of 100 at 768 dimensions), and writes vectors into Chroma.
               - **Metrics:** Review extraction, embedding, and insertion timings, chunk distributions, and embedding dimensions upon completion.
            2. **🗂️ Manage Knowledge Base:**
               - **Zero-API-key Operations:** View all indexed documents, inspect chunk/page counts, delete individual files, or reset the collection. Operates purely locally on the Chroma vector store.
            3. **💬 Chat with Knowledge Base:**
               - **Conversational Grounding:** Ask natural-language questions (e.g., *"What does NIST SP 800-94 recommend for isolating compromised web servers?"*).
               - **Strict Attribution:** Gemini Flash retrieves the top-$k$ relevant chunks and formulates an answer citing the specific source document and page number.
            """
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
        ["⬆️ Upload Document", "🗂️ Manage Knowledge Base", "💬 Chat with Knowledge Base"],
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

    elif rag_mode == "💬 Chat with Knowledge Base":
        st.markdown("### 💬 Chat with Knowledge Base")
        st.caption(
            "Ask natural-language questions against your uploaded reference documents. "
            "Gemini embeds the question, retrieves the most relevant excerpts from Chroma, "
            "and generates an answer citing the specific document name and page number."
        )

        if not os.environ.get("GEMINI_API_KEY"):
            st.warning(
                "GEMINI_API_KEY is not set, so the chat cannot query Gemini yet. "
                "Copy `.env.example` to `.env` and fill in a Google AI Studio key, "
                "or `export GEMINI_API_KEY=\"your-key\"` before launching the app."
            )

        docs = specialized_agent.list_custom_documents()
        if not docs:
            st.info(
                "ℹ️ The knowledge base is currently empty. Switch to the **Upload Document** "
                "tab to upload and index documents (.txt, .md, or .pdf) first."
            )
        else:
            with st.expander(f"📚 Available Reference Documents ({len(docs)} files indexed)"):
                st.dataframe(pd.DataFrame(docs), use_container_width=True, hide_index=True)

            top_bar_col1, top_bar_col2 = st.columns([3, 1])
            with top_bar_col1:
                retrieval_k = st.slider(
                    "Number of reference chunks to retrieve (k)", min_value=1, max_value=8, value=4
                )
            with top_bar_col2:
                st.write("")
                if st.button("🧹 Clear Chat", use_container_width=True):
                    st.session_state["kb_chat_history"] = []
                    st.rerun()

            chat_history = st.session_state.setdefault("kb_chat_history", [])

            # Render message history
            for msg in chat_history:
                with st.chat_message(msg["role"]):
                    st.markdown(msg["content"])
                    if msg.get("sources"):
                        with st.expander("🔎 View retrieved sources"):
                            for idx, src in enumerate(msg["sources"], start=1):
                                citation = (
                                    f"{src['filename']}, page {src['page_number']}"
                                    if src.get("page_number")
                                    else src["filename"]
                                )
                                st.markdown(f"**Source {idx}: [{citation}]** (distance: `{src['distance']}`)")
                                st.text(src["text"])

            # Chat input
            if prompt := st.chat_input("Ask a question about your uploaded documents (e.g. NIST guidelines, runbooks)..."):
                chat_history.append({"role": "user", "content": prompt})
                with st.chat_message("user"):
                    st.markdown(prompt)

                with st.chat_message("assistant"):
                    with st.spinner("⏳ Searching knowledge base & generating answer with Gemini Flash..."):
                        try:
                            qa_result = specialized_agent.query_knowledge_base(
                                query=prompt,
                                k=retrieval_k,
                                chat_history=chat_history[:-1],
                            )
                            answer = qa_result["answer"]
                            sources = qa_result.get("sources", [])

                            st.markdown(answer)
                            if sources:
                                with st.expander("🔎 View retrieved sources"):
                                    for idx, src in enumerate(sources, start=1):
                                        citation = (
                                            f"{src['filename']}, page {src['page_number']}"
                                            if src.get("page_number")
                                            else src["filename"]
                                        )
                                        st.markdown(f"**Source {idx}: [{citation}]** (distance: `{src['distance']}`)")
                                        st.text(src["text"])

                            chat_history.append(
                                {
                                    "role": "assistant",
                                    "content": answer,
                                    "sources": sources,
                                }
                            )
                        except (RuntimeError, ValueError) as exc:
                            st.error(str(exc))

elif page == "🧬 Specialized (Chroma + Gemini Flash)":
    st.caption(
        "Classify security and ops logs using few-shot vector retrieval in Chroma "
        "and Google Gemini Flash (`gemini-flash-latest`), with optional reference document "
        "grounding from your uploaded knowledge base."
    )

    with st.expander("📖 User Guide: Specialized Agent (Gemini Flash + Chroma)", expanded=False):
        st.markdown(
            """
            ### What This Menu Does
            Delivers **rich, context-aware AI incident triage** by combining semantic similarity search across labeled few-shot examples
            with Gemini Flash inference, constrained by a strict JSON schema.

            ---
            ### Architecture Highlights:
            - **Vector Retrieval:** The incoming log is embedded using `gemini-embedding-001` (at 768 dimensions) and matched against 18 curated few-shot intrusion/anomaly examples in Chroma (`log_fewshot_examples`).
            - **RAG Reference Grounding:** If enabled, relevant excerpts from your uploaded custom knowledge base documents are dynamically attached into the prompt context.
            - **Structured Schema Constraint:** Output is strictly constrained to Pydantic enums (`TriageResult`), guaranteeing that severities never drift outside the canonical vocabulary (`critical`, `high`, `medium`, `low`, `unknown`).
            - **Post-Generation Safety:** Automatically validates that the model has not invented non-existent IP addresses in the mitigation text.

            ---
            ### Step-by-Step Instructions:
            1. **Select Input Mode:**
               - **Pick a sample log:** Choose from curated fixtures (defaults to clean Snort alert).
               - **Upload log file:** Provide your own `.log`, `.json`, or `.txt` file.
               - **Paste log text:** Directly paste unstructured log lines.
            2. **Configure RAG Grounding:** Toggle the checkbox to include or exclude custom uploaded knowledge base documents.
            3. **Run Triage:** Click **▶️ Run Specialized Triage**.
            4. **Review Context & Citations:**
               - Review the **🎯 Retrieved Few-Shot Examples** to see which labeled training cases guided the model.
               - Review the **📚 Retrieved Reference Document Citations** to see exact document and page sources.
            5. **Record Feedback:** Submit your **Approve** or **Reject** evaluation to log your feedback for SOC quality control.
            """
        )

    try:
        import specialized_agent
    except ImportError as exc:
        st.error(
            f"The specialized-agent dependencies aren't installed ({exc}). "
            "Run `pip install -r requirements-specialized.txt` to use this page."
        )
        st.stop()

    if not os.environ.get("GEMINI_API_KEY"):
        st.warning(
            "GEMINI_API_KEY is not set, so this page can't call Gemini yet. "
            "Copy `.env.example` to `.env` and fill in a Google AI Studio key, "
            "or `export GEMINI_API_KEY=\"your-key\"` before launching the app."
        )

    source_choice = st.radio(
        "Log source", ["Pick a sample log", "Upload log file", "Paste log text"], horizontal=True
    )
    test_content = ""
    source_filename = "custom_log.txt"

    if source_choice == "Pick a sample log":
        log_extensions = {".log", ".json", ".txt"}
        sample_logs = sorted(
            p.name for p in Path("logs").glob("*")
            if p.is_file() and not p.name.startswith(".") and p.suffix.lower() in log_extensions
        )
        default_index = (
            sample_logs.index("snort_alert_clean.log")
            if "snort_alert_clean.log" in sample_logs
            else 0
        )
        chosen = st.selectbox("Sample log", sample_logs, index=default_index)
        source_filename = chosen or "sample_log.txt"
        test_content = (Path("logs") / chosen).read_bytes().decode("utf-8", errors="replace") if chosen else ""
        with st.expander("Raw log content"):
            st.text(test_content)
    elif source_choice == "Upload log file":
        uploaded_log = st.file_uploader(
            "Upload a log file", type=LOG_UPLOAD_TYPES, key="specialized_file_uploader"
        )
        if uploaded_log is not None:
            source_filename = uploaded_log.name
            test_content = uploaded_log.read().decode("utf-8", errors="replace")
            with st.expander("Raw log content"):
                st.text(test_content)
    else:
        test_content = st.text_area("Paste log content to classify", height=150)

    include_custom_docs = st.checkbox(
        "Include uploaded reference documents in retrieval (RAG)", value=True
    )

    if st.button("▶️ Run Specialized Triage", use_container_width=True) and test_content.strip():
        with st.spinner("⏳ Embedding log, querying Chroma, and generating with Gemini Flash..."):
            try:
                specialized_result = specialized_agent.classify_with_llm(
                    test_content, include_custom_docs=include_custom_docs
                )
            except RuntimeError as exc:
                st.error(str(exc))
            except ValueError as exc:
                if "Corrupted or unparseable" in str(exc):
                    st.warning(f"🛡️ Guardrail triggered (Safe fallback):\n\n{exc}")
                else:
                    st.error(f"Post-generation check failed: {exc}")
            else:
                sev = specialized_result["severity"]
                color = {
                    "critical": "red",
                    "high": "orange",
                    "medium": "blue",
                    "low": "green",
                    "unknown": "gray",
                }.get(sev, "gray")
                st.markdown(f"### Severity: :{color}[{sev.upper()}]")
                st.metric("Confidence score", f"{specialized_result['confidence_score']:.2f}")
                st.markdown("**Mitigation:**")
                st.write(specialized_result["mitigation"])

                if specialized_result["few_shot_examples_used"]:
                    with st.expander("🎯 Retrieved Few-Shot Examples"):
                        st.dataframe(
                            pd.DataFrame(specialized_result["few_shot_examples_used"]),
                            use_container_width=True,
                            hide_index=True,
                        )
                if specialized_result["custom_docs_used"]:
                    with st.expander("📚 Retrieved Reference Document Citations"):
                        st.dataframe(
                            pd.DataFrame(specialized_result["custom_docs_used"]),
                            use_container_width=True,
                            hide_index=True,
                        )

                with st.expander("📤 Complete JSON Response"):
                    st.json(specialized_result)

                observed_ips = sorted(set(IP_PATTERN.findall(test_content)))
                if observed_ips:
                    st.markdown("**🔎 Threat intelligence lookup**")
                    st.caption("Pivots on IPs observed in the source log:")
                    sel_col1, sel_col2 = st.columns(2)
                    with sel_col1:
                        selected_ip = st.selectbox("Observed IP", observed_ips, key="spec_ip")
                    with sel_col2:
                        selected_svc = st.selectbox(
                            "Lookup service", list(THREAT_INTEL_SERVICES.keys()), key="spec_svc"
                        )
                    url_template = THREAT_INTEL_SERVICES[selected_svc]
                    lookup_url = url_template.format(ip=selected_ip)
                    st.link_button(
                        f"🌐 Open {selected_svc} for {selected_ip}",
                        lookup_url,
                        use_container_width=True,
                    )

                st.markdown("---")
                st.markdown("#### Human Review")
                btn_c1, btn_c2 = st.columns(2)
                with btn_c1:
                    if st.button("✅ Approve Assessment", use_container_width=True, key="spec_approve"):
                        _save_human_evaluation(source_filename, sev, "approved")
                        st.success("Recorded: Approved")
                with btn_c2:
                    if st.button("❌ Reject Assessment", use_container_width=True, key="spec_reject"):
                        _save_human_evaluation(source_filename, sev, "rejected")
                        st.error("Recorded: Rejected")

elif page == "🧪 Test Retrieval vs. Baseline":
    st.caption(
        "Run any log through BOTH the deterministic baseline (`triage_agent.py`) and "
        "the Chroma + Gemini Flash agent side-by-side to compare severities, confidence "
        "calibrations, mitigations, and guardrail behaviors."
    )

    with st.expander("📖 User Guide: Head-to-Head Comparison", expanded=False):
        st.markdown(
            """
            ### What This Menu Does
            Provides a **side-by-side comparative benchmark** running any input log through both the
            **deterministic baseline agent** and the **Chroma + Gemini Flash agent** simultaneously.

            ---
            ### Why Compare Both Agents?
            1. **Severity Consistency:** Verify if semantic vector retrieval guides the LLM to the exact same incident severity as the deterministic rule-based baseline.
            2. **Confidence Calibration Contrast:** Notice how the baseline's confidence reflects literal evidence counts (0.10 for ambiguous logs up to 0.98 for clean alerts), while Gemini self-reports near-constant high confidence (0.90–0.99).
            3. **Guardrail Divergence:** Testing `corrupted_log.txt` demonstrates how both agents enforce pre-flight integrity checks to safely refuse garbled inputs rather than hallucinating plausible rationales.
            4. **Mitigation Quality:** Contrast templated runbook procedures against context-aware, tailored natural language instructions.

            ---
            ### Step-by-Step Instructions:
            1. **Choose a Test Input:** Select one of the pre-loaded fixtures (`snort_alert_clean.log`, `netdata_anomaly_clean.json`, `corrupted_log.txt`), upload a file, or paste raw text.
            2. **Toggle Reference Grounding:** Decide whether custom uploaded knowledge base documents should be retrieved into Gemini's prompt.
            3. **Run Comparison:** Click **▶️ Run Baseline vs. Specialized Comparison**.
            4. **Inspect Side-by-Side Cards:** Symmetrically compare JSON structures, extracted severities, and confidence ratings.
            5. **Check Agreement Banner:** Review the automated **Side-by-Side Assessment Summary** banner showing exact agreement status and confidence score comparisons.
            6. **Examine Centered Grounding Evidence:** Scroll to the bottom to inspect all retrieved few-shot training examples and custom document citations centered across the screen.
            """
        )

    try:
        import specialized_agent
    except ImportError as exc:
        st.error(
            f"The specialized-agent dependencies aren't installed ({exc}). "
            "Run `pip install -r requirements-specialized.txt` to use this page."
        )
        st.stop()

    if not os.environ.get("GEMINI_API_KEY"):
        st.warning(
            "GEMINI_API_KEY is not set, so this page can't call Gemini yet. "
            "Copy `.env.example` to `.env` and fill in a Google AI Studio key, "
            "or `export GEMINI_API_KEY=\"your-key\"` before launching the app."
        )

    source_choice = st.radio(
        "Log source", ["Pick a sample log", "Upload log file", "Paste log text"], horizontal=True, key="comp_src"
    )
    test_content = ""

    if source_choice == "Pick a sample log":
        log_extensions = {".log", ".json", ".txt"}
        sample_logs = sorted(
            p.name for p in Path("logs").glob("*")
            if p.is_file() and not p.name.startswith(".") and p.suffix.lower() in log_extensions
        )
        default_index = (
            sample_logs.index("snort_alert_clean.log")
            if "snort_alert_clean.log" in sample_logs
            else 0
        )
        chosen = st.selectbox("Sample log", sample_logs, index=default_index, key="comp_sample")
        test_content = (Path("logs") / chosen).read_bytes().decode("utf-8", errors="replace") if chosen else ""
        with st.expander("Raw log content"):
            st.text(test_content)
    elif source_choice == "Upload log file":
        uploaded_log = st.file_uploader(
            "Upload a log file", type=LOG_UPLOAD_TYPES, key="comp_file_uploader"
        )
        if uploaded_log is not None:
            test_content = uploaded_log.read().decode("utf-8", errors="replace")
            with st.expander("Raw log content"):
                st.text(test_content)
    else:
        test_content = st.text_area("Paste log content to classify", height=150, key="comp_paste")

    include_custom_docs = st.checkbox(
        "Include uploaded reference documents in retrieval (RAG)", value=True, key="comp_rag"
    )

    if st.button("▶️ Run Baseline vs. Specialized Comparison", use_container_width=True) and test_content.strip():
        col_baseline, col_specialized = st.columns(2)
        baseline_result = None
        specialized_result = None

        with col_baseline:
            st.markdown("**Baseline (triage_agent.py)**")
            try:
                baseline_result = process_log(test_content)
                st.json(baseline_result)
            except ValueError as exc:
                st.warning(f"🛡️ Guardrail triggered (Safe fallback):\n\n{exc}")

        with col_specialized:
            st.markdown("**Specialized (Chroma + Gemini Flash)**")
            with st.spinner("⏳ Embedding log, querying Chroma, and generating with Gemini Flash..."):
                try:
                    specialized_result = specialized_agent.classify_with_llm(
                        test_content, include_custom_docs=include_custom_docs
                    )
                except RuntimeError as exc:
                    st.error(str(exc))
                except ValueError as exc:
                    if "Corrupted or unparseable" in str(exc):
                        st.warning(f"🛡️ Guardrail triggered (Safe fallback):\n\n{exc}")
                    else:
                        st.error(f"Post-generation check failed: {exc}")
                else:
                    st.json(specialized_result)

        # Summary comparison metrics if both agents completed
        if baseline_result and specialized_result:
            st.markdown("---")
            st.markdown("### 📊 Side-by-Side Assessment Summary")
            b_sev = baseline_result["severity"].lower()
            s_sev = specialized_result["severity"].lower()
            if b_sev == s_sev:
                st.success(f"✅ **Severity Agreement:** Both agents classified this log as **{b_sev.upper()}**.")
            else:
                st.info(f"⚖️ **Severity Divergence:** Baseline assigned **{b_sev.upper()}**, while Specialized assigned **{s_sev.upper()}**.")

            metric_col1, metric_col2 = st.columns(2)
            metric_col1.metric("Baseline Confidence", f"{baseline_result['confidence_score']:.2f}")
            metric_col2.metric("Specialized Confidence", f"{specialized_result['confidence_score']:.2f}")

        # Centered evidence review for retrieved few-shot and custom documents
        if specialized_result:
            few_shots = specialized_result.get("few_shot_examples_used")
            custom_docs = specialized_result.get("custom_docs_used")

            if few_shots or custom_docs:
                st.markdown("---")
                st.markdown("### 🔎 Retrieval Evidence & Grounding Review")

                if few_shots:
                    st.markdown("**Few-shot examples retrieved:**")
                    st.dataframe(
                        pd.DataFrame(few_shots),
                        use_container_width=True,
                        hide_index=True,
                    )

                if custom_docs:
                    st.markdown("**Custom document context retrieved:**")
                    st.dataframe(
                        pd.DataFrame(custom_docs),
                        use_container_width=True,
                        hide_index=True,
                    )
