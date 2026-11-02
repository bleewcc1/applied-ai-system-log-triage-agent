# System Architecture Diagram

This document contains the visual Mermaid architecture diagram for the Log Triage Agent, illustrating data flow from ingestion through the baseline agent, specialized LLM agent, Chroma vector retrieval, and human-in-the-loop evaluation.

```mermaid
flowchart TD
    subgraph INPUT["📥 INPUT"]
        A["User uploads a log file\n(Snort alert or Netdata alarm)"]
    end

    A --> B["Streamlit App\ndecode bytes to text (utf-8, errors='replace')"]

    subgraph AGENT["🤖 BASELINE AGENT — triage_agent.process_log() : Plan → Act → Retrieve → Check"]
        direction TB
        PLAN["PLAN\ncorruption guardrail check,\nscan for intrusion vs. anomaly signals"]
        ACT["ACT\nextract IP addresses, classify log_type,\ndetermine severity, compute confidence_score"]
        RETRIEVER["RETRIEVER\nread the matching playbook\n(snort/netdata/general_playbook.md),\nextract the section for this severity"]
        CHECK["CHECK\nverify no IP in the mitigation was\nhallucinated; verify confidence_score\nis present (guardrail)"]
        PLAN --> ACT --> RETRIEVER --> CHECK
    end

    B --> PLAN
    CHECK -->|guardrail fails| ERR["Safe-fallback ValueError\nno result invented - raised, not guessed"]
    CHECK -->|guardrail passes| OUT["📤 Baseline OUTPUT — JSON\nseverity, confidence_score, mitigation,\nplaybook_file, observed_ips"]

    OUT --> UI["Streamlit UI renders the result\n(severity badge, confidence metric,\nmitigation, playbook download,\nthreat-intel lookup links)"]
    ERR --> UIERR["Streamlit UI renders the error\n(st.error - agent refused to guess)"]

    subgraph HUMAN["🧑‍💻 HUMAN REVIEW — in the Streamlit app"]
        direction TB
        REVIEW["Analyst clicks\n✅ Approve  or  ❌ Reject"]
        HUMANCSV[("logs/human_evaluations.csv\ntimestamp, filename, ai_severity,\nhuman_decision")]
        REVIEW --> HUMANCSV
    end

    UI --> REVIEW

    subgraph SPECIALIZED["🧬 SPECIALIZED AGENT (bonus) — specialized_agent.classify_with_llm() : Embed → Retrieve → Generate"]
        direction TB
        EMBED["EMBED\nembed log text\n(gemini-embedding-001)"]
        RETRIEVE2["RETRIEVE\nquery Chroma: k nearest few-shot\nexamples + uploaded custom docs"]
        GENERATE["GENERATE\nfew-shot prompt -> gemini-flash-latest\nresponse_schema-constrained JSON"]
        EMBED --> RETRIEVE2 --> GENERATE
    end

    subgraph VECTORDB["🗄️ Chroma vector store (~/.cache/.../chroma_db)"]
        direction TB
        FEWSHOT[("log_fewshot_examples\n18 synthetic labeled examples")]
        CUSTOMDOCS[("custom_uploaded_docs\nuser-uploaded .txt/.md/.pdf,\nparagraph-chunked, page-cited")]
    end

    UPLOAD["RAG Knowledge Base menu:\nupload .txt/.md/.pdf reference docs"] --> ADDDOC["add_custom_document()\nextract (pypdf for PDFs) + chunk + embed"]
    ADDDOC --> CUSTOMDOCS
    RETRIEVE2 -.-> FEWSHOT
    RETRIEVE2 -.-> CUSTOMDOCS

    GENERATE --> SPECOUT["📤 Specialized OUTPUT — JSON\nseverity, confidence_score, mitigation,\nfew_shot_examples_used, custom_docs_used"]

    B -. "Test vs. Baseline menu: same log also sent to" .-> EMBED
    OUT -. "compared side by side in" .-> COMPARE["Test Retrieval vs. Baseline menu /\ncompare_baseline_vs_specialized.py"]
    SPECOUT -. "compared side by side in" .-> COMPARE

    subgraph EVAL["🧪 EVALUATOR / TESTER — automated checks on both agents"]
        direction TB
        PYTEST["test_agent.py (pytest)\nclean logs -> valid JSON;\ncorrupted log -> safe-fallback error,\nnever a crash"]
        SPECTEST["test_specialized_agent.py (pytest)\nGemini + Chroma fully mocked -\nnever makes a real API call"]
        HISTORYCSV[("logs/triage_history.csv\nevery triage attempt, success or error")]
        DASHBOARD["Dashboard tab\nseverity breakdown,\nAI/human agreement rate\noverall and by severity"]
        HISTORYCSV --> DASHBOARD
        HUMANCSV --> DASHBOARD
    end

    PYTEST -. "runs against" .-> AGENT
    SPECTEST -. "runs against (mocked)" .-> SPECIALIZED
    OUT -. "every attempt logged" .-> HISTORYCSV
    ERR -. "every attempt logged" .-> HISTORYCSV
```

