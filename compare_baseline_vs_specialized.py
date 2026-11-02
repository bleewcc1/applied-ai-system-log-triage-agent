"""
compare_baseline_vs_specialized.py

Runs every sample log in logs/ through BOTH the deterministic baseline
agent (triage_agent.process_log) and the few-shot Chroma + Gemini Flash
agent (specialized_agent.classify_with_llm), and prints a side-by-side
comparison - the "show output measurably differs from baseline"
evidence for the Fine-Tuning/Specialization bonus.

Requires GEMINI_API_KEY to be set and network access. Not part of the
default pytest suite - run it manually:

    export GEMINI_API_KEY="your-key-here"
    python compare_baseline_vs_specialized.py
"""

import json
from pathlib import Path

from triage_agent import process_log
from specialized_agent import classify_with_llm

PROJECT_DIR = Path(__file__).parent

SAMPLE_LOGS = [
    "logs/snort_alert_clean.log",
    "logs/netdata_anomaly_clean.json",
    "logs/snort_alert_high.log",
    "logs/netdata_notice_low.json",
    "logs/generic_app_log.txt",
    "logs/corrupted_log.txt",
]


def main() -> None:
    for relative_path in SAMPLE_LOGS:
        content = (PROJECT_DIR / relative_path).read_bytes().decode("utf-8", errors="replace")
        print("=" * 80)
        print(relative_path)
        print("=" * 80)

        print("\n--- BASELINE (triage_agent.py, rule-based, deterministic) ---")
        try:
            baseline = process_log(content)
            print(json.dumps(baseline, indent=2))
        except ValueError as exc:
            print(f"Safe-fallback error: {exc}")

        print("\n--- SPECIALIZED (specialized_agent.py, Chroma + Gemini Flash) ---")
        try:
            specialized = classify_with_llm(content)
            print(json.dumps(specialized, indent=2))
        except Exception as exc:
            print(f"specialized_agent failed: {exc}")

        print()


if __name__ == "__main__":
    main()
