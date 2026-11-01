"""
specialized_agent.py

Bonus "Fine-Tuning / Specialization" module: a few-shot-constrained
classifier built on top of a real LLM (Gemini Flash), using Chroma as a
vector database to retrieve the most relevant labeled examples from a
small synthetic dataset (specialized_fewshot_dataset.py) before asking
the model to classify a new log.

This is deliberately kept SEPARATE from triage_agent.py:
  - triage_agent.py stays the default, deterministic, fully offline
    agent used by streamlit_app.py and test_agent.py. It needs no API
    key and no network access.
  - specialized_agent.py is the comparison path for the bonus rubric's
    "show output measurably differs from baseline" ask. It requires a
    Gemini API key and network access, and is not wired into the main
    app or the default test suite.

Pipeline:
  1. EMBED   - embed the incoming log's text with Gemini's embedding
               model.
  2. RETRIEVE - query a local Chroma collection (persisted at
               .chroma_db/, built once from the few-shot dataset) for
               the k most similar labeled examples.
  3. GENERATE - build a few-shot prompt from those examples and ask
               Gemini Flash for a structured JSON classification
               (severity, confidence_score, mitigation), using
               response_schema to constrain the output shape - the
               model cannot return malformed JSON and have it pass.

Setup:
    pip install -r requirements-specialized.txt
    export GEMINI_API_KEY="your-google-ai-studio-key"   # never hardcoded

Usage:
    python specialized_agent.py logs/snort_alert_clean.log
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import chromadb
from dotenv import load_dotenv
from google import genai
from google.genai import types
from pydantic import BaseModel, Field

from specialized_fewshot_dataset import FEW_SHOT_EXAMPLES

# Loads .env into os.environ if present (no-op, no error, if it isn't -
# e.g. you exported GEMINI_API_KEY directly in your shell instead).
load_dotenv()

CHROMA_PATH = Path(".chroma_db")
COLLECTION_NAME = "log_fewshot_examples"

# Overridable via env var in case these model ids change or you want to
# point at a different Gemini model without touching code.
EMBEDDING_MODEL = os.environ.get("GEMINI_EMBEDDING_MODEL", "text-embedding-004")
GENERATION_MODEL = os.environ.get("GEMINI_GENERATION_MODEL", "gemini-flash-latest")

NUM_FEW_SHOT_EXAMPLES = 4


class TriageResult(BaseModel):
    """Structured output contract the model's response is constrained to."""

    severity: str = Field(description="One of: critical, high, medium, low, unknown")
    confidence_score: float = Field(description="The model's own confidence in this classification, 0.0-1.0")
    mitigation: str = Field(description="A concrete, specific mitigation recommendation")


def _get_api_key() -> str:
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        raise RuntimeError(
            "GEMINI_API_KEY is not set. Get a key from Google AI Studio and set it, "
            "e.g.:\n    export GEMINI_API_KEY=\"your-key-here\"\n"
            "(never commit the key - .env is already gitignored if you prefer a file)."
        )
    return api_key


def _get_client() -> genai.Client:
    return genai.Client(api_key=_get_api_key())


def _embed_texts(client: genai.Client, texts: list[str]) -> list[list[float]]:
    response = client.models.embed_content(model=EMBEDDING_MODEL, contents=texts)
    return [embedding.values for embedding in response.embeddings]


def _get_or_build_collection(client: genai.Client):
    """Return the persisted Chroma collection, building it from the
    few-shot dataset the first time (or if it's empty)."""
    chroma_client = chromadb.PersistentClient(path=str(CHROMA_PATH))
    collection = chroma_client.get_or_create_collection(COLLECTION_NAME)

    if collection.count() == 0:
        texts = [example["text"] for example in FEW_SHOT_EXAMPLES]
        embeddings = _embed_texts(client, texts)
        collection.add(
            ids=[example["id"] for example in FEW_SHOT_EXAMPLES],
            embeddings=embeddings,
            documents=texts,
            metadatas=[
                {"log_type": example["log_type"], "severity": example["severity"]}
                for example in FEW_SHOT_EXAMPLES
            ],
        )

    return collection


def _retrieve_few_shot(client: genai.Client, collection, query_text: str, k: int = NUM_FEW_SHOT_EXAMPLES) -> list[dict]:
    """RETRIEVE: embed the query log and pull the k nearest labeled examples from Chroma."""
    query_embedding = _embed_texts(client, [query_text])[0]
    result = collection.query(
        query_embeddings=[query_embedding],
        n_results=k,
        include=["documents", "metadatas", "distances"],
    )
    examples = []
    for doc, meta, distance in zip(result["documents"][0], result["metadatas"][0], result["distances"][0]):
        examples.append({"text": doc, "log_type": meta["log_type"], "severity": meta["severity"], "distance": distance})
    return examples


def _build_prompt(log_content: str, few_shot_examples: list[dict]) -> str:
    """GENERATE: construct a few-shot prompt from the retrieved examples."""
    example_blocks = []
    for ex in few_shot_examples:
        example_blocks.append(
            f"Log:\n{ex['text']}\n"
            f"Classification: log_type={ex['log_type']}, severity={ex['severity']}"
        )
    examples_text = "\n\n".join(example_blocks)

    return (
        "You are a security/ops log triage specialist. Classify the NEW log below "
        "using the same severity vocabulary as the labeled examples "
        "(critical, high, medium, or low; use 'unknown' only if truly unclassifiable). "
        "Base your mitigation only on what's actually in the NEW log - do not invent "
        "IP addresses, hostnames, or details that aren't present in it.\n\n"
        f"--- LABELED EXAMPLES (retrieved as the most similar to the new log) ---\n\n"
        f"{examples_text}\n\n"
        f"--- NEW LOG TO CLASSIFY ---\n\n"
        f"{log_content}\n\n"
        "Return your classification as JSON with exactly these fields: "
        "severity, confidence_score (0.0-1.0, your own confidence), mitigation."
    )


def classify_with_llm(log_content: str) -> dict[str, Any]:
    """
    Full Embed -> Retrieve -> Generate pipeline. Returns a dict with the
    same 'severity' / 'confidence_score' / 'mitigation' keys as
    triage_agent.process_log(), plus 'few_shot_examples_used' and
    'source' so the output is clearly distinguishable from the baseline.

    Raises:
        RuntimeError: if GEMINI_API_KEY is not set.
        ValueError: if the model's response isn't valid, schema-conforming JSON.
    """
    client = _get_client()
    collection = _get_or_build_collection(client)
    few_shot_examples = _retrieve_few_shot(client, collection, log_content)
    prompt = _build_prompt(log_content, few_shot_examples)

    response = client.models.generate_content(
        model=GENERATION_MODEL,
        contents=prompt,
        config=types.GenerateContentConfig(
            response_mime_type="application/json",
            response_schema=TriageResult,
        ),
    )

    parsed = response.parsed
    if parsed is None:
        # Fall back to manual parsing if the SDK didn't auto-parse for
        # some reason - but never fabricate a result if this also fails.
        try:
            parsed = TriageResult.model_validate(json.loads(response.text))
        except Exception as exc:
            raise ValueError(f"Gemini did not return a schema-conforming result: {exc}") from exc

    if not (0.0 <= parsed.confidence_score <= 1.0):
        raise ValueError(f"Gemini returned an out-of-range confidence_score: {parsed.confidence_score}")

    return {
        "severity": parsed.severity,
        "confidence_score": parsed.confidence_score,
        "mitigation": parsed.mitigation,
        "few_shot_examples_used": [
            {"log_type": ex["log_type"], "severity": ex["severity"], "distance": round(ex["distance"], 4)}
            for ex in few_shot_examples
        ],
        "source": f"chroma+{GENERATION_MODEL}",
    }


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python specialized_agent.py <path-to-log-file>")
        raise SystemExit(1)

    path = Path(sys.argv[1])
    raw = path.read_bytes().decode("utf-8", errors="replace")
    try:
        output = classify_with_llm(raw)
    except (RuntimeError, ValueError) as exc:
        print(f"specialized_agent failed: {exc}")
        raise SystemExit(1)
    print(json.dumps(output, indent=2))
