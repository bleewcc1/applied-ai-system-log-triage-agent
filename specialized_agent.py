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

Safety guardrails (reused from triage_agent.py, not duplicated - see the
import of IP_PATTERN/_detect_corruption below):
  - classify_with_llm() refuses corrupted/unparseable input before ever
    calling Gemini, instead of confidently classifying garbage (confirmed
    live: Gemini returned 0.95 confidence on logs/corrupted_log.txt before
    this guard existed).
  - classify_with_llm() rejects a result whose mitigation text mentions an
    IP address absent from the source log - the prompt asks Gemini not to
    invent IOCs, but this is what actually enforces it.
  - TriageResult.severity is a Literal, not a bare str, so an
    out-of-vocabulary value from the model fails validation instead of
    silently passing through.

Pipeline:
  1. EMBED   - embed the incoming log's text with Gemini's embedding
               model. Embedded exactly once per classification and the
               vector reused for both retrievals below (it used to be
               embedded twice - once per retrieval call).
  2. RETRIEVE - query a local Chroma collection (persisted at
               .chroma_db/, built once from the few-shot dataset) for
               the k most similar labeled examples, plus (if any have
               been uploaded via add_custom_document()) the most
               relevant chunks from a second, separate collection of
               user-supplied reference documents.
  3. GENERATE - build a few-shot prompt from those examples and ask
               Gemini Flash for a structured JSON classification
               (severity, confidence_score, mitigation), using
               response_schema to constrain the output shape - the
               model cannot return malformed JSON and have it pass.

Performance: the Gemini HTTP client and the Chroma SQLite connection are
each built once per process and cached (_get_client / _get_chroma_client),
not reconstructed on every call - see those functions' docstrings. Text
embedding batches at EMBED_BATCH_SIZE (100) since Gemini's
BatchEmbedContentsRequest rejects larger single requests, which a
large-document upload can easily exceed.

Document ingestion (add_custom_document):
  - Accepts .txt, .md, or .pdf raw bytes.
  - PDFs are extracted page-by-page (pypdf) so each indexed chunk can
    cite its source page number; text/markdown is chunked as one
    continuous document.
  - Chunking is paragraph-aware (_chunk_paragraphs): it packs whole
    paragraphs up to CHUNK_SIZE characters rather than slicing at a
    fixed character offset, so a chunk boundary doesn't land mid-
    sentence. A single paragraph longer than CHUNK_SIZE falls back to a
    fixed-size sliding window (_chunk_fixed_size).

Setup:
    pip install -r requirements-specialized.txt
    export GEMINI_API_KEY="your-google-ai-studio-key"   # never hardcoded

Usage:
    python specialized_agent.py logs/snort_alert_clean.log
"""

from __future__ import annotations

import io
import json
import os
import time
from pathlib import Path
from typing import Any, Literal

import chromadb
from dotenv import load_dotenv
from google import genai
from google.genai import types
from pydantic import BaseModel, Field
from pypdf import PdfReader

from specialized_fewshot_dataset import FEW_SHOT_EXAMPLES
# Reused from the baseline agent rather than duplicated - these are plain,
# stateless utilities (a regex, a pure function), not a dependency on
# triage_agent's pipeline. Keeps the corruption/IP-hallucination checks
# identical on both paths instead of risking the two copies drifting apart.
from triage_agent import IP_PATTERN, _detect_corruption

# Loads .env into os.environ if present (no-op, no error, if it isn't -
# e.g. you exported GEMINI_API_KEY directly in your shell instead).
load_dotenv()

# Chroma's PersistentClient uses SQLite under the hood, which needs real
# POSIX file locking to do writes. exFAT (and some network/removable
# filesystems) don't support that properly and fail with "attempt to
# write a readonly database" even though the volume itself is writable -
# confirmed on this project's own checkout, which lives on an exFAT
# external drive. Default to a path under the user's home directory
# (reliably a native filesystem) instead of inside the project folder;
# override with CHROMA_DB_PATH if your project happens to live on a
# filesystem that handles SQLite locking fine.
CHROMA_PATH = Path(
    os.environ.get("CHROMA_DB_PATH", str(Path.home() / ".cache" / "applied-ai-log-triage-agent" / "chroma_db"))
)
COLLECTION_NAME = "log_fewshot_examples"
CUSTOM_DOCS_COLLECTION_NAME = "custom_uploaded_docs"

CHUNK_SIZE = 1500
CHUNK_OVERLAP = 200

# Overridable via env var in case these model ids change or you want to
# point at a different Gemini model without touching code.
EMBEDDING_MODEL = os.environ.get("GEMINI_EMBEDDING_MODEL", "gemini-embedding-001")
GENERATION_MODEL = os.environ.get("GEMINI_GENERATION_MODEL", "gemini-flash-latest")

# Gemini's BatchEmbedContentsRequest rejects a request with more than this
# many items - confirmed by hitting it on a real large-document upload.
EMBED_BATCH_SIZE = 100

# OPTIMIZATION: gemini-embedding-001 defaults to a 3072-dim vector, which
# is far more than a corpus this small (18 few-shot examples + whatever's
# uploaded) needs - it costs more Chroma storage and slower distance
# computation for no real accuracy gain here. Matryoshka-trained models
# support truncating to a smaller dimension via output_dimensionality;
# 768 is the usual quality/efficiency sweet spot. Changing this value
# requires re-embedding anything already stored at the old dimension -
# see _collection_dimension() and the dimension-check in
# _get_or_build_collection() / add_custom_document() / retrieval below.
EMBEDDING_DIMENSIONALITY = int(os.environ.get("GEMINI_EMBEDDING_DIMENSIONALITY", "768"))

NUM_FEW_SHOT_EXAMPLES = 4


SEVERITY_LEVELS = ("critical", "high", "medium", "low", "unknown")


class TriageResult(BaseModel):
    """
    Structured output contract the model's response is constrained to.
    severity is a Literal (not a bare str) so the JSON schema Gemini is
    given has an actual enum constraint - it was previously an
    unconstrained string, so an out-of-vocabulary or wrong-case value
    (e.g. "Critical", "sev1") would pass through unchanged and silently
    break anything comparing severities against the baseline's fixed
    vocabulary.
    """

    severity: Literal["critical", "high", "medium", "low", "unknown"] = Field(
        description="One of: critical, high, medium, low, unknown"
    )
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


# OPTIMIZATION: cache the Gemini HTTP client and the Chroma SQLite
# connection per process instead of reconstructing them on every call.
# Nothing about either changes between calls within one run - a loop
# classifying several logs (or a long-running Streamlit session) was
# paying connection/handshake setup cost on every single call for no
# reason. Tests reset these via an autouse fixture so caching here never
# leaks state between tests.
_cached_client: genai.Client | None = None
_cached_chroma_client: chromadb.ClientAPI | None = None


def _get_client() -> genai.Client:
    global _cached_client
    if _cached_client is None:
        _cached_client = genai.Client(api_key=_get_api_key())
    return _cached_client


def _get_chroma_client() -> chromadb.ClientAPI:
    global _cached_chroma_client
    if _cached_chroma_client is None:
        _cached_chroma_client = chromadb.PersistentClient(path=str(CHROMA_PATH))
    return _cached_chroma_client


def _embed_texts(client: genai.Client, texts: list[str]) -> list[list[float]]:
    """
    Embeds any number of texts, batching requests at EMBED_BATCH_SIZE.
    Gemini's BatchEmbedContentsRequest rejects more than 100 requests in
    one call - a single large PDF can easily chunk into more than 100
    pieces, so a document-sized text list can't be sent in one shot.
    """
    embeddings: list[list[float]] = []
    for start in range(0, len(texts), EMBED_BATCH_SIZE):
        batch = texts[start : start + EMBED_BATCH_SIZE]
        response = client.models.embed_content(
            model=EMBEDDING_MODEL,
            contents=batch,
            config=types.EmbedContentConfig(output_dimensionality=EMBEDDING_DIMENSIONALITY),
        )
        embeddings.extend(embedding.values for embedding in response.embeddings)
    return embeddings


def _collection_dimension(collection) -> int | None:
    """The embedding dimension already stored in a non-empty collection, or
    None if it's empty (nothing to compare against yet)."""
    peeked = collection.peek(limit=1)
    embeddings = peeked.get("embeddings")
    if embeddings is None or len(embeddings) == 0:
        return None
    return len(embeddings[0])


def _dimension_mismatch_error(exc: Exception) -> ValueError:
    """
    Wraps Chroma's own dimension-mismatch error for the custom-docs
    collection with actionable guidance. Unlike the few-shot collection
    (a pure build artifact, safe to auto-heal - see _get_or_build_collection),
    custom-docs holds the user's own uploads, so this never auto-deletes
    anything: it's the user's call whether to clear and re-upload.
    """
    return ValueError(
        f"{exc} - the knowledge base was built with a different embedding "
        f"dimension than the currently configured EMBEDDING_DIMENSIONALITY "
        f"({EMBEDDING_DIMENSIONALITY}). Clear it via clear_knowledge_base() "
        "(or the RAG Lab's Manage Knowledge Base page) and re-upload your "
        "documents to rebuild it at the new dimension."
    )


def _get_or_build_collection(client: genai.Client):
    """
    Return the persisted Chroma collection, building it from the few-shot
    dataset the first time (or if it's empty). This collection is a pure
    build artifact regenerated from specialized_fewshot_dataset.py, not
    user data, so if it was built under a different EMBEDDING_DIMENSIONALITY
    than the one currently configured, it's safe to drop and rebuild
    automatically rather than erroring (unlike the custom-docs collection,
    which holds the user's own uploads - see add_custom_document and
    _retrieve_custom_doc_context for that case).
    """
    chroma_client = _get_chroma_client()
    collection = chroma_client.get_or_create_collection(COLLECTION_NAME)

    if collection.count() > 0:
        stored_dimension = _collection_dimension(collection)
        # None means "couldn't determine it" (shouldn't happen in real
        # Chroma once count() > 0, but never treat indeterminate as a
        # mismatch - that would make an inconclusive read destructive).
        if stored_dimension is not None and stored_dimension != EMBEDDING_DIMENSIONALITY:
            chroma_client.delete_collection(COLLECTION_NAME)
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


def _chunk_fixed_size(text: str, chunk_size: int = CHUNK_SIZE, overlap: int = CHUNK_OVERLAP) -> list[str]:
    """Sliding-window fallback for a single block of text longer than chunk_size
    with no paragraph breaks to split on (e.g. one huge unbroken PDF page)."""
    chunks = []
    start = 0
    while start < len(text):
        end = start + chunk_size
        chunks.append(text[start:end])
        start = end - overlap
    return chunks


def _chunk_paragraphs(text: str, chunk_size: int = CHUNK_SIZE, overlap: int = CHUNK_OVERLAP) -> list[str]:
    """
    Paragraph-aware chunker: greedily packs whole paragraphs (split on blank
    lines) into chunks up to chunk_size, so a chunk boundary lands between
    paragraphs rather than mid-sentence wherever possible. A single
    paragraph longer than chunk_size falls back to _chunk_fixed_size.
    """
    text = text.strip()
    if not text:
        return []

    paragraphs = [p.strip() for p in text.split("\n\n") if p.strip()]
    if not paragraphs:
        paragraphs = [text]

    chunks: list[str] = []
    current = ""
    for paragraph in paragraphs:
        if len(paragraph) > chunk_size:
            if current:
                chunks.append(current)
                current = ""
            chunks.extend(_chunk_fixed_size(paragraph, chunk_size, overlap))
            continue

        candidate = f"{current}\n\n{paragraph}" if current else paragraph
        if len(candidate) <= chunk_size:
            current = candidate
        else:
            chunks.append(current)
            current = paragraph

    if current:
        chunks.append(current)
    return chunks


def _extract_pdf_pages(raw_bytes: bytes) -> list[str]:
    """
    Extracts text per page from a PDF's raw bytes, via pypdf.

    Raises:
        ValueError: if the PDF is encrypted, corrupted, or otherwise
                    unreadable - converted from pypdf's own exception
                    types so callers never need to import pypdf.errors.
    """
    try:
        reader = PdfReader(io.BytesIO(raw_bytes))
        if reader.is_encrypted:
            raise ValueError("PDF is password-protected/encrypted; upload a decrypted copy instead.")
        return [page.extract_text() or "" for page in reader.pages]
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError(
            f"Could not read this PDF ({type(exc).__name__}: {exc}). "
            "It may be corrupted or in an unsupported format."
        ) from exc


def _extract_document_chunks(filename: str, raw_bytes: bytes) -> tuple[list[dict], dict]:
    """
    Dispatches on file extension to turn raw uploaded bytes into a list of
    {"text": ..., "page_number": int | None} chunks ready for embedding,
    plus a small dict of extraction-level facts ({"num_pages": int | None})
    that add_custom_document folds into its pipeline metrics. PDFs are
    chunked per page (so each chunk can cite its page number); plain
    text/markdown is chunked as one continuous document.

    Raises:
        ValueError: if the PDF can't be read (see _extract_pdf_pages), or
                    if it's readable but has no extractable text at all
                    (e.g. a scanned/image-only PDF with no text layer).
    """
    suffix = Path(filename).suffix.lower()
    chunks: list[dict] = []
    extraction_info = {"num_pages": None}

    if suffix == ".pdf":
        pages = _extract_pdf_pages(raw_bytes)
        extraction_info["num_pages"] = len(pages)
        for page_number, page_text in enumerate(pages, start=1):
            for chunk_text in _chunk_paragraphs(page_text):
                chunks.append({"text": chunk_text, "page_number": page_number})
        if not chunks:
            raise ValueError(
                f"No extractable text found in '{filename}' ({len(pages)} page(s)). "
                "It may be a scanned/image-only PDF with no text layer - OCR it "
                "first, or upload a text-based PDF instead."
            )
    else:
        text = raw_bytes.decode("utf-8", errors="replace")
        for chunk_text in _chunk_paragraphs(text):
            chunks.append({"text": chunk_text, "page_number": None})

    return chunks, extraction_info


def add_custom_document(filename: str, raw_bytes: bytes) -> dict:
    """
    RAG ENHANCEMENT: extract, chunk, embed, and index a user-uploaded
    document (.txt, .md, or .pdf) into its own Chroma collection (separate
    from the curated few-shot dataset), so
    classify_with_llm(..., include_custom_docs=True) can retrieve from it
    as an additional data source. PDF chunks carry their source page
    number in metadata for citation.

    Returns a pipeline-metrics dict rather than a bare chunk count, so the
    UI (or a caller) can show exactly what the ingestion pipeline did:
        {
          "filename", "file_type" ("pdf" | "text"),
          "num_pages" (PDF only, else None),
          "num_chunks", "total_chars",
          "avg_chunk_size", "min_chunk_size", "max_chunk_size",
          "embedding_dimension",
          "timings_ms": {"extraction", "embedding", "chroma_insert", "total"},
        }
    An empty (whitespace-only) text/markdown upload returns this same
    shape with num_chunks=0 and zeroed-out stats, rather than raising -
    that's a no-op upload, not an error. A PDF with literally no
    extractable text raises ValueError instead (see
    _extract_document_chunks) since that's much more likely to be a
    scanning/format mistake worth surfacing.

    Raises:
        RuntimeError: if GEMINI_API_KEY is not set.
        ValueError: if the document can't be read or has no extractable
                    text (see _extract_document_chunks).
    """
    pipeline_start = time.perf_counter()
    suffix = Path(filename).suffix.lower()

    extract_start = time.perf_counter()
    doc_chunks, extraction_info = _extract_document_chunks(filename, raw_bytes)
    extraction_ms = (time.perf_counter() - extract_start) * 1000

    if not doc_chunks:
        return {
            "filename": filename,
            "file_type": "pdf" if suffix == ".pdf" else "text",
            "num_pages": extraction_info["num_pages"],
            "num_chunks": 0,
            "total_chars": 0,
            "avg_chunk_size": 0,
            "min_chunk_size": 0,
            "max_chunk_size": 0,
            "embedding_dimension": 0,
            "timings_ms": {
                "extraction": round(extraction_ms, 2),
                "embedding": 0.0,
                "chroma_insert": 0.0,
                "total": round((time.perf_counter() - pipeline_start) * 1000, 2),
            },
        }

    client = _get_client()
    texts = [c["text"] for c in doc_chunks]

    embed_start = time.perf_counter()
    embeddings = _embed_texts(client, texts)
    embedding_ms = (time.perf_counter() - embed_start) * 1000

    metadatas = []
    for i, chunk in enumerate(doc_chunks):
        metadata = {"filename": filename, "chunk_index": i}
        if chunk["page_number"] is not None:
            metadata["page_number"] = chunk["page_number"]
        metadatas.append(metadata)

    insert_start = time.perf_counter()
    chroma_client = _get_chroma_client()
    collection = chroma_client.get_or_create_collection(CUSTOM_DOCS_COLLECTION_NAME)
    existing_count = collection.count()
    try:
        collection.add(
            ids=[f"{filename}-chunk-{existing_count + i}" for i in range(len(doc_chunks))],
            embeddings=embeddings,
            documents=texts,
            metadatas=metadatas,
        )
    except chromadb.errors.InvalidArgumentError as exc:
        raise _dimension_mismatch_error(exc) from exc
    chroma_insert_ms = (time.perf_counter() - insert_start) * 1000

    chunk_lengths = [len(t) for t in texts]
    total_ms = (time.perf_counter() - pipeline_start) * 1000

    return {
        "filename": filename,
        "file_type": "pdf" if suffix == ".pdf" else "text",
        "num_pages": extraction_info["num_pages"],
        "num_chunks": len(doc_chunks),
        "total_chars": sum(chunk_lengths),
        "avg_chunk_size": round(sum(chunk_lengths) / len(chunk_lengths), 1),
        "min_chunk_size": min(chunk_lengths),
        "max_chunk_size": max(chunk_lengths),
        "embedding_dimension": len(embeddings[0]) if embeddings and embeddings[0] else 0,
        "timings_ms": {
            "extraction": round(extraction_ms, 2),
            "embedding": round(embedding_ms, 2),
            "chroma_insert": round(chroma_insert_ms, 2),
            "total": round(total_ms, 2),
        },
    }


def list_custom_documents() -> list[dict]:
    """
    KNOWLEDGE BASE MANAGEMENT: summarize what's currently indexed in the
    custom-docs collection, grouped by filename. Purely local (Chroma
    only) - no API key or network access needed, unlike ingestion/retrieval.

    Returns one {"filename", "file_type", "num_chunks", "num_pages"} dict
    per distinct uploaded file, sorted by filename. Empty list if nothing
    has been uploaded yet.
    """
    chroma_client = _get_chroma_client()
    collection = chroma_client.get_or_create_collection(CUSTOM_DOCS_COLLECTION_NAME)
    if collection.count() == 0:
        return []

    all_entries = collection.get(include=["metadatas"])
    by_filename: dict[str, dict] = {}
    for metadata in all_entries["metadatas"]:
        filename = metadata["filename"]
        entry = by_filename.setdefault(
            filename, {"filename": filename, "file_type": "text", "num_chunks": 0, "num_pages": None}
        )
        entry["num_chunks"] += 1
        page_number = metadata.get("page_number")
        if page_number is not None:
            entry["file_type"] = "pdf"
            entry["num_pages"] = max(entry["num_pages"] or 0, page_number)

    return sorted(by_filename.values(), key=lambda e: e["filename"])


def delete_custom_document(filename: str) -> int:
    """
    KNOWLEDGE BASE MANAGEMENT: remove every chunk belonging to one
    uploaded file from the custom-docs collection. Purely local - no API
    key needed. Returns the number of chunks deleted (0 if that filename
    wasn't in the knowledge base).
    """
    chroma_client = _get_chroma_client()
    collection = chroma_client.get_or_create_collection(CUSTOM_DOCS_COLLECTION_NAME)
    matching = collection.get(where={"filename": filename}, include=[])
    matching_ids = matching["ids"]
    if not matching_ids:
        return 0
    collection.delete(ids=matching_ids)
    return len(matching_ids)


def clear_knowledge_base() -> int:
    """
    KNOWLEDGE BASE MANAGEMENT: remove every uploaded document, resetting
    the custom-docs collection to empty. Purely local - no API key
    needed. Returns the number of chunks that were cleared.
    """
    chroma_client = _get_chroma_client()
    collection = chroma_client.get_or_create_collection(CUSTOM_DOCS_COLLECTION_NAME)
    count = collection.count()
    if count == 0:
        return 0
    chroma_client.delete_collection(CUSTOM_DOCS_COLLECTION_NAME)
    return count


def _retrieve_custom_doc_context(query_embedding: list[float], k: int = 3) -> list[dict]:
    """
    Query the custom-docs collection, if anything has been uploaded to it
    yet. Takes an already-computed query embedding rather than embedding
    the query itself - OPTIMIZATION: classify_with_llm's log text used to
    get embedded twice (once here, once in _retrieve_few_shot) for every
    single classification; now it's embedded once and the vector is
    reused for both retrievals.
    """
    chroma_client = _get_chroma_client()
    collection = chroma_client.get_or_create_collection(CUSTOM_DOCS_COLLECTION_NAME)
    if collection.count() == 0:
        return []

    try:
        result = collection.query(
            query_embeddings=[query_embedding],
            n_results=min(k, collection.count()),
            include=["documents", "metadatas", "distances"],
        )
    except chromadb.errors.InvalidArgumentError as exc:
        raise _dimension_mismatch_error(exc) from exc
    contexts = []
    for doc, meta, distance in zip(result["documents"][0], result["metadatas"][0], result["distances"][0]):
        contexts.append(
            {"text": doc, "filename": meta["filename"], "page_number": meta.get("page_number"), "distance": distance}
        )
    return contexts


def _retrieve_few_shot(collection, query_embedding: list[float], k: int = NUM_FEW_SHOT_EXAMPLES) -> list[dict]:
    """RETRIEVE: pull the k nearest labeled examples from Chroma for an
    already-computed query embedding (see _retrieve_custom_doc_context)."""
    result = collection.query(
        query_embeddings=[query_embedding],
        n_results=k,
        include=["documents", "metadatas", "distances"],
    )
    examples = []
    for doc, meta, distance in zip(result["documents"][0], result["metadatas"][0], result["distances"][0]):
        examples.append({"text": doc, "log_type": meta["log_type"], "severity": meta["severity"], "distance": distance})
    return examples


def _build_prompt(log_content: str, few_shot_examples: list[dict], custom_doc_context: list[dict] | None = None) -> str:
    """GENERATE: construct a few-shot prompt from the retrieved examples,
    plus any retrieved custom-document context (the RAG enhancement's
    second data source - see add_custom_document())."""
    example_blocks = []
    for ex in few_shot_examples:
        example_blocks.append(
            f"Log:\n{ex['text']}\n"
            f"Classification: log_type={ex['log_type']}, severity={ex['severity']}"
        )
    examples_text = "\n\n".join(example_blocks)

    custom_docs_section = ""
    if custom_doc_context:
        doc_blocks = []
        for ctx in custom_doc_context:
            citation = f"{ctx['filename']}, page {ctx['page_number']}" if ctx.get("page_number") else ctx["filename"]
            doc_blocks.append(f"[from {citation}]\n{ctx['text']}")
        custom_docs_section = (
            "\n\n--- ADDITIONAL REFERENCE DOCUMENTS (uploaded, retrieved as relevant) ---\n\n"
            + "\n\n".join(doc_blocks)
        )

    return (
        "You are a security/ops log triage specialist. Classify the NEW log below "
        "using the same severity vocabulary as the labeled examples "
        "(critical, high, medium, or low; use 'unknown' only if truly unclassifiable). "
        "Base your mitigation only on what's actually in the NEW log and any reference "
        "documents below - do not invent IP addresses, hostnames, or details that "
        "aren't present in them.\n\n"
        f"--- LABELED EXAMPLES (retrieved as the most similar to the new log) ---\n\n"
        f"{examples_text}"
        f"{custom_docs_section}\n\n"
        f"--- NEW LOG TO CLASSIFY ---\n\n"
        f"{log_content}\n\n"
        "Return your classification as JSON with exactly these fields: "
        "severity, confidence_score (0.0-1.0, your own confidence), mitigation."
    )


def classify_with_llm(log_content: str, include_custom_docs: bool = False) -> dict[str, Any]:
    """
    Full Embed -> Retrieve -> Generate pipeline. Returns a dict with the
    same 'severity' / 'confidence_score' / 'mitigation' keys as
    triage_agent.process_log(), plus 'few_shot_examples_used', optionally
    'custom_docs_used', and 'source' so the output is clearly
    distinguishable from the baseline.

    include_custom_docs: when True, also retrieves from whatever has been
    uploaded via add_custom_document() and adds it to the prompt as a
    second data source. Defaults to False so existing callers (the CLI,
    compare_baseline_vs_specialized.py) are unaffected unless they opt in.

    Raises:
        RuntimeError: if GEMINI_API_KEY is not set.
        ValueError: if the content is detected as corrupted/unparseable
                    (same PLAN-phase guardrail triage_agent.py uses - this
                    path previously sent garbled input straight to Gemini,
                    which confidently classified it instead of refusing),
                    if the model's response isn't valid, schema-conforming
                    JSON, or if its mitigation text mentions an IP address
                    that doesn't actually appear in log_content (same
                    CHECK-phase guardrail as triage_agent._check() - this
                    path previously had no such verification at all).
    """
    is_corrupted, reason = _detect_corruption(log_content)
    if is_corrupted:
        raise ValueError(
            f"Corrupted or unparseable log content detected ({reason}); "
            "refusing to classify rather than guess from garbled evidence."
        )

    client = _get_client()
    collection = _get_or_build_collection(client)

    # OPTIMIZATION: embed the log once and reuse the vector for both
    # retrievals below, instead of embedding the same text twice.
    query_embedding = _embed_texts(client, [log_content])[0]
    few_shot_examples = _retrieve_few_shot(collection, query_embedding)
    custom_doc_context = _retrieve_custom_doc_context(query_embedding) if include_custom_docs else []
    prompt = _build_prompt(log_content, few_shot_examples, custom_doc_context)

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

    # CHECK: verify no IP address in the mitigation was hallucinated - same
    # guardrail triage_agent._check() applies to the baseline. The prompt
    # already asks Gemini not to invent IPs, but nothing previously
    # enforced that post-generation.
    observed_ips = set(IP_PATTERN.findall(log_content))
    mitigation_ips = set(IP_PATTERN.findall(parsed.mitigation))
    hallucinated_ips = mitigation_ips - observed_ips
    if hallucinated_ips:
        raise ValueError(
            f"Gemini's mitigation mentions IP address(es) not present in the "
            f"source log - refusing to return a result with hallucinated "
            f"IOCs: {sorted(hallucinated_ips)}"
        )

    return {
        "severity": parsed.severity,
        "confidence_score": parsed.confidence_score,
        "mitigation": parsed.mitigation,
        "few_shot_examples_used": [
            {"log_type": ex["log_type"], "severity": ex["severity"], "distance": round(ex["distance"], 4)}
            for ex in few_shot_examples
        ],
        "custom_docs_used": [
            {
                "filename": ctx["filename"],
                "page_number": ctx.get("page_number"),
                "distance": round(ctx["distance"], 4),
            }
            for ctx in custom_doc_context
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
