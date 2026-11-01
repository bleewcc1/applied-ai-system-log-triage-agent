"""
test_specialized_agent.py

Tests for specialized_agent.py (the Chroma + Gemini Flash bonus module),
with the Gemini and Chroma clients fully mocked - these tests must never
make a real network call or spend real API quota, regardless of whether
a real GEMINI_API_KEY is present in the environment or .env.

Skips the whole file (not a failure) if chromadb/google-genai/python-dotenv
aren't installed, since those are optional deps in requirements-specialized.txt,
not the core requirements.txt.
"""

from types import SimpleNamespace

import pytest

specialized_agent = pytest.importorskip("specialized_agent")


@pytest.fixture(autouse=True)
def _reset_specialized_agent_caches():
    """
    specialized_agent caches its Gemini client and Chroma client at module
    level (an optimization - see _get_client/_get_chroma_client) so they
    aren't reconstructed on every call within one process. Without this
    reset, a test's monkeypatched fake would be shadowed by whatever an
    earlier test already cached, breaking isolation between tests.
    """
    specialized_agent._cached_client = None
    specialized_agent._cached_chroma_client = None
    yield
    specialized_agent._cached_client = None
    specialized_agent._cached_chroma_client = None


# ---------------------------------------------------------------------------
# Fakes - lightweight stand-ins for the real Gemini/Chroma objects, shaped
# exactly like what specialized_agent.py actually reads off them.
# ---------------------------------------------------------------------------

def _fake_embed_response(count: int):
    """Mimics google.genai.types.EmbedContentResponse: .embeddings[i].values"""
    return SimpleNamespace(embeddings=[SimpleNamespace(values=[0.1, 0.2, 0.3]) for _ in range(count)])


class FakeGenaiClient:
    """Stands in for google.genai.Client: records calls, returns canned responses."""

    def __init__(self, generate_content_response=None):
        self.embed_calls = []
        self.generate_calls = []
        self._generate_content_response = generate_content_response
        self.models = SimpleNamespace(
            embed_content=self._embed_content,
            generate_content=self._generate_content,
        )

    def _embed_content(self, *, model, contents, config=None):
        texts = contents if isinstance(contents, list) else [contents]
        self.embed_calls.append((model, texts, config))
        return _fake_embed_response(len(texts))

    def _generate_content(self, *, model, contents, config):
        self.generate_calls.append((model, contents, config))
        return self._generate_content_response


class FakeChromaCollection:
    def __init__(self, initial_count=0, query_result=None):
        self._count = initial_count
        self.add_calls = []
        self.delete_calls = []
        self._ids: list[str] = []
        self._metadatas: list[dict] = []
        self._embeddings: list[list[float]] = []
        self._query_result = query_result or {
            "documents": [["example log text"]],
            "metadatas": [[{"log_type": "network_intrusion", "severity": "critical"}]],
            "distances": [[0.1234]],
        }

    def count(self):
        return self._count

    def add(self, **kwargs):
        self.add_calls.append(kwargs)
        self._count += len(kwargs.get("ids", []))
        self._ids.extend(kwargs.get("ids", []))
        self._metadatas.extend(kwargs.get("metadatas", []))
        self._embeddings.extend(kwargs.get("embeddings", []))

    def query(self, **kwargs):
        return self._query_result

    def peek(self, limit=10):
        """Only ever used for the embedding-dimension check
        (_collection_dimension) - a collection built via `initial_count`
        alone (no real .add() call) correctly reports no embeddings here,
        which the dimension check treats as indeterminate, not a mismatch."""
        return {"embeddings": self._embeddings[:limit]}

    def get(self, ids=None, where=None, include=None):
        """Supports the simple {"field": value} equality `where` our code
        actually uses - not the full Chroma query-operator language."""
        matched_ids, matched_metadatas = [], []
        for entry_id, metadata in zip(self._ids, self._metadatas):
            if where and any(metadata.get(k) != v for k, v in where.items()):
                continue
            matched_ids.append(entry_id)
            matched_metadatas.append(metadata)
        result = {"ids": matched_ids}
        if include is None or "metadatas" in include:
            result["metadatas"] = matched_metadatas
        return result

    def delete(self, ids=None, where=None):
        self.delete_calls.append({"ids": ids, "where": where})
        if ids is None:
            return
        keep = [(i, m) for i, m in zip(self._ids, self._metadatas) if i not in ids]
        self._ids = [i for i, _ in keep]
        self._metadatas = [m for _, m in keep]
        self._count = len(self._ids)


class FakeChromaClient:
    """Maps collection name -> its own FakeChromaCollection, like real Chroma
    does - a lookup by one name must never return another collection's data."""

    def __init__(self, collections_by_name: dict[str, FakeChromaCollection]):
        self._collections_by_name = collections_by_name

    def get_or_create_collection(self, name):
        if name not in self._collections_by_name:
            self._collections_by_name[name] = FakeChromaCollection()
        return self._collections_by_name[name]

    def delete_collection(self, name):
        self._collections_by_name.pop(name, None)


def _patch_chroma(monkeypatch, collection: FakeChromaCollection, name: str = None):
    """By default, patches only the few-shot collection
    (specialized_agent.COLLECTION_NAME); pass `name` to seed a different
    one (e.g. CUSTOM_DOCS_COLLECTION_NAME), or call with a full dict via
    _patch_chroma_multi for tests that touch both collections.

    The registry dict is shared across every chromadb.PersistentClient(...)
    call this test makes (not rebuilt each time), so a delete_collection()
    call in one call actually persists into the next - needed for testing
    clear_knowledge_base()."""
    name = name or specialized_agent.COLLECTION_NAME
    registry = {name: collection}
    monkeypatch.setattr(
        specialized_agent.chromadb,
        "PersistentClient",
        lambda path: FakeChromaClient(registry),
    )


def _patch_chroma_multi(monkeypatch, collections_by_name: dict[str, FakeChromaCollection]):
    registry = dict(collections_by_name)
    monkeypatch.setattr(
        specialized_agent.chromadb,
        "PersistentClient",
        lambda path: FakeChromaClient(registry),
    )


# ---------------------------------------------------------------------------
# API key guardrail - must fail before ever touching the network.
# ---------------------------------------------------------------------------

def test_missing_api_key_raises_runtime_error_before_any_network_call(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="GEMINI_API_KEY"):
        specialized_agent.classify_with_llm("some log content")


def test_add_custom_document_missing_api_key_raises_runtime_error(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="GEMINI_API_KEY"):
        specialized_agent.add_custom_document("doc.txt", b"some reference text")


# ---------------------------------------------------------------------------
# Embedding batching - Gemini's BatchEmbedContentsRequest rejects more than
# EMBED_BATCH_SIZE items per call. A large document chunks into well over
# that many pieces, so _embed_texts must split into multiple requests
# rather than sending everything in one call (real bug hit in production:
# "BatchEmbedContentsRequest.requests: at most 100 requests can be in one
# batch", from uploading a large multi-page PDF).
# ---------------------------------------------------------------------------

def test_embed_texts_sends_one_request_when_under_the_batch_limit():
    client = FakeGenaiClient()
    texts = [f"text {i}" for i in range(50)]
    embeddings = specialized_agent._embed_texts(client, texts)
    assert len(client.embed_calls) == 1
    assert len(embeddings) == 50


def test_embed_texts_splits_into_multiple_requests_over_the_batch_limit():
    client = FakeGenaiClient()
    texts = [f"chunk {i}" for i in range(250)]  # e.g. a large multi-page PDF

    embeddings = specialized_agent._embed_texts(client, texts)

    assert len(embeddings) == 250
    # 250 texts at EMBED_BATCH_SIZE=100 -> 3 requests (100, 100, 50), never one.
    assert len(client.embed_calls) == 3
    batch_sizes = [len(batch_texts) for _model, batch_texts, _config in client.embed_calls]
    assert batch_sizes == [100, 100, 50]
    assert all(size <= specialized_agent.EMBED_BATCH_SIZE for size in batch_sizes)


def test_embed_texts_handles_exact_multiple_of_batch_limit():
    client = FakeGenaiClient()
    texts = [f"chunk {i}" for i in range(200)]
    embeddings = specialized_agent._embed_texts(client, texts)
    assert len(embeddings) == 200
    assert len(client.embed_calls) == 2


# ---------------------------------------------------------------------------
# Pure function: prompt construction needs no mocking at all.
# ---------------------------------------------------------------------------

def test_build_prompt_includes_examples_and_new_log_content():
    few_shot = [
        {"text": "example log A", "log_type": "network_intrusion", "severity": "critical", "distance": 0.1},
        {"text": "example log B", "log_type": "resource_anomaly", "severity": "low", "distance": 0.3},
    ]
    prompt = specialized_agent._build_prompt("THE NEW LOG CONTENT", few_shot)

    assert "THE NEW LOG CONTENT" in prompt
    assert "example log A" in prompt
    assert "example log B" in prompt
    assert "log_type=network_intrusion, severity=critical" in prompt
    assert "log_type=resource_anomaly, severity=low" in prompt


def test_build_prompt_omits_custom_docs_section_when_none_retrieved():
    prompt = specialized_agent._build_prompt("log text", [], custom_doc_context=[])
    assert "ADDITIONAL REFERENCE DOCUMENTS" not in prompt


def test_build_prompt_includes_custom_docs_section_when_present():
    custom_docs = [{"text": "internal runbook step 1...", "filename": "runbook.md", "distance": 0.2}]
    prompt = specialized_agent._build_prompt("log text", [], custom_doc_context=custom_docs)
    assert "ADDITIONAL REFERENCE DOCUMENTS" in prompt
    assert "internal runbook step 1..." in prompt
    assert "[from runbook.md]" in prompt


def test_build_prompt_cites_page_number_for_pdf_custom_docs():
    custom_docs = [{"text": "pdf excerpt text", "filename": "policy.pdf", "page_number": 3, "distance": 0.1}]
    prompt = specialized_agent._build_prompt("log text", [], custom_doc_context=custom_docs)
    assert "[from policy.pdf, page 3]" in prompt


# ---------------------------------------------------------------------------
# RAG enhancement: custom document upload -> its own Chroma collection,
# retrieved only when classify_with_llm opts in.
# ---------------------------------------------------------------------------

def test_add_custom_document_chunks_and_embeds_into_its_own_collection(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key-not-real")
    custom_docs_collection = FakeChromaCollection(initial_count=0)
    _patch_chroma(monkeypatch, custom_docs_collection, name=specialized_agent.CUSTOM_DOCS_COLLECTION_NAME)

    fake_client = FakeGenaiClient()
    monkeypatch.setattr(specialized_agent.genai, "Client", lambda api_key: fake_client)

    metrics = specialized_agent.add_custom_document("runbook.md", b"short reference document text")

    assert metrics["num_chunks"] == 1
    assert metrics["file_type"] == "text"
    assert metrics["num_pages"] is None
    assert metrics["embedding_dimension"] == 3
    assert metrics["total_chars"] == len("short reference document text")
    assert set(metrics["timings_ms"].keys()) == {"extraction", "embedding", "chroma_insert", "total"}
    assert all(v >= 0 for v in metrics["timings_ms"].values())

    assert len(custom_docs_collection.add_calls) == 1
    added = custom_docs_collection.add_calls[0]
    assert added["metadatas"][0]["filename"] == "runbook.md"
    assert "page_number" not in added["metadatas"][0]  # text/md docs don't have pages


def test_add_custom_document_empty_text_adds_nothing(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key-not-real")
    metrics = specialized_agent.add_custom_document("empty.md", b"   ")
    assert metrics["num_chunks"] == 0
    assert metrics["file_type"] == "text"
    assert metrics["embedding_dimension"] == 0


def test_add_custom_document_pdf_extracts_per_page_with_page_numbers(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key-not-real")
    custom_docs_collection = FakeChromaCollection(initial_count=0)
    _patch_chroma(monkeypatch, custom_docs_collection, name=specialized_agent.CUSTOM_DOCS_COLLECTION_NAME)

    fake_client = FakeGenaiClient()
    monkeypatch.setattr(specialized_agent.genai, "Client", lambda api_key: fake_client)
    monkeypatch.setattr(
        specialized_agent, "_extract_pdf_pages", lambda raw_bytes: ["page one text", "page two text"]
    )

    metrics = specialized_agent.add_custom_document("policy.pdf", b"%PDF-fake-bytes-not-parsed-due-to-mock")

    assert metrics["num_chunks"] == 2
    assert metrics["file_type"] == "pdf"
    assert metrics["num_pages"] == 2
    added = custom_docs_collection.add_calls[0]
    assert added["metadatas"][0]["page_number"] == 1
    assert added["metadatas"][1]["page_number"] == 2
    assert added["documents"] == ["page one text", "page two text"]


def test_extract_pdf_pages_real_extraction_from_minimal_pdf():
    """One real (unmocked) pypdf round trip, to make sure the actual library
    integration works - not just the mocked unit tests above."""
    minimal_pdf = (
        b"%PDF-1.4\n"
        b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n"
        b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n"
        b"3 0 obj << /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> "
        b"/MediaBox [0 0 612 792] /Contents 5 0 R >> endobj\n"
        b"4 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj\n"
        b"5 0 obj << /Length 60 >>\n"
        b"stream\nBT /F1 24 Tf 72 712 Td (TEST PDF EXTRACTION OK) Tj ET\nendstream endobj\n"
        b"xref\n0 6\n0000000000 65535 f \n"
        b"trailer << /Size 6 /Root 1 0 R >>\nstartxref\n0\n%%EOF"
    )
    pages = specialized_agent._extract_pdf_pages(minimal_pdf)
    assert len(pages) == 1
    assert "TEST PDF EXTRACTION OK" in pages[0]


# ---------------------------------------------------------------------------
# PDF failure modes - a real file "not supporting PDF" almost always means
# one of these two cases wasn't handled, not that the uploader rejected it.
# ---------------------------------------------------------------------------

def test_extract_pdf_pages_raises_value_error_for_corrupted_bytes():
    with pytest.raises(ValueError, match="Could not read this PDF"):
        specialized_agent._extract_pdf_pages(b"not a pdf at all, just garbage bytes")


def test_extract_document_chunks_raises_value_error_for_image_only_pdf(monkeypatch):
    """A scanned/image-only PDF extracts successfully but yields no text per page."""
    monkeypatch.setattr(specialized_agent, "_extract_pdf_pages", lambda raw_bytes: ["", ""])
    with pytest.raises(ValueError, match="No extractable text found"):
        specialized_agent._extract_document_chunks("scanned.pdf", b"irrelevant-bytes")


def test_add_custom_document_corrupted_pdf_raises_value_error_not_a_crash(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key-not-real")
    with pytest.raises(ValueError, match="Could not read this PDF"):
        specialized_agent.add_custom_document("bad.pdf", b"garbage, not a real pdf")


def test_extract_document_chunks_reports_num_pages_for_pdf(monkeypatch):
    monkeypatch.setattr(specialized_agent, "_extract_pdf_pages", lambda raw_bytes: ["page one", "page two", "page three"])
    chunks, extraction_info = specialized_agent._extract_document_chunks("doc.pdf", b"irrelevant")
    assert extraction_info["num_pages"] == 3
    assert len(chunks) == 3


def test_extract_document_chunks_num_pages_none_for_text():
    chunks, extraction_info = specialized_agent._extract_document_chunks("doc.md", b"some text content")
    assert extraction_info["num_pages"] is None
    assert len(chunks) == 1


# ---------------------------------------------------------------------------
# Paragraph-aware chunking.
# ---------------------------------------------------------------------------

def test_chunk_paragraphs_keeps_short_text_as_one_chunk():
    text = "Paragraph one.\n\nParagraph two.\n\nParagraph three."
    chunks = specialized_agent._chunk_paragraphs(text, chunk_size=1000, overlap=50)
    assert len(chunks) == 1
    assert "Paragraph one." in chunks[0]
    assert "Paragraph three." in chunks[0]


def test_chunk_paragraphs_splits_when_paragraphs_exceed_chunk_size():
    para_a = "A" * 40
    para_b = "B" * 40
    text = f"{para_a}\n\n{para_b}"
    chunks = specialized_agent._chunk_paragraphs(text, chunk_size=50, overlap=10)
    # Each paragraph alone fits in a chunk, but both together don't -> 2 chunks,
    # split cleanly between paragraphs (not mid-word).
    assert len(chunks) == 2
    assert chunks[0] == para_a
    assert chunks[1] == para_b


def test_chunk_paragraphs_falls_back_to_fixed_size_for_oversized_paragraph():
    huge_paragraph = "X" * 500  # no blank lines at all, one giant paragraph
    chunks = specialized_agent._chunk_paragraphs(huge_paragraph, chunk_size=100, overlap=20)
    assert len(chunks) > 1
    assert all(len(c) <= 100 for c in chunks)
    # Overlap: consecutive chunks share a tail/head region.
    assert chunks[0][-20:] == chunks[1][:20]


def test_chunk_paragraphs_empty_text_returns_no_chunks():
    assert specialized_agent._chunk_paragraphs("   ") == []


# ---------------------------------------------------------------------------
# Knowledge base management - purely local (no Gemini calls at all).
# ---------------------------------------------------------------------------

def test_list_custom_documents_empty_when_nothing_uploaded(monkeypatch):
    empty_collection = FakeChromaCollection(initial_count=0)
    _patch_chroma(monkeypatch, empty_collection, name=specialized_agent.CUSTOM_DOCS_COLLECTION_NAME)
    assert specialized_agent.list_custom_documents() == []


def test_list_custom_documents_groups_by_filename_with_type_and_pages(monkeypatch):
    collection = FakeChromaCollection(initial_count=0)
    _patch_chroma(monkeypatch, collection, name=specialized_agent.CUSTOM_DOCS_COLLECTION_NAME)
    collection.add(
        ids=["runbook.md-chunk-0", "policy.pdf-chunk-0", "policy.pdf-chunk-1"],
        embeddings=[[0.1], [0.2], [0.3]],
        documents=["a", "b", "c"],
        metadatas=[
            {"filename": "runbook.md", "chunk_index": 0},
            {"filename": "policy.pdf", "chunk_index": 0, "page_number": 1},
            {"filename": "policy.pdf", "chunk_index": 1, "page_number": 2},
        ],
    )

    docs = specialized_agent.list_custom_documents()

    assert docs == [
        {"filename": "policy.pdf", "file_type": "pdf", "num_chunks": 2, "num_pages": 2},
        {"filename": "runbook.md", "file_type": "text", "num_chunks": 1, "num_pages": None},
    ]


def test_delete_custom_document_removes_only_matching_chunks(monkeypatch):
    collection = FakeChromaCollection(initial_count=0)
    _patch_chroma(monkeypatch, collection, name=specialized_agent.CUSTOM_DOCS_COLLECTION_NAME)
    collection.add(
        ids=["a.txt-chunk-0", "b.txt-chunk-0"],
        embeddings=[[0.1], [0.2]],
        documents=["a", "b"],
        metadatas=[{"filename": "a.txt", "chunk_index": 0}, {"filename": "b.txt", "chunk_index": 0}],
    )

    deleted = specialized_agent.delete_custom_document("a.txt")

    assert deleted == 1
    remaining = specialized_agent.list_custom_documents()
    assert remaining == [{"filename": "b.txt", "file_type": "text", "num_chunks": 1, "num_pages": None}]


def test_delete_custom_document_unknown_filename_deletes_nothing(monkeypatch):
    collection = FakeChromaCollection(initial_count=0)
    _patch_chroma(monkeypatch, collection, name=specialized_agent.CUSTOM_DOCS_COLLECTION_NAME)
    collection.add(
        ids=["a.txt-chunk-0"], embeddings=[[0.1]], documents=["a"],
        metadatas=[{"filename": "a.txt", "chunk_index": 0}],
    )
    assert specialized_agent.delete_custom_document("nonexistent.txt") == 0
    assert collection.count() == 1


def test_clear_knowledge_base_removes_everything_and_returns_count(monkeypatch):
    collection = FakeChromaCollection(initial_count=0)
    _patch_chroma(monkeypatch, collection, name=specialized_agent.CUSTOM_DOCS_COLLECTION_NAME)
    collection.add(
        ids=["a.txt-chunk-0", "b.txt-chunk-0"],
        embeddings=[[0.1], [0.2]],
        documents=["a", "b"],
        metadatas=[{"filename": "a.txt", "chunk_index": 0}, {"filename": "b.txt", "chunk_index": 0}],
    )

    cleared = specialized_agent.clear_knowledge_base()

    assert cleared == 2
    assert specialized_agent.list_custom_documents() == []


def test_clear_knowledge_base_empty_returns_zero(monkeypatch):
    empty_collection = FakeChromaCollection(initial_count=0)
    _patch_chroma(monkeypatch, empty_collection, name=specialized_agent.CUSTOM_DOCS_COLLECTION_NAME)
    assert specialized_agent.clear_knowledge_base() == 0


def test_retrieve_custom_doc_context_empty_when_nothing_uploaded(monkeypatch):
    empty_collection = FakeChromaCollection(initial_count=0)
    _patch_chroma(monkeypatch, empty_collection, name=specialized_agent.CUSTOM_DOCS_COLLECTION_NAME)

    context = specialized_agent._retrieve_custom_doc_context([0.1, 0.2, 0.3])

    assert context == []


def test_retrieve_custom_doc_context_returns_matches_when_populated(monkeypatch):
    populated_collection = FakeChromaCollection(
        initial_count=1,
        query_result={
            "documents": [["runbook excerpt"]],
            "metadatas": [[{"filename": "runbook.md", "chunk_index": 0}]],
            "distances": [[0.15]],
        },
    )
    _patch_chroma(monkeypatch, populated_collection, name=specialized_agent.CUSTOM_DOCS_COLLECTION_NAME)

    context = specialized_agent._retrieve_custom_doc_context([0.1, 0.2, 0.3])

    assert context == [{"text": "runbook excerpt", "filename": "runbook.md", "page_number": None, "distance": 0.15}]


def test_classify_with_llm_include_custom_docs_false_skips_custom_collection_entirely(monkeypatch):
    """Default behavior (existing callers) must never even touch the custom-docs collection."""
    monkeypatch.setenv("GEMINI_API_KEY", "test-key-not-real")

    k = specialized_agent.NUM_FEW_SHOT_EXAMPLES
    few_shot_collection = FakeChromaCollection(
        initial_count=len(specialized_agent.FEW_SHOT_EXAMPLES),
        query_result={
            "documents": [[f"log {i}" for i in range(k)]],
            "metadatas": [[{"log_type": "network_intrusion", "severity": "critical"} for _ in range(k)]],
            "distances": [[0.1 * i for i in range(k)]],
        },
    )
    custom_docs_collection = FakeChromaCollection(initial_count=5)  # would match if ever queried
    _patch_chroma_multi(
        monkeypatch,
        {
            specialized_agent.COLLECTION_NAME: few_shot_collection,
            specialized_agent.CUSTOM_DOCS_COLLECTION_NAME: custom_docs_collection,
        },
    )

    fake_response = SimpleNamespace(
        parsed=specialized_agent.TriageResult(severity="high", confidence_score=0.5, mitigation="x"),
        text=None,
    )
    fake_client = FakeGenaiClient(generate_content_response=fake_response)
    monkeypatch.setattr(specialized_agent.genai, "Client", lambda api_key: fake_client)

    result = specialized_agent.classify_with_llm("some log content")  # include_custom_docs defaults False

    assert result["custom_docs_used"] == []
    assert custom_docs_collection.add_calls == []


def test_classify_with_llm_include_custom_docs_true_uses_custom_collection(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key-not-real")

    k = specialized_agent.NUM_FEW_SHOT_EXAMPLES
    few_shot_collection = FakeChromaCollection(
        initial_count=len(specialized_agent.FEW_SHOT_EXAMPLES),
        query_result={
            "documents": [[f"log {i}" for i in range(k)]],
            "metadatas": [[{"log_type": "network_intrusion", "severity": "critical"} for _ in range(k)]],
            "distances": [[0.1 * i for i in range(k)]],
        },
    )
    custom_docs_collection = FakeChromaCollection(
        initial_count=1,
        query_result={
            "documents": [["custom doc excerpt"]],
            "metadatas": [[{"filename": "policy.md", "chunk_index": 0}]],
            "distances": [[0.22]],
        },
    )
    _patch_chroma_multi(
        monkeypatch,
        {
            specialized_agent.COLLECTION_NAME: few_shot_collection,
            specialized_agent.CUSTOM_DOCS_COLLECTION_NAME: custom_docs_collection,
        },
    )

    fake_response = SimpleNamespace(
        parsed=specialized_agent.TriageResult(severity="high", confidence_score=0.5, mitigation="x"),
        text=None,
    )
    fake_client = FakeGenaiClient(generate_content_response=fake_response)
    monkeypatch.setattr(specialized_agent.genai, "Client", lambda api_key: fake_client)

    result = specialized_agent.classify_with_llm("some log content", include_custom_docs=True)

    assert result["custom_docs_used"] == [{"filename": "policy.md", "page_number": None, "distance": 0.22}]

    # OPTIMIZATION regression check: the log text must be embedded exactly
    # once and that one vector reused for both the few-shot and
    # custom-docs retrievals - not embedded separately for each.
    assert len(fake_client.embed_calls) == 1
    assert fake_client.embed_calls[0][1] == ["some log content"]


def test_classify_with_llm_reuses_cached_client_and_chroma_client_across_calls(monkeypatch):
    """OPTIMIZATION regression check: genai.Client and the Chroma
    PersistentClient must be constructed once per process, not once per
    classify_with_llm() call."""
    monkeypatch.setenv("GEMINI_API_KEY", "test-key-not-real")

    k = specialized_agent.NUM_FEW_SHOT_EXAMPLES
    few_shot_collection = FakeChromaCollection(
        initial_count=len(specialized_agent.FEW_SHOT_EXAMPLES),
        query_result={
            "documents": [[f"log {i}" for i in range(k)]],
            "metadatas": [[{"log_type": "network_intrusion", "severity": "critical"} for _ in range(k)]],
            "distances": [[0.1 * i for i in range(k)]],
        },
    )
    _patch_chroma(monkeypatch, few_shot_collection)

    fake_response = SimpleNamespace(
        parsed=specialized_agent.TriageResult(severity="high", confidence_score=0.5, mitigation="x"),
        text=None,
    )
    client_construction_count = [0]

    def fake_client_factory(api_key):
        client_construction_count[0] += 1
        return FakeGenaiClient(generate_content_response=fake_response)

    monkeypatch.setattr(specialized_agent.genai, "Client", fake_client_factory)
    chroma_construction_count = [0]
    # _patch_chroma already replaced chromadb.PersistentClient with a fake;
    # wrap that (not the real chromadb) so this stays purely a call-count check.
    already_patched_persistent_client = specialized_agent.chromadb.PersistentClient

    def counting_persistent_client(path):
        chroma_construction_count[0] += 1
        return already_patched_persistent_client(path)

    monkeypatch.setattr(specialized_agent.chromadb, "PersistentClient", counting_persistent_client)

    specialized_agent.classify_with_llm("first log")
    specialized_agent.classify_with_llm("second log")

    assert client_construction_count[0] == 1, "genai.Client should be built once and reused, not once per call"
    assert chroma_construction_count[0] == 1, "chromadb.PersistentClient should be built once and reused, not once per call"


# ---------------------------------------------------------------------------
# RETRIEVE: Chroma query result -> structured few-shot example list.
# ---------------------------------------------------------------------------

def test_retrieve_few_shot_formats_chroma_query_result():
    collection = FakeChromaCollection(
        initial_count=3,
        query_result={
            "documents": [["log A", "log B"]],
            "metadatas": [[{"log_type": "network_intrusion", "severity": "high"}, {"log_type": "unknown", "severity": "low"}]],
            "distances": [[0.05, 0.42]],
        },
    )

    examples = specialized_agent._retrieve_few_shot(collection, [0.1, 0.2, 0.3], k=2)

    assert examples == [
        {"text": "log A", "log_type": "network_intrusion", "severity": "high", "distance": 0.05},
        {"text": "log B", "log_type": "unknown", "severity": "low", "distance": 0.42},
    ]


# ---------------------------------------------------------------------------
# Collection build-once caching.
# ---------------------------------------------------------------------------

def test_get_or_build_collection_embeds_and_adds_dataset_when_empty(monkeypatch):
    collection = FakeChromaCollection(initial_count=0)
    _patch_chroma(monkeypatch, collection)
    client = FakeGenaiClient()

    returned = specialized_agent._get_or_build_collection(client)

    assert returned is collection
    assert len(collection.add_calls) == 1
    added = collection.add_calls[0]
    expected_count = len(specialized_agent.FEW_SHOT_EXAMPLES)
    assert len(added["ids"]) == expected_count
    assert len(added["embeddings"]) == expected_count
    assert len(added["documents"]) == expected_count
    assert len(added["metadatas"]) == expected_count
    # Embedding was actually called with the dataset's texts.
    assert len(client.embed_calls) == 1
    assert len(client.embed_calls[0][1]) == expected_count


def test_get_or_build_collection_skips_rebuild_when_already_populated(monkeypatch):
    collection = FakeChromaCollection(initial_count=len(specialized_agent.FEW_SHOT_EXAMPLES))
    _patch_chroma(monkeypatch, collection)
    client = FakeGenaiClient()

    specialized_agent._get_or_build_collection(client)

    assert collection.add_calls == []
    assert client.embed_calls == []  # no embedding work done at all


# ---------------------------------------------------------------------------
# Full pipeline, end to end, entirely mocked.
# ---------------------------------------------------------------------------

def test_classify_with_llm_success_returns_expected_shape(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key-not-real")

    k = specialized_agent.NUM_FEW_SHOT_EXAMPLES
    collection = FakeChromaCollection(
        initial_count=len(specialized_agent.FEW_SHOT_EXAMPLES),
        query_result={
            "documents": [[f"log {i}" for i in range(k)]],
            "metadatas": [[{"log_type": "network_intrusion", "severity": "critical"} for _ in range(k)]],
            "distances": [[0.1 * i for i in range(k)]],
        },
    )
    _patch_chroma(monkeypatch, collection)

    fake_result = specialized_agent.TriageResult(
        severity="critical", confidence_score=0.87, mitigation="Block the offending IP at the firewall."
    )
    fake_response = SimpleNamespace(parsed=fake_result, text=None)
    fake_client = FakeGenaiClient(generate_content_response=fake_response)
    monkeypatch.setattr(specialized_agent.genai, "Client", lambda api_key: fake_client)

    result = specialized_agent.classify_with_llm("some snort-like log content")

    assert result["severity"] == "critical"
    assert result["confidence_score"] == 0.87
    assert result["mitigation"] == "Block the offending IP at the firewall."
    assert result["source"] == f"chroma+{specialized_agent.GENERATION_MODEL}"
    assert isinstance(result["few_shot_examples_used"], list)
    assert len(result["few_shot_examples_used"]) == specialized_agent.NUM_FEW_SHOT_EXAMPLES
    # Confirms the generation call actually used the constrained schema.
    model, contents, config = fake_client.generate_calls[0]
    assert config.response_mime_type == "application/json"
    assert config.response_schema is specialized_agent.TriageResult


def test_classify_with_llm_out_of_range_confidence_raises_value_error(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key-not-real")
    collection = FakeChromaCollection(initial_count=len(specialized_agent.FEW_SHOT_EXAMPLES))
    _patch_chroma(monkeypatch, collection)

    bad_result = specialized_agent.TriageResult(severity="critical", confidence_score=1.7, mitigation="x")
    fake_response = SimpleNamespace(parsed=bad_result, text=None)
    fake_client = FakeGenaiClient(generate_content_response=fake_response)
    monkeypatch.setattr(specialized_agent.genai, "Client", lambda api_key: fake_client)

    with pytest.raises(ValueError, match="out-of-range confidence_score"):
        specialized_agent.classify_with_llm("some log content")


def test_classify_with_llm_malformed_response_raises_value_error(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key-not-real")
    collection = FakeChromaCollection(initial_count=len(specialized_agent.FEW_SHOT_EXAMPLES))
    _patch_chroma(monkeypatch, collection)

    # .parsed is None (SDK couldn't auto-parse) AND .text isn't valid JSON either.
    fake_response = SimpleNamespace(parsed=None, text="not valid json at all")
    fake_client = FakeGenaiClient(generate_content_response=fake_response)
    monkeypatch.setattr(specialized_agent.genai, "Client", lambda api_key: fake_client)

    with pytest.raises(ValueError, match="schema-conforming"):
        specialized_agent.classify_with_llm("some log content")


# ---------------------------------------------------------------------------
# Safety guardrails carried over from triage_agent.py - these were
# previously missing entirely from the specialized (LLM) path.
# ---------------------------------------------------------------------------

def test_classify_with_llm_corrupted_content_refuses_before_any_network_call(monkeypatch):
    """Even with no API key at all, corrupted input must fail with the
    corruption message, not the missing-key message - proving the PLAN-
    style guardrail runs before anything else, same as triage_agent.py."""
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    garbled = "some log text with ��� replacement characters �" * 3

    with pytest.raises(ValueError, match="Corrupted or unparseable"):
        specialized_agent.classify_with_llm(garbled)


def test_classify_with_llm_clean_content_passes_corruption_guard(monkeypatch):
    """Sanity check the guard isn't simply rejecting everything."""
    monkeypatch.setenv("GEMINI_API_KEY", "test-key-not-real")
    collection = FakeChromaCollection(initial_count=len(specialized_agent.FEW_SHOT_EXAMPLES))
    _patch_chroma(monkeypatch, collection)
    fake_response = SimpleNamespace(
        parsed=specialized_agent.TriageResult(severity="low", confidence_score=0.5, mitigation="fine"),
        text=None,
    )
    monkeypatch.setattr(specialized_agent.genai, "Client", lambda api_key: FakeGenaiClient(fake_response))

    result = specialized_agent.classify_with_llm("perfectly clean, readable log text")
    assert result["severity"] == "low"


def test_classify_with_llm_hallucinated_ip_in_mitigation_raises_value_error(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key-not-real")
    collection = FakeChromaCollection(initial_count=len(specialized_agent.FEW_SHOT_EXAMPLES))
    _patch_chroma(monkeypatch, collection)

    # Log genuinely mentions 10.0.0.5, but Gemini's mitigation invents a
    # second IP (203.0.113.99) that never appeared anywhere in the log.
    fake_response = SimpleNamespace(
        parsed=specialized_agent.TriageResult(
            severity="high",
            confidence_score=0.9,
            mitigation="Block 10.0.0.5 and also investigate 203.0.113.99 for lateral movement.",
        ),
        text=None,
    )
    monkeypatch.setattr(specialized_agent.genai, "Client", lambda api_key: FakeGenaiClient(fake_response))

    with pytest.raises(ValueError, match="hallucinated"):
        specialized_agent.classify_with_llm("alert from 10.0.0.5: suspicious activity detected")


def test_classify_with_llm_mitigation_ips_matching_log_pass_the_check(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key-not-real")
    collection = FakeChromaCollection(initial_count=len(specialized_agent.FEW_SHOT_EXAMPLES))
    _patch_chroma(monkeypatch, collection)

    fake_response = SimpleNamespace(
        parsed=specialized_agent.TriageResult(
            severity="high", confidence_score=0.9, mitigation="Block 10.0.0.5 at the firewall."
        ),
        text=None,
    )
    monkeypatch.setattr(specialized_agent.genai, "Client", lambda api_key: FakeGenaiClient(fake_response))

    result = specialized_agent.classify_with_llm("alert from 10.0.0.5: suspicious activity detected")
    assert result["mitigation"] == "Block 10.0.0.5 at the firewall."


def test_triage_result_rejects_out_of_vocabulary_severity():
    with pytest.raises(Exception):  # pydantic.ValidationError, a ValueError subclass
        specialized_agent.TriageResult(severity="Critical", confidence_score=0.9, mitigation="x")
    with pytest.raises(Exception):
        specialized_agent.TriageResult(severity="sev1", confidence_score=0.9, mitigation="x")


def test_triage_result_accepts_each_canonical_severity():
    for level in specialized_agent.SEVERITY_LEVELS:
        result = specialized_agent.TriageResult(severity=level, confidence_score=0.5, mitigation="x")
        assert result.severity == level


# ---------------------------------------------------------------------------
# Embedding dimensionality - configured explicitly rather than left at
# gemini-embedding-001's much larger default.
# ---------------------------------------------------------------------------

def test_embed_texts_requests_configured_output_dimensionality():
    client = FakeGenaiClient()
    specialized_agent._embed_texts(client, ["some text"])
    model, texts, config = client.embed_calls[0]
    assert config.output_dimensionality == specialized_agent.EMBEDDING_DIMENSIONALITY


# ---------------------------------------------------------------------------
# Dimension-mismatch handling: the few-shot collection (a build artifact)
# auto-heals; the custom-docs collection (real user data) never does -
# it fails with clear guidance instead.
# ---------------------------------------------------------------------------

def test_get_or_build_collection_rebuilds_when_stored_dimension_differs(monkeypatch):
    stale_collection = FakeChromaCollection(initial_count=1)
    stale_collection._ids = ["fs-01"]
    stale_collection._metadatas = [{"log_type": "network_intrusion", "severity": "critical"}]
    stale_collection._embeddings = [[0.1] * 3072]  # old dimension, not the current 768 default
    _patch_chroma(monkeypatch, stale_collection)
    client = FakeGenaiClient()

    returned = specialized_agent._get_or_build_collection(client)

    # A fresh collection was built (not the stale one) and repopulated.
    assert returned is not stale_collection
    assert returned.count() == len(specialized_agent.FEW_SHOT_EXAMPLES)


def test_get_or_build_collection_keeps_collection_when_dimension_matches(monkeypatch):
    matching_collection = FakeChromaCollection(initial_count=1)
    matching_collection._ids = ["fs-01"]
    matching_collection._metadatas = [{"log_type": "network_intrusion", "severity": "critical"}]
    matching_collection._embeddings = [[0.1] * specialized_agent.EMBEDDING_DIMENSIONALITY]
    _patch_chroma(monkeypatch, matching_collection)
    client = FakeGenaiClient()

    returned = specialized_agent._get_or_build_collection(client)

    assert returned is matching_collection
    assert returned.count() == 1  # untouched, not rebuilt


def test_add_custom_document_dimension_mismatch_raises_clear_error_without_deleting(monkeypatch):
    """Unlike the few-shot collection, a dimension mismatch on the
    custom-docs collection must NOT auto-delete the user's uploads."""
    monkeypatch.setenv("GEMINI_API_KEY", "test-key-not-real")
    collection = FakeChromaCollection(initial_count=0)

    def failing_add(**kwargs):
        raise specialized_agent.chromadb.errors.InvalidArgumentError(
            "Collection expecting embedding with dimension of 3072, got 768"
        )

    collection.add = failing_add
    _patch_chroma(monkeypatch, collection, name=specialized_agent.CUSTOM_DOCS_COLLECTION_NAME)
    monkeypatch.setattr(specialized_agent.genai, "Client", lambda api_key: FakeGenaiClient())

    with pytest.raises(ValueError, match="clear_knowledge_base"):
        specialized_agent.add_custom_document("doc.md", b"some reference text")
