"""Semantic search over the authored Hub and security guides."""

from __future__ import annotations

import math
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from bs4 import BeautifulSoup

from adapters import openai_client


GUIDE_TEMPLATE = Path(__file__).resolve().parents[1] / "templates" / "home.html"
ALLOWED_PANELS = {"how-to", "security"}


@dataclass(frozen=True)
class GuideChunk:
    panel: str
    anchor: str
    heading_index: int
    title: str
    section_title: str
    text: str

    @property
    def embedding_text(self) -> str:
        return (
            f"Guide: {self.panel}\n"
            f"Section: {self.section_title}\n"
            f"Answer heading: {self.title}\n"
            f"Instructions: {self.text}"
        )


def _clean_text(value: str) -> str:
    return " ".join((value or "").split())


def load_guide_chunks(template_path: Path = GUIDE_TEMPLATE) -> list[GuideChunk]:
    """Split each guide section into heading-sized searchable answers."""
    soup = BeautifulSoup(template_path.read_text(encoding="utf-8"), "html.parser")
    chunks: list[GuideChunk] = []

    for panel_node in soup.select(".page-panel[data-panel]"):
        panel = panel_node.get("data-panel", "")
        if panel not in ALLOWED_PANELS:
            continue

        for section in panel_node.select(".guide-body section[id]"):
            anchor = section.get("id", "")
            headings = section.find_all(["h2", "h3"], recursive=False)
            if not anchor or not headings:
                continue

            section_title = _clean_text(headings[0].get_text(" ", strip=True))
            for heading_index, heading in enumerate(headings):
                content_parts: list[str] = []
                for sibling in heading.next_siblings:
                    sibling_name = getattr(sibling, "name", None)
                    if sibling_name in {"h2", "h3"}:
                        break
                    if hasattr(sibling, "get_text"):
                        content_parts.append(sibling.get_text(" ", strip=True))

                title = _clean_text(heading.get_text(" ", strip=True))
                text = _clean_text(" ".join(content_parts))
                if not text:
                    text = f"Open {section_title} for details about {title}."
                chunks.append(
                    GuideChunk(
                        panel=panel,
                        anchor=anchor,
                        heading_index=heading_index,
                        title=title,
                        section_title=section_title,
                        text=text,
                    )
                )

    if not chunks:
        raise RuntimeError("No searchable guide sections were found.")
    return chunks


def normalized(vector: list[float]) -> list[float]:
    """L2-normalize a vector so its dot product is cosine similarity."""
    magnitude = math.sqrt(sum(value * value for value in vector))
    if magnitude == 0:
        raise ValueError("Cannot normalize a zero-length embedding.")
    return [value / magnitude for value in vector]


def dot_product(left: list[float], right: list[float]) -> float:
    if len(left) != len(right):
        raise ValueError("Embedding vectors must have equal dimensions.")
    return sum(a * b for a, b in zip(left, right))


def rank_chunks(
    chunks: list[GuideChunk],
    chunk_vectors: list[list[float]],
    query_vector: list[float],
    panel: str,
) -> list[tuple[GuideChunk, float]]:
    """Rank chunks by cosine similarity, highest score first."""
    query = normalized(query_vector)
    ranked = []
    for chunk, vector in zip(chunks, chunk_vectors):
        if chunk.panel == panel:
            ranked.append((chunk, dot_product(normalized(vector), query)))
    return sorted(ranked, key=lambda item: item[1], reverse=True)


class SemanticGuideSearch:
    """Build and cache guide embeddings, then embed only each new question."""

    def __init__(
        self,
        embedder: Callable[[list[str]], list[list[float]]] = openai_client.embed_texts,
        template_path: Path = GUIDE_TEMPLATE,
    ) -> None:
        self._embedder = embedder
        self._template_path = template_path
        self._lock = threading.Lock()
        self._template_mtime: float | None = None
        self._chunks: list[GuideChunk] = []
        self._vectors: list[list[float]] = []

    def _ensure_index(self) -> None:
        template_mtime = self._template_path.stat().st_mtime
        if self._vectors and self._template_mtime == template_mtime:
            return

        with self._lock:
            template_mtime = self._template_path.stat().st_mtime
            if self._vectors and self._template_mtime == template_mtime:
                return
            chunks = load_guide_chunks(self._template_path)
            vectors = self._embedder([chunk.embedding_text for chunk in chunks])
            if len(vectors) != len(chunks):
                raise RuntimeError("Guide embedding count did not match the guide index.")
            self._chunks = chunks
            self._vectors = vectors
            self._template_mtime = template_mtime

    def search(self, query: str, panel: str, limit: int = 3) -> list[dict]:
        clean_query = _clean_text(query)
        if not clean_query:
            raise ValueError("A question is required.")
        if panel not in ALLOWED_PANELS:
            raise ValueError("Unknown guide panel.")

        self._ensure_index()
        query_vector = self._embedder([clean_query])[0]
        ranked = rank_chunks(self._chunks, self._vectors, query_vector, panel)

        results = []
        for chunk, score in ranked[: max(1, min(limit, 5))]:
            answer = chunk.text
            if len(answer) > 420:
                answer = answer[:417].rsplit(" ", 1)[0] + "..."
            results.append(
                {
                    "panel": chunk.panel,
                    "anchor": chunk.anchor,
                    "heading_index": chunk.heading_index,
                    "title": chunk.title,
                    "section_title": chunk.section_title,
                    "answer": answer,
                    "score": round(score, 4),
                }
            )
        return results


guide_search = SemanticGuideSearch()
