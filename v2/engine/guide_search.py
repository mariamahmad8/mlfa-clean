"""Sentence-based semantic search over the Hub guides and interface text."""

from __future__ import annotations

import math
import re
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from bs4 import BeautifulSoup

from adapters import openai_client


GUIDE_TEMPLATE = Path(__file__).resolve().parents[1] / "templates" / "home.html"
ALLOWED_PANELS = {"how-to", "security"}
_SENTENCE_BREAK = re.compile(r"(?<=[.!?])\s+")
_ABBREVIATION = re.compile(r"\b(?:e\.g|i\.e|Mr|Mrs|Ms|Dr|vs|etc|U\.S)\.", re.IGNORECASE)
_UI_ANCHORS = {
    "audit": "s-audit",
    "categories": "s-categories",
    "inboxes": "s-inboxes",
    "recipients": "s-recipients",
    "templates": "s-templates",
    "users": "s-users",
}


@dataclass(frozen=True)
class GuideSentence:
    panel: str
    anchor: str
    heading_index: int
    title: str
    section_title: str
    text: str
    source_order: int

    @property
    def embedding_text(self) -> str:
        return (
            f"Guide: {self.panel}\n"
            f"Section: {self.section_title}\n"
            f"Topic: {self.title}\n"
            f"Sentence: {self.text}"
        )


def _clean_text(value: str) -> str:
    return " ".join((value or "").split())


def split_sentences(text: str) -> list[str]:
    """Split prose at sentence boundaries without adding a language dependency."""
    clean = _clean_text(text)
    if not clean:
        return []

    protected: dict[str, str] = {}

    def protect(match: re.Match) -> str:
        token = f"__ABBR_{len(protected)}__"
        protected[token] = match.group(0)
        return token

    safe = _ABBREVIATION.sub(protect, clean)
    sentences = []
    for part in _SENTENCE_BREAK.split(safe):
        for token, original in protected.items():
            part = part.replace(token, original)
        part = _clean_text(part)
        if part:
            sentences.append(part)
    return sentences


def _content_units_after_heading(heading) -> list[str]:
    """Preserve list items and table rows as independent sentence candidates."""
    units: list[str] = []
    for sibling in heading.next_siblings:
        name = getattr(sibling, "name", None)
        if name in {"h2", "h3"}:
            break
        if not hasattr(sibling, "get_text"):
            continue
        if name in {"ul", "ol"}:
            nodes = sibling.find_all("li", recursive=False)
        elif name == "table":
            nodes = sibling.find_all("tr")
        else:
            nodes = [sibling]
        for node in nodes:
            value = _clean_text(node.get_text(" ", strip=True))
            if value:
                units.append(value)
    return units


def load_guide_sentences(template_path: Path = GUIDE_TEMPLATE) -> list[GuideSentence]:
    """Read the guide and turn every authored sentence into one search chunk."""
    soup = BeautifulSoup(template_path.read_text(encoding="utf-8"), "html.parser")
    chunks: list[GuideSentence] = []
    source_order = 0

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
                title = _clean_text(heading.get_text(" ", strip=True))
                sentences = [
                    sentence
                    for unit in _content_units_after_heading(heading)
                    for sentence in split_sentences(unit)
                ]
                if not sentences:
                    sentences = [f"Open {section_title} for details about {title}."]

                for sentence in sentences:
                    chunks.append(GuideSentence(
                        panel=panel,
                        anchor=anchor,
                        heading_index=heading_index,
                        title=title,
                        section_title=section_title,
                        text=sentence,
                        source_order=source_order,
                    ))
                    source_order += 1

    if not chunks or {chunk.panel for chunk in chunks} != ALLOWED_PANELS:
        raise RuntimeError("Both searchable guide panels must contain authored sentences.")
    return chunks


def _visible_fragment_text(fragment: str) -> str:
    text = BeautifulSoup(fragment, "html.parser").get_text(" ", strip=True)
    text = re.sub(r"\$\{[^}]+\}", "", text)
    return _clean_text(text).lstrip("+ ")


def load_interface_sentences(
    template_dir: Path,
    source_order: int = 0,
) -> list[GuideSentence]:
    """Create searchable facts from user-facing controls and help text."""
    chunks: list[GuideSentence] = []

    for path in sorted(template_dir.glob("*.html")):
        if path.name == "home.html" or path.name.startswith("_"):
            continue

        raw = path.read_text(encoding="utf-8")
        soup = BeautifulSoup(raw, "html.parser")
        heading = soup.select_one("h1.page-title, main h1, h1")
        if not heading:
            continue

        page_title = _clean_text(heading.get_text(" ", strip=True))
        if not page_title:
            continue

        anchor = _UI_ANCHORS.get(path.stem, "overview")
        title = f"{page_title} controls"
        facts: list[str] = []

        # Regex also sees controls rendered later from JavaScript template strings.
        for fragment in re.findall(r"<button\b[^>]*>(.*?)</button>", raw, re.I | re.S):
            label = _visible_fragment_text(fragment)
            if label and len(label) <= 100:
                facts.append(
                    f'On the {page_title} page, a control labeled "{label}" is available.'
                )

        for node in soup.select(".page-subtitle, .info-content"):
            facts.extend(split_sentences(node.get_text(" ", strip=True)))

        # Confirmation text explains the consequence of destructive UI actions.
        confirmation_text = re.findall(r"confirm\(\s*`([^`]*)`\s*\)", raw, re.S)
        confirmation_text += re.findall(r"confirm\(\s*'([^']*)'\s*\)", raw, re.S)
        for message in confirmation_text:
            message = re.sub(r"\$\{[^}]+\}", "selected", message)
            message = _clean_text(message)
            if message:
                facts.append(f"The {page_title} page may ask for confirmation: {message}")

        for fact in dict.fromkeys(facts):
            chunks.append(GuideSentence(
                panel="how-to",
                anchor=anchor,
                heading_index=0,
                title=title,
                section_title=page_title,
                text=fact,
                source_order=source_order,
            ))
            source_order += 1

    return chunks


def load_search_sentences(template_path: Path = GUIDE_TEMPLATE) -> list[GuideSentence]:
    """Combine authored instructions with automatically discovered UI facts."""
    sentences = load_guide_sentences(template_path)
    sentences.extend(load_interface_sentences(
        template_path.parent,
        source_order=len(sentences),
    ))
    return sentences


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


def rank_sentences(
    sentences: list[GuideSentence],
    sentence_vectors: list[list[float]],
    query_vector: list[float],
    panel: str,
) -> list[tuple[GuideSentence, float]]:
    """Rank individual sentences by normalized dot product."""
    query = normalized(query_vector)
    ranked = [
        (sentence, dot_product(vector, query))
        for sentence, vector in zip(sentences, sentence_vectors)
        if sentence.panel == panel
    ]
    return sorted(ranked, key=lambda item: item[1], reverse=True)


class SemanticGuideSearch:
    """Embed the guide once per process/template version, then answer questions."""

    def __init__(
        self,
        embedder: Callable[[list[str]], list[list[float]]] = openai_client.embed_texts,
        answerer: Callable[[str, list[str]], str] = openai_client.answer_guide_question,
        template_path: Path = GUIDE_TEMPLATE,
    ) -> None:
        self._embedder = embedder
        self._answerer = answerer
        self._template_path = template_path
        self._lock = threading.Lock()
        self._source_version: tuple[tuple[str, int], ...] | None = None
        self._sentences: list[GuideSentence] = []
        self._vectors: list[list[float]] = []

    def _ensure_index(self) -> None:
        source_version = self._current_source_version()
        if self._vectors and self._source_version == source_version:
            return

        with self._lock:
            source_version = self._current_source_version()
            if self._vectors and self._source_version == source_version:
                return
            sentences = load_search_sentences(self._template_path)
            vectors: list[list[float]] = []
            for start in range(0, len(sentences), 128):
                batch = sentences[start:start + 128]
                vectors.extend(self._embedder([sentence.embedding_text for sentence in batch]))
            if len(vectors) != len(sentences):
                raise RuntimeError("Guide embedding count did not match the sentence index.")
            self._sentences = sentences
            self._vectors = [normalized(vector) for vector in vectors]
            self._source_version = source_version

    def _current_source_version(self) -> tuple[tuple[str, int], ...]:
        paths = sorted(self._template_path.parent.glob("*.html"))
        if self._template_path not in paths:
            paths.append(self._template_path)
        return tuple((str(path), path.stat().st_mtime_ns) for path in paths)

    def search(self, query: str, panel: str, limit: int = 8) -> list[dict]:
        clean_query = _clean_text(query)
        if not clean_query:
            raise ValueError("A question is required.")
        if panel not in ALLOWED_PANELS:
            raise ValueError("Unknown guide panel.")

        self._ensure_index()
        query_vector = self._embedder([clean_query])[0]
        retrieval_started = time.perf_counter()
        ranked = rank_sentences(
            self._sentences,
            self._vectors,
            query_vector,
            panel,
        )
        retrieval_ms = (time.perf_counter() - retrieval_started) * 1000
        selected = ranked[:max(1, min(limit, 12))]
        if not selected:
            return []

        # Preserve the guide's original order so procedural steps remain readable.
        context = [
            sentence.text
            for sentence, _ in sorted(selected, key=lambda item: item[0].source_order)
        ]
        answer = self._answerer(clean_query, context)
        source, score = selected[0]
        return [{
            "panel": source.panel,
            "anchor": source.anchor,
            "heading_index": source.heading_index,
            "title": source.title,
            "section_title": source.section_title,
            "answer": answer,
            "score": round(score, 4),
            "retrieval_ms": round(retrieval_ms, 3),
        }]


guide_search = SemanticGuideSearch()
