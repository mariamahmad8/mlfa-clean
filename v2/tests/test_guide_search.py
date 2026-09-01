import tempfile
import unittest
from pathlib import Path

from engine.guide_search import (
    GuideSentence,
    SemanticGuideSearch,
    dot_product,
    load_guide_sentences,
    load_interface_sentences,
    normalized,
    rank_sentences,
    split_sentences,
)


class GuideSearchTests(unittest.TestCase):
    def test_split_sentences_preserves_complete_thoughts(self):
        result = split_sentences("Open Settings. Choose Categories. Click Add category.")
        self.assertEqual(result, [
            "Open Settings.",
            "Choose Categories.",
            "Click Add category.",
        ])

    def test_home_template_contains_sentence_chunks_for_category_walkthrough(self):
        sentences = load_guide_sentences()
        matches = [
            sentence for sentence in sentences
            if sentence.panel == "how-to" and sentence.title == "Adding a new category"
        ]

        self.assertGreater(len(matches), 3)
        self.assertTrue(any("+ Add category" in sentence.text for sentence in matches))
        self.assertTrue(any("Test & preview" in sentence.text for sentence in matches))
        self.assertTrue(all(sentence.anchor == "s-categories" for sentence in matches))

    def test_interface_controls_are_automatically_searchable(self):
        with tempfile.TemporaryDirectory() as directory:
            template = Path(directory) / "categories.html"
            template.write_text("""
                <main><h1 class="page-title">Category rules</h1>
                <button>Add category</button>
                <script>
                  const row = `<button onclick="deleteRule(1)">Delete</button>`;
                  confirm(`Delete "${label}"? Future emails will no longer use it.`);
                </script></main>
            """, encoding="utf-8")

            sentences = load_interface_sentences(Path(directory))

        text = " ".join(sentence.text for sentence in sentences)
        self.assertIn('control labeled "Delete"', text)
        self.assertIn("Future emails will no longer use it", text)
        self.assertTrue(all(sentence.anchor == "s-categories" for sentence in sentences))

    def test_normalized_dot_product_is_cosine_similarity(self):
        left = normalized([3.0, 0.0])
        right = normalized([9.0, 0.0])
        self.assertAlmostEqual(dot_product(left, right), 1.0)

    def test_ranking_uses_dot_product_and_panel_filter(self):
        category = GuideSentence("how-to", "categories", 0, "Add", "Categories", "Add one.", 0)
        security = GuideSentence("security", "auth", 0, "MFA", "Security", "Sign in.", 1)
        audit = GuideSentence("how-to", "audit", 0, "Audit", "Audit", "View history.", 2)

        ranked = rank_sentences(
            [category, security, audit],
            [normalized([1.0, 0.0]), normalized([1.0, 0.0]), normalized([0.0, 1.0])],
            [0.9, 0.1],
            "how-to",
        )

        self.assertEqual([sentence.title for sentence, _ in ranked], ["Add", "Audit"])

    def test_guide_is_embedded_once_and_answers_use_retrieved_sentences(self):
        html = """
        <div class="page-panel" data-panel="how-to"><div class="guide-body">
          <section id="categories"><h2>Categories</h2><p>Open Settings.</p>
          <h3>Add category</h3><p>Click Add category.</p></section>
        </div></div>
        <div class="page-panel" data-panel="security"><div class="guide-body">
          <section id="auth"><h2>Authentication</h2><p>Microsoft verifies identity.</p></section>
        </div></div>
        """
        with tempfile.TemporaryDirectory() as directory:
            template = Path(directory) / "guide.html"
            template.write_text(html, encoding="utf-8")
            calls = []

            def embed(texts):
                calls.append(list(texts))
                vectors = []
                for text in texts:
                    if not text.startswith("Guide:") or "Topic: Add category" in text:
                        vectors.append([1.0, 0.0])
                    else:
                        vectors.append([0.0, 1.0])
                return vectors

            answer_calls = []

            def answer(question, sentences):
                answer_calls.append((question, sentences))
                return "Click Add category."

            search = SemanticGuideSearch(embedder=embed, answerer=answer, template_path=template)
            first = search.search("How do I add a category?", "how-to")
            search.search("Where are categories?", "how-to")

        # One batch embeds the guide; the following two calls embed only each query.
        self.assertEqual(len(calls), 3)
        self.assertGreater(len(calls[0]), 1)
        self.assertEqual(len(calls[1]), 1)
        self.assertEqual(first[0]["title"], "Add category")
        self.assertGreaterEqual(first[0]["retrieval_ms"], 0)
        self.assertEqual(answer_calls[0][0], "How do I add a category?")
        self.assertIn("Click Add category.", answer_calls[0][1])


if __name__ == "__main__":
    unittest.main()
