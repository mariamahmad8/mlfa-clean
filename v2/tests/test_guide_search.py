import unittest

from engine.guide_search import GuideChunk, dot_product, load_guide_chunks, normalized, rank_chunks


class GuideSearchTests(unittest.TestCase):
    def test_home_template_contains_step_by_step_category_answer(self):
        chunks = load_guide_chunks()
        matches = [
            chunk for chunk in chunks
            if chunk.panel == "how-to" and chunk.title == "Adding a new category"
        ]

        self.assertEqual(len(matches), 1)
        self.assertIn("+ Add category", matches[0].text)
        self.assertIn("Test & preview", matches[0].text)
        self.assertEqual(matches[0].anchor, "s-categories")

    def test_normalized_dot_product_is_cosine_similarity(self):
        left = normalized([3.0, 0.0])
        right = normalized([9.0, 0.0])
        self.assertAlmostEqual(dot_product(left, right), 1.0)

    def test_ranking_uses_semantic_vector_and_panel(self):
        category = GuideChunk("how-to", "categories", 0, "Add category", "Categories", "Steps")
        security = GuideChunk("security", "auth", 0, "MFA", "Security", "Sign in")
        unrelated = GuideChunk("how-to", "audit", 0, "Audit log", "Audit", "History")

        ranked = rank_chunks(
            [category, security, unrelated],
            [[1.0, 0.0], [1.0, 0.0], [0.0, 1.0]],
            [0.9, 0.1],
            "how-to",
        )

        self.assertEqual([chunk.title for chunk, _ in ranked], ["Add category", "Audit log"])


if __name__ == "__main__":
    unittest.main()
