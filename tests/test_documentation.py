from __future__ import annotations

import re
import unittest
from pathlib import Path


REPOSITORY = Path(__file__).resolve().parents[1]
BILINGUAL_DOCUMENTS = (
    "README.md",
    "HIGH-ASSURANCE.md",
    "COMPANION.md",
    "SECURITY.md",
    "ACCEPTANCE.md",
    "SECURITY-ROADMAP.md",
    "PROJECT-STATUS.md",
    "TODO.md",
    "CHANGELOG.md",
    "RELEASE-NOTES.md",
)


class DocumentationTests(unittest.TestCase):
    def sections(self, name: str) -> tuple[str, str]:
        content = (REPOSITORY / name).read_text(encoding="utf-8")
        self.assertEqual(
            content.count("\n---\n"),
            1,
            f"{name} must contain exactly one English/French separator",
        )
        english, french = content.split("\n---\n")
        self.assertNotIn("Français", english.splitlines()[0])
        self.assertIn("Français", french.lstrip().splitlines()[0])
        return english, french

    def marker_count(self, text: str, pattern: str) -> int:
        return len(re.findall(pattern, text, flags=re.MULTILINE))

    def test_public_documents_have_one_to_one_bilingual_structure(self) -> None:
        structural_patterns = (
            r"^#{2,3} ",
            r"^- ",
            r"^\d+\. ",
            r"^```",
            r"^\|",
            r"^- \[[ x]\] ",
        )
        for name in BILINGUAL_DOCUMENTS:
            with self.subTest(document=name):
                english, french = self.sections(name)
                for pattern in structural_patterns:
                    self.assertEqual(
                        self.marker_count(english, pattern),
                        self.marker_count(french, pattern),
                        f"{name} differs between English and French for {pattern}",
                    )
                ratio = len(french) / len(english)
                self.assertGreater(ratio, 0.75, f"{name} French content is incomplete")
                self.assertLess(ratio, 1.60, f"{name} French content unexpectedly diverges")

    def test_security_status_is_equivalent_in_both_languages(self) -> None:
        required_pairs = {
            "README.md": (
                ("archive password", "mot de passe de l'archive"),
                ("one-time token", "jeton à usage unique"),
            ),
            "ACCEPTANCE.md": (
                ("real game traffic", "trafic d'un vrai jeu"),
                ("fresh Debian 13", "Debian 13 neuf"),
            ),
            "SECURITY-ROADMAP.md": (
                ("P-521 is not", "P-521 n'est pas"),
                ("remote TPM attestation", "attestation TPM distante"),
            ),
            "TODO.md": (
                ("same time", "simultanément"),
                ("Completed baseline", "Base terminée"),
            ),
        }
        for name, pairs in required_pairs.items():
            english, french = self.sections(name)
            for english_marker, french_marker in pairs:
                self.assertIn(english_marker, english)
                self.assertIn(french_marker, french)


if __name__ == "__main__":
    unittest.main()
