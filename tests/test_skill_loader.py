import tempfile
import unittest
from pathlib import Path

from core.skill_loader import SkillLoader


class TestSkillLoader(unittest.TestCase):
    def setUp(self):
        self.loader = SkillLoader()

    def test_loads_existing_skills_folder(self):
        skills = self.loader.load_skills()
        ids = {skill.id for skill in skills}
        self.assertIn("solidity-audit", ids)
        self.assertIn("solidity-security", ids)
        self.assertGreaterEqual(len(skills), 2)

    def test_get_skill_by_id(self):
        skills = self.loader.load_skills()
        skill = self.loader.get_skill("solidity-audit", skills)
        self.assertIsNotNone(skill)
        self.assertEqual(skill.name, "solidity-audit")

    def test_search_finds_security_skill(self):
        skills = self.loader.load_skills()
        matches = self.loader.search("private key reentrancy", skills)
        self.assertGreater(len(matches), 0)
        self.assertEqual(matches[0].skill.id, "solidity-security")

    def test_runtime_file_overrides_same_id(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            runtime_path = Path(tmpdir) / "audit_override.md"
            runtime_path.write_text(
                """---
name: solidity-audit
description: Runtime override
priority: 99
version: 2
updated_at: 2026-04-05
---

# Override

Runtime content.
""",
                encoding="utf-8",
            )
            skills = self.loader.load_skills(additional_paths=[str(runtime_path)])
            skill = self.loader.get_skill("solidity-audit", skills)
            self.assertIsNotNone(skill)
            self.assertEqual(skill.description, "Runtime override")
            self.assertEqual(skill.source, "runtime")

    def test_save_downloaded_markdown(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            loader = SkillLoader(skill_roots=[tmpdir])
            path = loader.save_downloaded_markdown(
                """---
name: bridge-review
description: Bridge review skill
tags: [bridge, security]
---

# Bridge Review
""",
                filename="bridge-review.md",
                category="defi",
            )
            saved = Path(path)
            self.assertTrue(saved.exists())
            self.assertEqual(saved.parent.name, "defi")
            skill = loader.load_file(saved)
            self.assertEqual(skill.id, "bridge-review")

    def test_missing_frontmatter_raises(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            bad_path = Path(tmpdir) / "bad.md"
            bad_path.write_text("# Missing frontmatter", encoding="utf-8")
            with self.assertRaises(ValueError):
                self.loader.load_file(bad_path)
