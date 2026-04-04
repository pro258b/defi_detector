"""
Minimal skill loader for Markdown-based skills.

This MVP supports:
- recursive loading from one or more local folders
- strict YAML frontmatter parsing
- runtime-provided markdown files
- simple weighted search by id/name/tags/triggers/body
- deterministic conflict resolution for duplicate skill ids
"""

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import yaml


FRONTMATTER_RE = re.compile(r"\A---\s*\r?\n(.*?)\r?\n---\s*\r?\n?(.*)\Z", re.DOTALL)
WORD_RE = re.compile(r"[a-z0-9_./+-]+", re.IGNORECASE)


@dataclass
class Skill:
    """Parsed markdown skill."""

    id: str
    name: str
    description: str
    content: str
    path: str
    source: str = "local"
    tags: List[str] = field(default_factory=list)
    triggers: List[str] = field(default_factory=list)
    auto_invoke: bool = False
    priority: int = 50
    version: int = 1
    status: str = "active"
    updated_at: str = ""
    hash: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def searchable_text(self) -> str:
        return " ".join(
            [
                self.id,
                self.name,
                self.description,
                " ".join(self.tags),
                " ".join(self.triggers),
                self.content,
            ]
        ).lower()


@dataclass
class SkillMatch:
    """Search result entry."""

    skill: Skill
    score: int
    reasons: List[str] = field(default_factory=list)


class SkillLoader:
    """Load and search markdown skills from local folders and ad hoc files."""

    def __init__(self, skill_roots: Optional[Sequence[str]] = None):
        if skill_roots:
            self.skill_roots = [Path(root).resolve() for root in skill_roots]
        else:
            self.skill_roots = [Path(__file__).resolve().parents[1] / "skills"]

    def load_skills(
        self,
        additional_paths: Optional[Sequence[str]] = None,
        include_archived: bool = False,
    ) -> List[Skill]:
        """Load skills from configured roots and optional runtime files."""
        skills_by_id: Dict[str, Skill] = {}

        for root in self.skill_roots:
            if not root.exists():
                continue
            for path in sorted(root.rglob("*.md")):
                if not include_archived and "archive" in {part.lower() for part in path.parts}:
                    continue
                skill = self.load_file(path, source="local")
                self._merge_skill(skills_by_id, skill)

        for runtime_path in additional_paths or []:
            skill = self.load_file(runtime_path, source="runtime")
            self._merge_skill(skills_by_id, skill)

        return sorted(
            skills_by_id.values(),
            key=lambda skill: (-skill.priority, skill.id.lower(), skill.path.lower()),
        )

    def load_file(self, path: Any, source: str = "local") -> Skill:
        """Load a single markdown skill from disk."""
        skill_path = Path(path).resolve()
        text = skill_path.read_text(encoding="utf-8")
        return self.parse_markdown(text, path=str(skill_path), source=source)

    def parse_markdown(self, text: str, path: str, source: str = "local") -> Skill:
        """Parse a markdown skill with YAML frontmatter."""
        match = FRONTMATTER_RE.match(text)
        if not match:
            raise ValueError(f"Skill file is missing YAML frontmatter: {path}")

        raw_frontmatter, body = match.groups()
        metadata = yaml.safe_load(raw_frontmatter) or {}
        if not isinstance(metadata, dict):
            raise ValueError(f"Skill frontmatter must be a YAML object: {path}")

        name = self._require_string(metadata, "name", path)
        description = self._require_string(metadata, "description", path)
        skill_id = self._normalize_skill_id(metadata.get("id") or name)

        tags = self._normalize_string_list(metadata.get("tags"))
        triggers = self._normalize_string_list(metadata.get("triggers"))
        auto_invoke = bool(metadata.get("auto_invoke", False))
        priority = int(metadata.get("priority", 50))
        version = int(metadata.get("version", 1))
        status = str(metadata.get("status", "active"))
        updated_at = str(metadata.get("updated_at", ""))

        body = body.strip()
        return Skill(
            id=skill_id,
            name=name,
            description=description,
            content=body,
            path=path,
            source=source,
            tags=tags,
            triggers=triggers,
            auto_invoke=auto_invoke,
            priority=priority,
            version=version,
            status=status,
            updated_at=updated_at,
            hash=self._content_hash(text),
            metadata=metadata,
        )

    def get_skill(
        self,
        skill_id_or_name: str,
        loaded_skills: Optional[Sequence[Skill]] = None,
    ) -> Optional[Skill]:
        """Return the best exact match by id or name."""
        needle = skill_id_or_name.strip().lower()
        for skill in loaded_skills or self.load_skills():
            if skill.id.lower() == needle or skill.name.lower() == needle:
                return skill
        return None

    def search(
        self,
        query: str,
        loaded_skills: Optional[Sequence[Skill]] = None,
        limit: int = 10,
    ) -> List[SkillMatch]:
        """Search skills with a simple weighted ranking model."""
        terms = self._tokenize(query)
        if not terms:
            return []

        matches: List[SkillMatch] = []
        for skill in loaded_skills or self.load_skills():
            score, reasons = self._score_skill(skill, terms)
            if score > 0:
                matches.append(SkillMatch(skill=skill, score=score, reasons=reasons))

        matches.sort(
            key=lambda match: (
                -match.score,
                -match.skill.priority,
                match.skill.id.lower(),
            )
        )
        return matches[:limit]

    def save_downloaded_markdown(
        self,
        markdown_text: str,
        filename: str,
        category: Optional[str] = None,
    ) -> str:
        """Persist a downloaded markdown skill into the local skill store."""
        root = self.skill_roots[0]
        target_dir = root / category if category else root
        target_dir.mkdir(parents=True, exist_ok=True)

        safe_name = Path(filename).stem
        safe_name = re.sub(r"[^a-zA-Z0-9._-]+", "-", safe_name).strip("-")
        if not safe_name:
            raise ValueError("filename must produce a non-empty safe path")

        target_path = (target_dir / f"{safe_name}.md").resolve()
        target_path.write_text(markdown_text, encoding="utf-8")
        return str(target_path)

    def _merge_skill(self, skills_by_id: Dict[str, Skill], candidate: Skill) -> None:
        existing = skills_by_id.get(candidate.id)
        if existing is None or self._is_better_candidate(candidate, existing):
            skills_by_id[candidate.id] = candidate

    @staticmethod
    def _is_better_candidate(candidate: Skill, existing: Skill) -> bool:
        source_rank = {"runtime": 3, "downloaded": 2, "local": 1}
        candidate_key = (
            source_rank.get(candidate.source, 0),
            candidate.version,
            candidate.updated_at,
            candidate.priority,
            candidate.hash,
        )
        existing_key = (
            source_rank.get(existing.source, 0),
            existing.version,
            existing.updated_at,
            existing.priority,
            existing.hash,
        )
        return candidate_key > existing_key

    def _score_skill(self, skill: Skill, terms: Sequence[str]) -> Tuple[int, List[str]]:
        score = 0
        reasons: List[str] = []
        search_blob = skill.searchable_text

        for term in terms:
            if skill.id.lower() == term:
                score += 100
                reasons.append(f"id:{term}")
            elif term in skill.id.lower():
                score += 60
                reasons.append(f"id-part:{term}")

            if term == skill.name.lower():
                score += 70
                reasons.append(f"name:{term}")
            elif term in skill.name.lower():
                score += 35
                reasons.append(f"name-part:{term}")

            if term in [tag.lower() for tag in skill.tags]:
                score += 30
                reasons.append(f"tag:{term}")

            if term in [trigger.lower() for trigger in skill.triggers]:
                score += 40
                reasons.append(f"trigger:{term}")

            if term in skill.description.lower():
                score += 20
                reasons.append(f"description:{term}")
            elif term in search_blob:
                score += 5
                reasons.append(f"body:{term}")

        score += skill.priority
        return score, reasons

    @staticmethod
    def _normalize_skill_id(value: str) -> str:
        normalized = re.sub(r"[^a-z0-9]+", "-", value.strip().lower()).strip("-")
        if not normalized:
            raise ValueError("skill id/name must produce a non-empty id")
        return normalized

    @staticmethod
    def _require_string(metadata: Dict[str, Any], key: str, path: str) -> str:
        value = metadata.get(key)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"Skill frontmatter field '{key}' is required: {path}")
        return value.strip()

    @staticmethod
    def _normalize_string_list(value: Any) -> List[str]:
        if value is None:
            return []
        if isinstance(value, str):
            return [value.strip()] if value.strip() else []
        if isinstance(value, list):
            return [str(item).strip() for item in value if str(item).strip()]
        raise ValueError("tags/triggers must be a string or list of strings")

    @staticmethod
    def _content_hash(text: str) -> str:
        return hashlib.md5(text.encode("utf-8")).hexdigest()

    @staticmethod
    def _tokenize(text: str) -> List[str]:
        return [token.lower() for token in WORD_RE.findall(text or "")]
