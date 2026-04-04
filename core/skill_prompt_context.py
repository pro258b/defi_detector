"""
Helpers for turning markdown skills into compact LLM prompt context.
"""

import re
from typing import Any, Dict, List

from core.skill_loader import Skill, SkillLoader


def build_skill_prompt_sections(
    contract_content: str,
    static_results: Dict[str, Any],
    max_skills: int = 3,
) -> Dict[str, str]:
    """Build reusable prompt sections from the best-matching local skills."""
    try:
        loader = SkillLoader()
        loaded_skills = loader.load_skills()
    except Exception:
        return {
            "selected_skill_ids": [],
            "summary": "",
            "one_shot": "",
            "pass1": "",
            "pass2": "",
            "pass3": "",
            "pass3_5": "",
            "pass4": "",
            "pass5": "",
        }

    if not loaded_skills:
        return {
            "selected_skill_ids": [],
            "summary": "",
            "one_shot": "",
            "pass1": "",
            "pass2": "",
            "pass3": "",
            "pass3_5": "",
            "pass4": "",
            "pass5": "",
        }

    query = _build_skill_query(contract_content, static_results)
    matches = loader.search(query, loaded_skills, limit=max_skills)
    selected_skills = [match.skill for match in matches]
    if not selected_skills:
        selected_skills = loaded_skills[:max_skills]

    summary = _format_skill_summary(selected_skills)
    sections = {
        "selected_skill_ids": [skill.id for skill in selected_skills],
        "summary": summary,
        "one_shot": _format_skill_guidance(selected_skills, "one_shot", 4200),
        "pass1": _format_skill_guidance(selected_skills, "pass1", 1400),
        "pass2": _format_skill_guidance(selected_skills, "pass2", 1100),
        "pass3": _format_skill_guidance(selected_skills, "pass3", 3000),
        "pass3_5": _format_skill_guidance(selected_skills, "pass3_5", 2200),
        "pass4": _format_skill_guidance(selected_skills, "pass4", 2200),
        "pass5": _format_skill_guidance(selected_skills, "pass5", 2000),
    }
    return sections


def _build_skill_query(contract_content: str, static_results: Dict[str, Any]) -> str:
    """Build a search query from the contract and current analysis context."""
    query_parts: List[str] = ["solidity", "security", "audit", "vulnerability"]

    lowered = contract_content.lower()
    keyword_map = {
        "reentrancy": ["reentrancy", "nonreentrant", "call{value", ".call{", "erc777", "erc1155"],
        "access control": ["onlyowner", "accesscontrol", "owner", "admin", "role"],
        "flash loan": ["flash loan", "flashloan"],
        "oracle": ["oracle", "chainlink", "latestRoundData", "pricefeed", "twap"],
        "signature": ["signature", "ecrecover", "permit", "eip712"],
        "erc20": ["erc20", "transferfrom", "safeerc20", "approve"],
        "upgradeable": ["initializer", "uups", "upgrade", "proxy"],
    }
    for label, needles in keyword_map.items():
        if any(needle.lower() in lowered for needle in needles):
            query_parts.append(label)

    for vuln in static_results.get("vulnerabilities", [])[:12]:
        if isinstance(vuln, dict):
            vuln_type = (
                vuln.get("vulnerability_type")
                or vuln.get("title")
                or vuln.get("category")
                or ""
            )
        else:
            vuln_type = getattr(vuln, "vulnerability_type", "") or getattr(vuln, "title", "")
        if vuln_type:
            query_parts.append(str(vuln_type))

    return " ".join(query_parts)


def _format_skill_summary(skills: List[Skill]) -> str:
    if not skills:
        return ""
    lines = ["## Selected Audit Skills"]
    for skill in skills:
        lines.append(f"- {skill.id}: {skill.description}")
    return "\n".join(lines)


def _format_skill_guidance(skills: List[Skill], mode: str, max_chars: int) -> str:
    if not skills:
        return ""

    header_map = {
        "one_shot": "## Additional Audit Skills",
        "pass1": "## Audit Skill Lens",
        "pass2": "## Audit Skill Lens",
        "pass3": "## Skill-Guided Exploit and Invariant Checks",
        "pass3_5": "## Skill-Guided Cross-Contract Checks",
        "pass4": "## Skill-Guided Cross-Function Checks",
        "pass5": "## Skill-Guided Adversarial Checks",
    }
    lines = [header_map.get(mode, "## Audit Skills")]

    for skill in skills:
        excerpt = _extract_relevant_excerpt(skill.content, mode)
        lines.append(f"### {skill.name}")
        lines.append(f"Description: {skill.description}")
        if excerpt:
            lines.append(excerpt)
        lines.append("")

    text = "\n".join(lines).strip()
    if len(text) <= max_chars:
        return text
    return text[:max_chars].rstrip() + "\n...[skill guidance truncated]"


def _extract_relevant_excerpt(content: str, mode: str) -> str:
    """Extract a compact excerpt from skill markdown."""
    lines = [line.rstrip() for line in content.splitlines()]
    collected: List[str] = []
    line_limit = {
        "one_shot": 28,
        "pass1": 10,
        "pass2": 8,
        "pass3": 20,
        "pass3_5": 14,
        "pass4": 14,
        "pass5": 12,
    }.get(mode, 10)

    section_keywords = {
        "pass1": ("description", "analysis framework", "quick triage", "core capabilities"),
        "pass2": ("quick triage", "code review checklist", "access", "state"),
        "pass3": ("vulnerab", "checklist", "oracle", "flash", "reentr", "access", "input"),
        "pass3_5": ("cross-chain", "bridge", "third-party", "dependency", "multi-contract", "trust boundary"),
        "pass4": ("reentr", "state", "shared", "same-block", "callback"),
        "pass5": ("flash", "attack", "exploit", "mev", "oracle", "governance"),
    }

    keywords = section_keywords.get(mode, tuple())
    current_heading = ""
    for line in lines:
        normalized = line.strip()
        if not normalized:
            continue
        if normalized.startswith("#"):
            current_heading = normalized.lstrip("#").strip().lower()
            continue

        if mode == "one_shot":
            collected.append(normalized)
        else:
            haystack = f"{current_heading} {normalized.lower()}"
            if any(keyword in haystack for keyword in keywords):
                collected.append(normalized)

        if len(collected) >= line_limit:
            break

    if not collected:
        for line in lines:
            normalized = line.strip()
            if normalized and not normalized.startswith("#"):
                collected.append(normalized)
            if len(collected) >= min(8, line_limit):
                break

    text = "\n".join(collected)
    text = re.sub(r"\n{3,}", "\n\n", text).strip()
    return text
