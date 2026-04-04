"""
Heuristics for deciding whether project-specific Aderyn detectors should surface findings.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Sequence, Set

SENSITIVE_SETTER_DETECTOR = "sensitive-setter-without-guard"

_SENSITIVE_STATE_PATTERN = re.compile(
    r"\b(owner|admin|guardian|operator|signer|keeper|pauser|treasury|recipient|collector|vault|oracle|router|implementation|upgrader|proxy|fee|tax|commission|basispoints|bps|merkle|root|whitelist|blacklist)\b",
    re.IGNORECASE,
)

_SETTER_FUNCTION_PATTERN = re.compile(
    r"\bfunction\s+(set|update|change|configure|rotate|grant|revoke|pause|unpause|initialize)\w*\s*\(",
    re.IGNORECASE,
)

_ACCESS_CONTROL_PATTERN = re.compile(
    r"\b(onlyOwner|onlyAdmin|onlyRole|requiresAuth|hasRole|_checkRole|checkRole|authorized|isAuthorized|canCall)\b",
    re.IGNORECASE,
)

_STATE_VAR_DECL_PATTERN = re.compile(
    r"\b(address|uint(?:8|16|32|64|96|128|160|192|224|256)?|int(?:8|16|32|64|96|128|160|192|224|256)?|bytes32|bytes|string|bool)\b[^;=\n]*\b(public|private|internal)?\s+\w+\s*(?:=|;)",
    re.IGNORECASE,
)


@dataclass
class AderynProjectClassification:
    target_path: str
    solidity_files_scanned: int = 0
    sensitive_state_hits: int = 0
    setter_function_hits: int = 0
    access_control_hits: int = 0
    state_variable_hits: int = 0
    enabled_detectors: Set[str] = field(default_factory=set)
    reasons: List[str] = field(default_factory=list)

    def should_surface(self, detector_name: str) -> bool:
        if detector_name != SENSITIVE_SETTER_DETECTOR:
            return True
        return detector_name in self.enabled_detectors


def classify_project_for_aderyn(target_path: str) -> AderynProjectClassification:
    files = list(_iter_solidity_files(target_path))
    classification = AderynProjectClassification(target_path=os.path.abspath(target_path))
    classification.solidity_files_scanned = len(files)

    if not files:
        classification.reasons.append("no Solidity files found")
        return classification

    for path in files:
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        classification.sensitive_state_hits += len(_SENSITIVE_STATE_PATTERN.findall(content))
        classification.setter_function_hits += len(_SETTER_FUNCTION_PATTERN.findall(content))
        classification.access_control_hits += len(_ACCESS_CONTROL_PATTERN.findall(content))
        classification.state_variable_hits += len(_STATE_VAR_DECL_PATTERN.findall(content))

    if (
        classification.sensitive_state_hits > 0
        and classification.setter_function_hits > 0
        and classification.state_variable_hits > 0
    ):
        classification.enabled_detectors.add(SENSITIVE_SETTER_DETECTOR)
        classification.reasons.append(
            "project has sensitive state variables and public setter-like functions"
        )
    elif classification.sensitive_state_hits > 0 and classification.access_control_hits > 0:
        classification.enabled_detectors.add(SENSITIVE_SETTER_DETECTOR)
        classification.reasons.append(
            "project has privileged state and explicit access-control patterns"
        )
    else:
        classification.reasons.append(
            "project does not look like an admin-configurable protocol target"
        )

    return classification


def filter_aderyn_findings_for_project(
    findings: Sequence[Dict[str, object]],
    classification: AderynProjectClassification,
) -> List[Dict[str, object]]:
    filtered: List[Dict[str, object]] = []
    for finding in findings:
        detector_name = str(
            finding.get("vulnerability_type")
            or finding.get("title")
            or finding.get("name")
            or ""
        )
        if classification.should_surface(detector_name):
            filtered.append(dict(finding))
    return filtered


def format_classification_summary(classification: AderynProjectClassification) -> str:
    status = (
        "enabled"
        if SENSITIVE_SETTER_DETECTOR in classification.enabled_detectors
        else "disabled"
    )
    return (
        f"{SENSITIVE_SETTER_DETECTOR}={status} "
        f"(files={classification.solidity_files_scanned}, "
        f"sensitive={classification.sensitive_state_hits}, "
        f"setters={classification.setter_function_hits}, "
        f"access={classification.access_control_hits})"
    )


def _iter_solidity_files(target_path: str) -> Iterable[Path]:
    path = Path(target_path)
    if path.is_file() and path.suffix.lower() == ".sol":
        yield path
        return

    if not path.is_dir():
        return

    for sol_file in path.glob("**/*.sol"):
        if any(part in {"lib", "node_modules", "vendor", "dist", "out", "build"} for part in sol_file.parts):
            continue
        yield sol_file
