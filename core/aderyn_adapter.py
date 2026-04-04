"""
Aderyn adapter for Aether.

Runs the external Aderyn CLI, parses JSON reports, and normalizes findings into
the shape used by Aether's static-analysis pipeline.
"""

import json
import logging
import os
import platform
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from core.file_handler import get_tool_env

logger = logging.getLogger(__name__)


@dataclass
class AderynIssueInstance:
    """Single issue location reported by Aderyn."""

    contract_path: str
    line_no: int
    src: str = ""
    src_char: str = ""
    src_char2: str = ""
    hint: Optional[str] = None


@dataclass
class AderynIssue:
    """Logical issue reported by Aderyn, potentially with multiple instances."""

    title: str
    description: str
    detector_name: str
    severity: str
    instances: List[AderynIssueInstance] = field(default_factory=list)


@dataclass
class AderynRunResult:
    """Aggregated result of one Aderyn invocation."""

    success: bool
    command: List[str]
    findings: List[AderynIssue] = field(default_factory=list)
    normalized_findings: List[Dict[str, Any]] = field(default_factory=list)
    raw_report: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None
    aderyn_version: Optional[str] = None
    stdout: str = ""
    stderr: str = ""


class AderynAdapter:
    """Thin wrapper around the external Aderyn binary."""

    DEFAULT_TIMEOUT = 180

    def __init__(self, binary_path: Optional[str] = None, timeout: int = DEFAULT_TIMEOUT):
        self.timeout = timeout
        self._aderyn_path: Optional[str] = None
        self._version: Optional[str] = None
        self._discover_binary(binary_path)

    def _discover_binary(self, binary_path: Optional[str]) -> None:
        """Locate the Aderyn binary from explicit path, PATH, or common cargo paths."""
        candidates: List[str] = []
        env_path = os.environ.get("ADERYN_BINARY")
        if env_path:
            candidates.append(env_path)

        if binary_path:
            candidates.append(binary_path)

        which_path = shutil.which("aderyn")
        if which_path:
            candidates.append(which_path)

        project_root = Path(__file__).resolve().parents[1]
        local_binary_name = "aderyn.exe" if platform.system().lower().startswith("win") else "aderyn"
        candidates.extend(
            [
                str(project_root / "external" / "aderyn" / "target" / "release" / local_binary_name),
                str(project_root / "external" / "aderyn" / "target" / "debug" / local_binary_name),
            ]
        )

        candidates.extend(
            [
                str(Path.home() / ".cargo" / "bin" / "aderyn"),
                str(Path.home() / ".cargo" / "bin" / "aderyn.exe"),
                str(Path.home() / ".local" / "bin" / "aderyn"),
            ]
        )

        seen = set()
        for candidate in candidates:
            if not candidate or candidate in seen:
                continue
            seen.add(candidate)
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                self._aderyn_path = candidate
                self._version = self._get_version(candidate)
                logger.info("Found aderyn at %s (version %s)", candidate, self._version)
                return

        logger.info("aderyn not found; adapter will degrade gracefully")

    def _get_version(self, binary_path: str) -> Optional[str]:
        """Return Aderyn version text if available."""
        try:
            result = subprocess.run(
                [binary_path, "--version"],
                capture_output=True,
                text=True,
                timeout=10,
                env=get_tool_env(),
            )
        except Exception:
            return None

        version_text = (result.stdout or result.stderr).strip()
        return version_text or None

    def is_available(self) -> bool:
        """Return True when the adapter can invoke Aderyn."""
        return self._aderyn_path is not None

    @property
    def version(self) -> Optional[str]:
        return self._version

    def run(
        self,
        target_path: str,
        src: Optional[str] = None,
        path_includes: Optional[Sequence[str]] = None,
        path_excludes: Optional[Sequence[str]] = None,
        highs_only: bool = False,
        detector_names: Optional[Sequence[str]] = None,
        extra_args: Optional[Sequence[str]] = None,
        no_snippets: bool = True,
    ) -> AderynRunResult:
        """Run Aderyn against a file or project path and normalize the report."""
        if not self.is_available():
            return AderynRunResult(
                success=False,
                command=[],
                error_message="aderyn is not installed",
            )

        root_path, merged_includes = self._resolve_scan_target(target_path, path_includes)

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as report_file:
            report_path = report_file.name

        command = self.build_command(
            root_path=root_path,
            output_path=report_path,
            src=src,
            path_includes=merged_includes,
            path_excludes=path_excludes,
            highs_only=highs_only,
            extra_args=extra_args,
            no_snippets=no_snippets,
        )

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                env=get_tool_env(),
                cwd=root_path,
            )
        except FileNotFoundError:
            return AderynRunResult(
                success=False,
                command=command,
                error_message="aderyn binary not found",
            )
        except subprocess.TimeoutExpired:
            return AderynRunResult(
                success=False,
                command=command,
                error_message=f"aderyn timed out after {self.timeout} seconds",
            )
        except Exception as exc:
            return AderynRunResult(
                success=False,
                command=command,
                error_message=f"aderyn execution failed: {exc}",
            )

        try:
            if result.returncode != 0:
                return AderynRunResult(
                    success=False,
                    command=command,
                    error_message=(result.stderr or result.stdout or f"aderyn exited with code {result.returncode}").strip(),
                    aderyn_version=self._version,
                    stdout=result.stdout,
                    stderr=result.stderr,
                )

            try:
                report_data = self._load_report(report_path)
                findings = self.parse_report(report_data, detector_names=detector_names)
                normalized = self.normalize_findings(findings)
            except ValueError as exc:
                return AderynRunResult(
                    success=False,
                    command=command,
                    error_message=str(exc),
                    aderyn_version=self._version,
                    stdout=result.stdout,
                    stderr=result.stderr,
                )

            return AderynRunResult(
                success=True,
                command=command,
                findings=findings,
                normalized_findings=normalized,
                raw_report=report_data,
                aderyn_version=self._version,
                stdout=result.stdout,
                stderr=result.stderr,
            )
        finally:
            try:
                os.unlink(report_path)
            except OSError:
                pass

    def build_command(
        self,
        root_path: str,
        output_path: str,
        src: Optional[str] = None,
        path_includes: Optional[Sequence[str]] = None,
        path_excludes: Optional[Sequence[str]] = None,
        highs_only: bool = False,
        extra_args: Optional[Sequence[str]] = None,
        no_snippets: bool = True,
    ) -> List[str]:
        """Build the Aderyn CLI command for a JSON report."""
        if not self._aderyn_path:
            raise ValueError("aderyn binary path is not available")

        command = [self._aderyn_path, root_path, "--output", output_path, "--skip-update-check"]

        if src:
            command.extend(["--src", src])
        if path_includes:
            command.extend(["-i", ",".join(path_includes)])
        if path_excludes:
            command.extend(["-x", ",".join(path_excludes)])
        if highs_only:
            command.append("--highs-only")
        if no_snippets:
            command.append("--no-snippets")
        if extra_args:
            command.extend(extra_args)

        return command

    def parse_report(
        self,
        report_data: Dict[str, Any],
        detector_names: Optional[Sequence[str]] = None,
    ) -> List[AderynIssue]:
        """Parse Aderyn JSON output into typed issue objects."""
        detector_filter = {name.lower() for name in detector_names or []}
        issues: List[AderynIssue] = []

        for severity_key, severity_value in (("high_issues", "high"), ("low_issues", "low")):
            issue_group = report_data.get(severity_key, {})
            for raw_issue in issue_group.get("issues", []) or []:
                detector_name = str(raw_issue.get("detector_name", "") or "")
                if detector_filter and detector_name.lower() not in detector_filter:
                    continue

                raw_instances = raw_issue.get("instances", []) or []
                instances = [
                    AderynIssueInstance(
                        contract_path=str(instance.get("contract_path", "") or ""),
                        line_no=int(instance.get("line_no", 0) or 0),
                        src=str(instance.get("src", "") or ""),
                        src_char=str(instance.get("src_char", "") or ""),
                        src_char2=str(instance.get("src_char2", "") or ""),
                        hint=instance.get("hint"),
                    )
                    for instance in raw_instances
                ]

                issues.append(
                    AderynIssue(
                        title=str(raw_issue.get("title", detector_name or "Aderyn Issue")),
                        description=str(raw_issue.get("description", "") or ""),
                        detector_name=detector_name or "unknown-detector",
                        severity=severity_value,
                        instances=instances,
                    )
                )

        return issues

    def normalize_findings(self, findings: Sequence[AderynIssue]) -> List[Dict[str, Any]]:
        """Convert parsed issues into Aether's normalized vulnerability dicts."""
        normalized: List[Dict[str, Any]] = []

        for finding in findings:
            for instance in finding.instances:
                normalized.append(
                    {
                        "vulnerability_type": finding.detector_name,
                        "title": finding.title,
                        "severity": self._normalize_severity(finding.severity),
                        "confidence": self._default_confidence(finding.severity),
                        "line_number": instance.line_no,
                        "line": instance.line_no,
                        "description": finding.description,
                        "code_snippet": "",
                        "swc_id": "",
                        "category": "aderyn_custom",
                        "file": instance.contract_path,
                        "tool": "aderyn",
                        "status": "confirmed",
                        "context": {
                            "source": "aderyn",
                            "detector_name": finding.detector_name,
                            "aderyn_severity": finding.severity,
                            "title": finding.title,
                            "hint": instance.hint,
                            "src": instance.src,
                            "src_char": instance.src_char,
                            "src_char2": instance.src_char2,
                            "instance_count_for_issue": len(finding.instances),
                        },
                    }
                )

        return normalized

    def _resolve_scan_target(
        self,
        target_path: str,
        path_includes: Optional[Sequence[str]],
    ) -> Tuple[str, Optional[List[str]]]:
        """Resolve file-vs-directory target semantics for the Aderyn CLI."""
        target = Path(target_path)
        includes = list(path_includes or [])

        if target.is_file():
            root_path = str(target.parent.resolve())
            includes.append(target.name)
            return root_path, self._dedupe(includes)

        return str(target.resolve()), self._dedupe(includes) if includes else None

    def _load_report(self, report_path: str) -> Dict[str, Any]:
        """Load the JSON report produced by Aderyn."""
        try:
            with open(report_path, "r", encoding="utf-8") as handle:
                return json.load(handle)
        except FileNotFoundError as exc:
            raise ValueError(f"Aderyn report was not produced: {report_path}") from exc
        except json.JSONDecodeError as exc:
            raise ValueError(f"Aderyn output was not valid JSON: {exc}") from exc

    @staticmethod
    def _normalize_severity(severity: str) -> str:
        normalized = severity.lower().strip()
        if normalized in {"high", "critical"}:
            return "high"
        if normalized == "low":
            return "low"
        return "medium"

    @staticmethod
    def _default_confidence(severity: str) -> float:
        return 0.85 if severity.lower().strip() == "high" else 0.7

    @staticmethod
    def _dedupe(values: Iterable[str]) -> List[str]:
        seen = set()
        deduped: List[str] = []
        for value in values:
            if value not in seen:
                seen.add(value)
                deduped.append(value)
        return deduped
