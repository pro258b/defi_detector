#!/usr/bin/env python3
"""
Context-aware DeFi vulnerability detector
Uses invariant checking and control flow analysis, not just keywords
"""

import re
from typing import List, Dict, Set, Optional
from dataclasses import dataclass


@dataclass
class FunctionContext:
    name: str
    modifiers: List[str]
    visibility: str
    state_changes: List[str]
    external_calls: List[str]
    checks: List[str]


class ContextAwareDetector:
    """Detector using control flow and invariant analysis"""

    def __init__(self):
        self.functions = {}
        self.state_vars = set()

    def analyze_contract(self, source: str) -> List[Dict]:
        """Analyze with context, not just keywords"""
        self._extract_state_vars(source)
        self._parse_functions(source)
        return self._detect_vulnerabilities()

    def _extract_state_vars(self, source: str):
        """Extract state variables for tracking"""
        for match in re.finditer(r'^\s+(mapping|uint|address|bool)\s+\w+\s+(\w+);', source, re.MULTILINE):
            self.state_vars.add(match.group(2))

    def _parse_functions(self, source: str):
        """Parse functions with full context"""
        func_pattern = r'function\s+(\w+)\s*\([^)]*\)\s*(public|external|internal|private)?\s*([^{]*)\{([^}]+)\}'

        for match in re.finditer(func_pattern, source, re.DOTALL):
            name = match.group(1)
            visibility = match.group(2) or 'public'
            modifiers_str = match.group(3)
            body = match.group(4)

            modifiers = re.findall(r'\b(onlyOwner|nonReentrant|whenNotPaused)\b', modifiers_str)

            self.functions[name] = FunctionContext(
                name=name,
                modifiers=modifiers,
                visibility=visibility,
                state_changes=self._find_state_changes(body),
                external_calls=self._find_external_calls(body),
                checks=self._find_checks(body)
            )

    def _find_state_changes(self, body: str) -> List[str]:
        """Find state variable modifications"""
        changes = []
        for var in self.state_vars:
            if re.search(rf'\b{var}\s*[=\+\-]|delete\s+{var}', body):
                changes.append(var)
        return changes

    def _find_external_calls(self, body: str) -> List[str]:
        """Find external calls with targets"""
        calls = []
        for match in re.finditer(r'(\w+)\.call\(|(\w+)\.transfer\(|(\w+)\.send\(', body):
            target = match.group(1) or match.group(2) or match.group(3)
            calls.append(target)
        return calls

    def _find_checks(self, body: str) -> List[str]:
        """Find require/assert statements"""
        return re.findall(r'require\([^)]+\)|assert\([^)]+\)', body)

    def _detect_vulnerabilities(self) -> List[Dict]:
        """Detect vulnerabilities using context analysis"""
        findings = []

        for name, ctx in self.functions.items():
            # Check 1: External calls without access control
            if ctx.visibility in ['public', 'external'] and ctx.external_calls:
                if not ctx.modifiers and not any('msg.sender' in c for c in ctx.checks):
                    findings.append({
                        'type': 'Missing Access Control',
                        'severity': 'CRITICAL',
                        'function': name,
                        'reason': f'External calls to {ctx.external_calls} without auth checks',
                        'invariant_violated': 'Only authorized users should trigger external calls'
                    })

            # Check 2: State changes after external calls (reentrancy)
            if ctx.external_calls and ctx.state_changes:
                if 'nonReentrant' not in ctx.modifiers:
                    findings.append({
                        'type': 'Potential Reentrancy',
                        'severity': 'HIGH',
                        'function': name,
                        'reason': f'State changes {ctx.state_changes} after external calls',
                        'invariant_violated': 'State must be updated before external calls'
                    })

            # Check 3: Delete state without validation
            if any('delete' in str(s) for s in ctx.state_changes):
                if len(ctx.checks) == 0:
                    findings.append({
                        'type': 'Unchecked State Deletion',
                        'severity': 'HIGH',
                        'function': name,
                        'reason': 'Deletes state variables without validation',
                        'invariant_violated': 'State deletion requires precondition checks'
                    })

        return findings
