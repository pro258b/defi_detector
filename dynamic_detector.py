#!/usr/bin/env python3
"""
Dynamic DeFi vulnerability detector that learns from skill.md patterns
"""

import re
from pathlib import Path
from typing import List, Dict, Any
from dataclasses import dataclass


@dataclass
class VulnerabilityPattern:
    name: str
    severity: str
    code_patterns: List[str]
    description: str
    exploit_reference: str
    fix: str


class DynamicDeFiDetector:
    """Detector that learns patterns from defi-security-analyst.skill.md"""

    def __init__(self, skill_file: str):
        self.patterns = self._parse_skill_file(skill_file)

    def _parse_skill_file(self, skill_file: str) -> List[VulnerabilityPattern]:
        """Extract vulnerability patterns from skill.md"""
        with open(skill_file, 'r', encoding='utf-8') as f:
            content = f.read()

        patterns = []

        # Parse Pattern sections (existing exploits)
        pattern_blocks = re.findall(
            r'### Pattern \d+: (.+?)\n```solidity\n(.+?)```',
            content,
            re.DOTALL
        )

        for name, code_block in pattern_blocks:
            vuln_lines = re.findall(r'// ← EXPLOIT: (.+)', code_block)
            code_patterns = self._extract_code_patterns(code_block)
            fix_match = re.search(r'// Fix: (.+)', code_block)
            fix = fix_match.group(1) if fix_match else "Review and validate"

            patterns.append(VulnerabilityPattern(
                name=name.strip(),
                severity="HIGH",
                code_patterns=code_patterns,
                description=vuln_lines[0] if vuln_lines else name,
                exploit_reference=self._find_exploit_ref(content, name),
                fix=fix
            ))

        # Parse Bug Discovery Methodologies section
        methodology_patterns = self._parse_methodologies(content)
        patterns.extend(methodology_patterns)

        return patterns

    def _parse_methodologies(self, content: str) -> List[VulnerabilityPattern]:
        """Parse Damn Vulnerable DeFi methodologies"""
        patterns = []

        # Extract methodology sections
        method_blocks = re.findall(
            r'\*\*\d+\.\s+(.+?)\*\*\n-\s+(.+?)\n-\s+Example:\s+(.+?)\n-\s+Look for:\s+(.+?)(?=\n\n|\*\*)',
            content,
            re.DOTALL
        )

        for name, description, example, look_for in method_blocks:
            code_patterns = self._extract_methodology_patterns(look_for)

            patterns.append(VulnerabilityPattern(
                name=name.strip(),
                severity="MEDIUM",
                code_patterns=code_patterns,
                description=description.strip(),
                exploit_reference="Damn Vulnerable DeFi",
                fix=f"Check: {look_for.strip()}"
            ))

        return patterns

    def _extract_methodology_patterns(self, look_for: str) -> List[str]:
        """Convert 'look for' text into regex patterns"""
        patterns = []

        if 'balance check' in look_for.lower():
            patterns.append(r'balanceOf.*require|require.*balance')

        if 'msg.sender' in look_for.lower():
            patterns.append(r'msg\.sender.*!=|require.*msg\.sender')

        if 'state update' in look_for.lower():
            patterns.append(r'\w+\s*=\s*\w+;.*\n.*external')

        if 'callback' in look_for.lower():
            patterns.append(r'function\s+on\w+\(')

        return patterns if patterns else [r'function\s+\w+']

    def _extract_code_patterns(self, code_block: str) -> List[str]:
        """Extract regex patterns from vulnerable code"""
        patterns = []

        # Look for key vulnerability indicators
        if 'call(data)' in code_block or 'target.call' in code_block:
            patterns.append(r'\.call\(.*data.*\)')

        if 'transferFrom' in code_block:
            patterns.append(r'transferFrom\(')

        if 'abi.decode' in code_block:
            patterns.append(r'abi\.decode.*\(')

        if 'uint128(' in code_block or 'uint64(' in code_block:
            patterns.append(r'uint(128|64|32)\(')

        if 'delete' in code_block and 'balance' in code_block:
            patterns.append(r'delete.*balance')

        if 'mulDown' in code_block or 'scalingFactor' in code_block:
            patterns.append(r'mulDown|divDown|scalingFactor')

        if 'collateral' in code_block and 'balanceOf' in code_block:
            patterns.append(r'collateral.*balanceOf')

        return patterns if patterns else [r'function\s+\w+']

    def _find_exploit_ref(self, content: str, pattern_name: str) -> str:
        """Find real exploit reference for pattern"""
        section = content[content.find(pattern_name):content.find(pattern_name) + 500]

        # Look for dollar amounts
        money_match = re.search(r'\$[\d.]+[kKmM]', section)
        if money_match:
            return money_match.group(0)

        return "DeFiHackLabs"

    def scan_contract(self, source_code: str) -> List[Dict[str, Any]]:
        """Scan contract using learned patterns"""
        findings = []
        lines = source_code.split('\n')

        for pattern in self.patterns:
            for line_num, line in enumerate(lines, 1):
                for code_pattern in pattern.code_patterns:
                    if re.search(code_pattern, line, re.IGNORECASE):
                        findings.append({
                            'line': line_num,
                            'vulnerability': pattern.name,
                            'severity': pattern.severity,
                            'description': pattern.description,
                            'code': line.strip(),
                            'exploit_ref': pattern.exploit_reference,
                            'fix': pattern.fix
                        })

        return findings
