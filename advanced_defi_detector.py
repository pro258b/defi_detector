"""
Advanced DeFi Detector using Aether's methodology:
- Pattern-based detection with confidence scores
- Context-aware analysis (not just keywords)
- SWC classification
- Specific recommendations
"""

import re
from typing import List, Dict, Any
from dataclasses import dataclass
from enum import Enum


class DeFiVulnType(Enum):
    SIGNATURE_BYPASS = "signature_bypass"
    NFT_COLLATERAL_NO_VALIDATION = "nft_collateral_no_validation"
    ARBITRARY_EXTERNAL_CALL = "arbitrary_external_call"
    PRECISION_LOSS = "precision_loss"
    BAD_DEBT_NO_CHECK = "bad_debt_no_check"
    UNSAFE_DOWNCAST = "unsafe_downcast"


@dataclass
class DeFiVulnerability:
    vulnerability_type: str
    severity: str
    description: str
    line_number: int
    code_snippet: str
    confidence: float
    swc_id: str
    recommendation: str
    real_exploit: str
    context: Dict[str, Any]


class AdvancedDeFiDetector:
    """Advanced detector using Aether's pattern-based methodology"""

    def __init__(self):
        self.patterns = self._initialize_patterns()

    def _initialize_patterns(self) -> List[Dict[str, Any]]:
        """Initialize detection patterns with context requirements"""
        return [
            {
                'name': 'ERC-6492 Signature Bypass',
                'type': DeFiVulnType.SIGNATURE_BYPASS,
                'code_pattern': r'abi\.decode.*signature.*\n.*\.call\(',
                'context_required': ['isValidSig', 'ERC6492'],
                'missing_protection': ['whitelist', 'approved'],
                'severity': 'critical',
                'confidence': 0.85,
                'swc_id': 'SWC-107',
                'exploit': 'ODOS $50k (2025-01)',
                'recommendation': 'Whitelist allowed call targets in signature validation'
            },
            {
                'name': 'NFT Collateral Without Valuation',
                'type': DeFiVulnType.NFT_COLLATERAL_NO_VALIDATION,
                'code_pattern': r'collateral\[.*\]\s*=.*balanceOf',
                'context_required': ['mint', 'deposit'],
                'missing_protection': ['getPrice', 'oracle', 'TWAP', 'valuation'],
                'severity': 'critical',
                'confidence': 0.80,
                'swc_id': 'SWC-101',
                'exploit': 'Impermax $300k, Paribus $86k (2025-04)',
                'recommendation': 'Implement TWAP-based LP position valuation'
            },
            {
                'name': 'Arbitrary External Call',
                'type': DeFiVulnType.ARBITRARY_EXTERNAL_CALL,
                'code_pattern': r'abi\.decode.*\(.*data.*\).*\n.*\.call\(',
                'context_required': ['swap', 'interaction'],
                'missing_protection': ['whitelist', 'authorized', 'approved'],
                'severity': 'critical',
                'confidence': 0.90,
                'swc_id': 'SWC-107',
                'exploit': 'Size Credit $19.7k, Bebop $21k (2025-08)',
                'recommendation': 'Whitelist swap routers and validate calldata'
            },
            {
                'name': 'Bad Debt Clearing Without Check',
                'type': DeFiVulnType.BAD_DEBT_NO_CHECK,
                'code_pattern': r'delete\s+\w*[Bb]orrow|restructureBadDebt',
                'context_required': ['debt', 'borrow'],
                'missing_protection': ['require.*underwater', 'collateral.*<.*debt'],
                'severity': 'high',
                'confidence': 0.85,
                'swc_id': 'SWC-123',
                'exploit': 'Impermax V3 $300k (2025-04)',
                'recommendation': 'Verify position is underwater before clearing debt'
            }
        ]

    def detect(self, source_code: str, file_context: Dict[str, Any] = None) -> List[DeFiVulnerability]:
        """Detect vulnerabilities with context awareness"""
        vulnerabilities = []
        lines = source_code.split('\n')

        for pattern in self.patterns:
            matches = self._find_pattern_matches(source_code, lines, pattern)
            vulnerabilities.extend(matches)

        return vulnerabilities

    def _find_pattern_matches(self, source: str, lines: List[str], pattern: Dict) -> List[DeFiVulnerability]:
        """Find pattern matches with context validation"""
        matches = []

        # Check if context is present
        has_context = all(re.search(ctx, source, re.IGNORECASE) for ctx in pattern['context_required'])
        if not has_context:
            return matches

        # Find code pattern matches
        for match in re.finditer(pattern['code_pattern'], source, re.MULTILINE | re.DOTALL):
            line_num = source[:match.start()].count('\n') + 1
            snippet = lines[line_num - 1] if line_num <= len(lines) else ""

            # Check if protection is missing
            has_protection = any(re.search(prot, snippet, re.IGNORECASE) for prot in pattern['missing_protection'])
            if has_protection:
                continue

            matches.append(DeFiVulnerability(
                vulnerability_type=pattern['type'].value,
                severity=pattern['severity'],
                description=pattern['name'],
                line_number=line_num,
                code_snippet=snippet.strip(),
                confidence=pattern['confidence'],
                swc_id=pattern['swc_id'],
                recommendation=pattern['recommendation'],
                real_exploit=pattern['exploit'],
                context={'pattern': pattern['name']}
            ))

        return matches

