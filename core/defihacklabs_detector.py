"""
DeFiHackLabs Pattern Detector

Detects vulnerabilities based on 685+ real exploits from DeFiHackLabs.
Patterns extracted from 2025-2026 incidents.
"""

import re
from typing import List, Dict, Any
from dataclasses import dataclass
from enum import Enum


class DeFiVulnerabilityType(Enum):
    SIGNATURE_BYPASS = "signature_bypass"
    NFT_COLLATERAL_MANIPULATION = "nft_collateral_manipulation"
    ARBITRARY_CALL_SWAP_DATA = "arbitrary_call_swap_data"
    PRECISION_LOSS_AMM = "precision_loss_amm"
    BAD_DEBT_RESTRUCTURING = "bad_debt_restructuring"
    SETTLEMENT_INTERACTION_EXPLOIT = "settlement_interaction_exploit"
    ORACLE_MANIPULATION = "oracle_manipulation"
    TYPE_CASTING_OVERFLOW = "type_casting_overflow"


@dataclass
class DeFiVulnerability:
    vulnerability_type: str
    severity: str
    description: str
    line_number: int
    code_snippet: str
    confidence: float
    real_exploit_reference: str
    recommendation: str


class DeFiHackLabsDetector:
    """Detects vulnerabilities from real DeFi exploits"""

    def detect(self, source_code: str) -> List[DeFiVulnerability]:
        vulnerabilities = []
        lines = source_code.split('\n')

        for i, line in enumerate(lines, 1):
            vulnerabilities.extend(self._check_signature_bypass(line, i))
            vulnerabilities.extend(self._check_nft_collateral(line, i))
            vulnerabilities.extend(self._check_arbitrary_call(line, i))
            vulnerabilities.extend(self._check_precision_loss(line, i))
            vulnerabilities.extend(self._check_bad_debt(line, i))
            vulnerabilities.extend(self._check_type_casting(line, i))

        return vulnerabilities

    def _check_signature_bypass(self, line: str, line_num: int) -> List[DeFiVulnerability]:
        """Detect ERC-6492 signature bypass (ODOS $50k)"""
        if re.search(r'abi\.decode.*signature|ERC6492|6492649264926492', line, re.IGNORECASE):
            if re.search(r'\.call\(', line):
                return [DeFiVulnerability(
                    vulnerability_type=DeFiVulnerabilityType.SIGNATURE_BYPASS.value,
                    severity="HIGH",
                    description="ERC-6492 signature validation allows arbitrary calls",
                    line_number=line_num,
                    code_snippet=line.strip(),
                    confidence=0.85,
                    real_exploit_reference="ODOS $50k (2025-01)",
                    recommendation="Validate signature target address against whitelist"
                )]
        return []

    def _check_nft_collateral(self, line: str, line_num: int) -> List[DeFiVulnerability]:
        """Detect NFT collateral without valuation (Impermax $300k, Paribus $86k)"""
        if re.search(r'collateral.*=.*balanceOf|mint.*tokenId.*collateral', line, re.IGNORECASE):
            if not re.search(r'getPrice|oracle|valuation|twap', line, re.IGNORECASE):
                return [DeFiVulnerability(
                    vulnerability_type=DeFiVulnerabilityType.NFT_COLLATERAL_MANIPULATION.value,
                    severity="CRITICAL",
                    description="NFT/LP position used as collateral without proper valuation",
                    line_number=line_num,
                    code_snippet=line.strip(),
                    confidence=0.80,
                    real_exploit_reference="Impermax V3 $300k, Paribus $86k (2025-04)",
                    recommendation="Implement TWAP-based valuation for LP positions"
                )]
        return []

    def _check_arbitrary_call(self, line: str, line_num: int) -> List[DeFiVulnerability]:
        """Detect arbitrary calls via swap data (Size Credit $19.7k)"""
        if re.search(r'abi\.decode.*SwapParams|interactions\[.*\]\.call', line):
            if not re.search(r'whitelist|approved|authorized', line, re.IGNORECASE):
                return [DeFiVulnerability(
                    vulnerability_type=DeFiVulnerabilityType.ARBITRARY_CALL_SWAP_DATA.value,
                    severity="CRITICAL",
                    description="Unvalidated calldata allows arbitrary external calls",
                    line_number=line_num,
                    code_snippet=line.strip(),
                    confidence=0.90,
                    real_exploit_reference="Size Credit $19.7k, Bebop $21k (2025-08)",
                    recommendation="Whitelist swap routers and validate calldata structure"
                )]
        return []

    def _check_precision_loss(self, line: str, line_num: int) -> List[DeFiVulnerability]:
        """Detect precision loss in AMM math (Balancer V2 $120M)"""
        if re.search(r'mulDown|divDown|scalingFactor.*1e18', line):
            return [DeFiVulnerability(
                vulnerability_type=DeFiVulnerabilityType.PRECISION_LOSS_AMM.value,
                severity="CRITICAL",
                description="Rounding errors in repeated calculations can be exploited",
                line_number=line_num,
                code_snippet=line.strip(),
                confidence=0.70,
                real_exploit_reference="Balancer V2 $120M (2025-11)",
                recommendation="Use higher precision math or limit swap iterations"
            )]
        return []

    def _check_bad_debt(self, line: str, line_num: int) -> List[DeFiVulnerability]:
        """Detect bad debt clearing without checks (Impermax $300k)"""
        if re.search(r'restructureBadDebt|delete.*borrowBalance', line):
            if not re.search(r'require.*underwater|collateral.*<.*debt', line):
                return [DeFiVulnerability(
                    vulnerability_type=DeFiVulnerabilityType.BAD_DEBT_RESTRUCTURING.value,
                    severity="HIGH",
                    description="Bad debt cleared without verifying position is underwater",
                    line_number=line_num,
                    code_snippet=line.strip(),
                    confidence=0.85,
                    real_exploit_reference="Impermax V3 $300k (2025-04)",
                    recommendation="Verify collateral < debt before clearing bad debt"
                )]
        return []

    def _check_type_casting(self, line: str, line_num: int) -> List[DeFiVulnerability]:
        """Detect unsafe type casting (Alkimiya)"""
        if re.search(r'uint128\(.*\)|uint64\(.*\)|uint32\(.*\)', line):
            if not re.search(r'SafeCast|require.*<=.*max', line):
                return [DeFiVulnerability(
                    vulnerability_type=DeFiVulnerabilityType.TYPE_CASTING_OVERFLOW.value,
                    severity="MEDIUM",
                    description="Unsafe downcast can cause overflow",
                    line_number=line_num,
                    code_snippet=line.strip(),
                    confidence=0.75,
                    real_exploit_reference="Alkimiya (2025-03)",
                    recommendation="Use OpenZeppelin SafeCast library"
                )]
        return []
