#!/usr/bin/env python3
"""
Integration script to add DeFiHackLabs detector to Aether
"""

import sys
from pathlib import Path
from core.defihacklabs_detector import DeFiHackLabsDetector

def scan_contract(contract_path: str):
    """Scan a contract with DeFiHackLabs patterns"""
    detector = DeFiHackLabsDetector()

    with open(contract_path, 'r') as f:
        source_code = f.read()

    vulnerabilities = detector.detect(source_code)

    print(f"\n[DeFiHackLabs Scanner] Analyzing: {contract_path}")
    print(f"Found {len(vulnerabilities)} potential vulnerabilities\n")

    for vuln in vulnerabilities:
        print(f"[{vuln.severity}] {vuln.vulnerability_type}")
        print(f"  Line {vuln.line_number}: {vuln.description}")
        print(f"  Real exploit: {vuln.real_exploit_reference}")
        print(f"  Confidence: {vuln.confidence:.0%}")
        print(f"  Fix: {vuln.recommendation}\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python integrate_defihacklabs.py <contract.sol>")
        sys.exit(1)

    scan_contract(sys.argv[1])
