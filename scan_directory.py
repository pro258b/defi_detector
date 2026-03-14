#!/usr/bin/env python3
"""
Batch scanner for DeFiHackLabs detector
Scans all .sol files in a directory
"""

import sys
from pathlib import Path
from core.defihacklabs_detector import DeFiHackLabsDetector

def scan_directory(directory: str):
    """Scan all .sol files in directory"""
    detector = DeFiHackLabsDetector()
    sol_files = list(Path(directory).rglob("*.sol"))

    if not sol_files:
        print(f"No .sol files found in {directory}")
        return

    print(f"Scanning {len(sol_files)} contracts...\n")

    total_vulns = 0
    vulnerable_files = []

    for sol_file in sol_files:
        try:
            with open(sol_file, 'r', encoding='utf-8') as f:
                source_code = f.read()

            vulnerabilities = detector.detect(source_code)

            if vulnerabilities:
                total_vulns += len(vulnerabilities)
                vulnerable_files.append((sol_file, vulnerabilities))
                print(f"[!] {sol_file.name}: {len(vulnerabilities)} issues")
        except Exception as e:
            print(f"[ERROR] {sol_file.name}: {e}")

    print(f"\n{'='*60}")
    print(f"Summary: {total_vulns} vulnerabilities in {len(vulnerable_files)} files\n")

    for file_path, vulns in vulnerable_files:
        print(f"\n{file_path}")
        for vuln in vulns:
            print(f"  [{vuln.severity}] Line {vuln.line_number}: {vuln.vulnerability_type}")
            print(f"    {vuln.description}")
            print(f"    Fix: {vuln.recommendation}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scan_directory.py <directory>")
        sys.exit(1)

    scan_directory(sys.argv[1])
