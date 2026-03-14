#!/usr/bin/env python3
"""
Advanced scanner using Aether's pattern-based methodology
"""

import sys
from pathlib import Path
from advanced_defi_detector import AdvancedDeFiDetector


def main():
    if len(sys.argv) < 2:
        print("Usage: python advanced_scan.py <directory>")
        sys.exit(1)

    detector = AdvancedDeFiDetector()
    target_dir = Path(sys.argv[1])
    sol_files = list(target_dir.rglob("*.sol"))

    if not sol_files:
        print(f"No .sol files in {target_dir}")
        return

    print(f"Advanced scanning {len(sol_files)} contracts...\n")

    total = 0
    for sol_file in sol_files:
        try:
            source = sol_file.read_text(encoding='utf-8')
            findings = detector.detect(source)

            if findings:
                total += len(findings)
                print(f"\n[!] {sol_file.name}")
                for f in findings:
                    print(f"  [{f.severity.upper()}] {f.description}")
                    print(f"    Line {f.line_number}: {f.code_snippet[:60]}...")
                    print(f"    Confidence: {f.confidence:.0%} | {f.swc_id}")
                    print(f"    Real exploit: {f.real_exploit}")
                    print(f"    Fix: {f.recommendation}")
        except Exception as e:
            print(f"[ERROR] {sol_file.name}: {e}")

    print(f"\n{'='*60}")
    print(f"Total: {total} vulnerabilities")


if __name__ == "__main__":
    main()
