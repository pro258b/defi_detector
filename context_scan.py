#!/usr/bin/env python3
"""
Context-aware scanner using invariant checking
"""

import sys
from pathlib import Path
from context_detector import ContextAwareDetector


def main():
    if len(sys.argv) < 2:
        print("Usage: python context_scan.py <directory>")
        sys.exit(1)

    target_dir = Path(sys.argv[1])
    sol_files = list(target_dir.rglob("*.sol"))

    if not sol_files:
        print(f"No .sol files in {target_dir}")
        return

    print(f"Context-aware scanning {len(sol_files)} contracts...\n")

    total_findings = 0

    for sol_file in sol_files:
        try:
            source = sol_file.read_text(encoding='utf-8')
            detector = ContextAwareDetector()
            findings = detector.analyze_contract(source)

            if findings:
                total_findings += len(findings)
                print(f"\n[!] {sol_file.name}")
                for f in findings:
                    print(f"  [{f['severity']}] {f['type']} in {f['function']}()")
                    print(f"    Reason: {f['reason']}")
                    print(f"    Invariant: {f['invariant_violated']}")
        except Exception as e:
            print(f"[ERROR] {sol_file.name}: {e}")

    print(f"\n{'='*60}")
    print(f"Total: {total_findings} vulnerabilities")


if __name__ == "__main__":
    main()
