#!/usr/bin/env python3
"""
Smart scanner that learns from defi-security-analyst.skill.md
"""

import sys
from pathlib import Path
from dynamic_detector import DynamicDeFiDetector


def main():
    if len(sys.argv) < 2:
        print("Usage: python smart_scan.py <directory>")
        print("Learns patterns from ../defi-security-analyst.skill.md")
        sys.exit(1)

    # Load skill file
    skill_file = Path(__file__).parent.parent / "defi-security-analyst.skill.md"
    if not skill_file.exists():
        print(f"Error: {skill_file} not found")
        sys.exit(1)

    print(f"Loading patterns from {skill_file.name}...")
    detector = DynamicDeFiDetector(str(skill_file))
    print(f"Loaded {len(detector.patterns)} vulnerability patterns\n")

    # Scan directory
    target_dir = Path(sys.argv[1])
    sol_files = list(target_dir.rglob("*.sol"))

    if not sol_files:
        print(f"No .sol files in {target_dir}")
        return

    print(f"Scanning {len(sol_files)} contracts...\n")

    total_findings = 0
    vulnerable_files = []

    for sol_file in sol_files:
        try:
            source = sol_file.read_text(encoding='utf-8')
            findings = detector.scan_contract(source)

            if findings:
                total_findings += len(findings)
                vulnerable_files.append((sol_file, findings))
                print(f"[!] {sol_file.name}: {len(findings)} issues")
        except Exception as e:
            print(f"[ERROR] {sol_file.name}: {e}")

    print(f"\n{'='*70}")
    print(f"Found {total_findings} vulnerabilities in {len(vulnerable_files)} files\n")

    for file_path, findings in vulnerable_files:
        print(f"\n{file_path.name}")
        for f in findings:
            print(f"  Line {f['line']}: [{f['severity']}] {f['vulnerability']}")
            print(f"    {f['description']}")
            print(f"    Real exploit: {f['exploit_ref']}")
            print(f"    Fix: {f['fix']}\n")


if __name__ == "__main__":
    main()
