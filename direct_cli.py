#!/usr/bin/env python3
"""
Direct CLI for Aether - bypasses TUI
Usage:
  python direct_cli.py audit <contract.sol> [--no-static] [--no-llm] [--no-validation]
  python direct_cli.py audit-dir <directory> [--no-static] [--no-llm] [--no-validation]
"""

import sys
import asyncio
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.absolute()))

from core.enhanced_audit_engine import EnhancedAetherAuditEngine
from core.config_manager import ConfigManager


async def audit_contract(contract_path: str, flow_config: dict):
    """Run audit directly without TUI"""
    print(f"[*] Auditing {contract_path}...")

    engine = EnhancedAetherAuditEngine(verbose=True)
    result = await engine.run_audit(
        contract_path=contract_path,
        flow_config=flow_config,
        enhanced=True
    )

    print(f"\n[+] Found {len(result.get('findings', []))} findings")
    for finding in result.get('findings', []):
        print(f"  [{finding.get('severity')}] {finding.get('title')}")

    return result


async def audit_directory(directory: str, flow_config: dict):
    """Audit all .sol files in directory"""
    dir_path = Path(directory)
    if not dir_path.is_dir():
        print(f"❌ Not a directory: {directory}")
        sys.exit(1)

    sol_files = list(dir_path.glob("**/*.sol"))
    print(f"[*] Found {len(sol_files)} .sol files in {directory}")

    all_results = []
    for sol_file in sol_files:
        result = await audit_contract(str(sol_file), flow_config)
        all_results.append((str(sol_file), result))
        print("-" * 80)

    print(f"\n[+] Audited {len(all_results)} contracts")
    return all_results


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)

    command = sys.argv[1]
    target = sys.argv[2]
    args = sys.argv[3:]

    flow_config = {
        'enable_static_analysis': '--no-static' not in args,
        'enable_llm_analysis': '--no-llm' not in args,
        'enable_validation': '--no-validation' not in args
    }

    print(f"[*] Config: static={flow_config['enable_static_analysis']}, "
          f"llm={flow_config['enable_llm_analysis']}, "
          f"validation={flow_config['enable_validation']}")

    if command == "audit":
        asyncio.run(audit_contract(target, flow_config))
    elif command == "audit-dir":
        asyncio.run(audit_directory(target, flow_config))
    else:
        print(f"❌ Unknown command: {command}")
        print(__doc__)
        sys.exit(1)
