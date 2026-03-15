#!/usr/bin/env python3
"""
Direct CLI for Aether - bypasses TUI
Usage: python direct_cli.py audit <contract.sol>
"""

import sys
import asyncio
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.absolute()))

from core.enhanced_audit_engine import EnhancedAetherAuditEngine
from core.config_manager import ConfigManager


async def audit_contract(contract_path: str):
    """Run audit directly without TUI"""
    print(f"[*] Auditing {contract_path}...")

    config = ConfigManager()
    engine = EnhancedAetherAuditEngine(verbose=True)

    flow_config = {
        'enable_static_analysis': True,
        'enable_llm_analysis': True,
        'enable_validation': True
    }

    result = await engine.run_audit(
        contract_path=contract_path,
        flow_config=flow_config,
        enhanced=True
    )

    print(f"\n[+] Found {len(result.get('findings', []))} findings")
    for finding in result.get('findings', []):
        print(f"  [{finding.get('severity')}] {finding.get('title')}")

    return result


if __name__ == "__main__":
    if len(sys.argv) < 3 or sys.argv[1] != "audit":
        print("Usage: python direct_cli.py audit <contract.sol>")
        sys.exit(1)

    asyncio.run(audit_contract(sys.argv[2]))
