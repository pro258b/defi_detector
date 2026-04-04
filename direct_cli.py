#!/usr/bin/env python3
"""
Direct CLI for Aether - bypasses TUI
Usage:
  python direct_cli.py audit <contract.sol> [--no-static] [--no-llm] [--no-validation]
  python direct_cli.py audit-dir <directory> [--no-static] [--no-llm] [--no-validation]
  python direct_cli.py audit <0xcontractaddress> [--no-static] [--no-llm] [--no-validation]
"""

import asyncio
import signal
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.absolute()))

from cli.main import AetherCLI
from core.aderyn_detector_selector import (
    classify_project_for_aderyn,
    format_classification_summary,
)
from core.enhanced_audit_engine import EnhancedAetherAuditEngine

partial_result = None


def signal_handler(signum, frame):
    print("\nWarning: Ctrl+C - saving partial results...")
    raise KeyboardInterrupt()


async def audit_contract(contract_path: str, flow_config: dict, timeout: int = 600):
    """Run audit directly without TUI."""
    global partial_result
    print(f"[*] Auditing {contract_path}... (timeout: {timeout}s)")

    engine = EnhancedAetherAuditEngine(verbose=True)

    try:
        result = await asyncio.wait_for(
            engine.run_audit(contract_path=contract_path, flow_config=flow_config, enhanced=True),
            timeout=timeout,
        )
        partial_result = result
        print(f"\n[+] Found {len(result.get('findings', []))} findings")
        for finding in result.get('findings', []):
            print(f"  [{finding.get('severity')}] {finding.get('title')}")
        return result
    except asyncio.TimeoutError:
        print(f"\n[!] Timeout after {timeout}s")
        return partial_result or {'findings': [], 'status': 'timeout'}
    except KeyboardInterrupt:
        print("\n[!] Interrupted")
        return partial_result or {'findings': [], 'status': 'interrupted'}


async def audit_directory(directory: str, flow_config: dict, timeout: int = 600, selected_files=None):
    """Audit all .sol files in directory, optionally restricted to a selected file list."""
    dir_path = Path(directory)
    if not dir_path.is_dir():
        print(f"[!] Not a directory: {directory}")
        sys.exit(1)

    if selected_files:
        sol_files = [Path(file_path) for file_path in selected_files]
        print(f"[*] Using filtered contract set: {len(sol_files)} files")
    else:
        sol_files = list(dir_path.glob("**/*.sol"))
    print(f"[*] Found {len(sol_files)} .sol files in {directory}")

    all_results = []
    for sol_file in sol_files:
        result = await audit_contract(str(sol_file), flow_config, timeout)
        all_results.append((str(sol_file), result))
        print("-" * 80)

    print(f"\n[+] Audited {len(all_results)} contracts")
    return all_results


def resolve_target(target: str):
    """Resolve a live contract address into a local file or directory using the main CLI fetchers."""
    cli = AetherCLI()

    etherscan_result = cli._handle_etherscan_address(target, interactive_scope=True)
    if etherscan_result is not None:
        if isinstance(etherscan_result, dict):
            selected_files = [contract['file_path'] for contract in etherscan_result.get('contracts', [])]
            return etherscan_result['path'], selected_files
        return etherscan_result, None

    basescan_result = cli._handle_basescan_address(target)
    if basescan_result is not None:
        return basescan_result, None

    return target, None


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)

    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)

    command = sys.argv[1]
    target = sys.argv[2]
    args = sys.argv[3:]

    timeout = 600
    for i, arg in enumerate(args):
        if arg == '--timeout' and i + 1 < len(args):
            timeout = int(args[i + 1])

    flow_config = {
        'enable_static_analysis': '--no-static' not in args,
        'enable_llm_analysis': '--no-llm' not in args,
        'enable_validation': '--no-validation' not in args,
    }

    print(
        f"[*] Config: static={flow_config['enable_static_analysis']}, "
        f"llm={flow_config['enable_llm_analysis']}, "
        f"validation={flow_config['enable_validation']}"
    )

    try:
        resolved_target, selected_files = resolve_target(target)
        aderyn_classification = classify_project_for_aderyn(resolved_target)
        print(f"[*] Aderyn classification: {format_classification_summary(aderyn_classification)}")

        if command == "audit":
            if Path(resolved_target).is_dir():
                asyncio.run(audit_directory(resolved_target, flow_config, timeout, selected_files=selected_files))
            else:
                asyncio.run(audit_contract(resolved_target, flow_config, timeout))
        elif command == "audit-dir":
            asyncio.run(audit_directory(resolved_target, flow_config, timeout, selected_files=selected_files))
        else:
            print(f"[!] Unknown command: {command}")
            print(__doc__)
            sys.exit(1)
    except KeyboardInterrupt:
        print("\n[+] Partial results saved")
