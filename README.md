基础使用：

- pip install -r requirements.txt
(windows需要加装 pip install windows-curses)

- 设置好.env

- python setup.py (会生成 Path.home() / '.aether/config.yaml')

启动：

python aether.py

选s 设置 模型 api

## 主要改动
已经修改setup.py可以指向env其他模型

主要修改 core\deep_analysis_engine.py 和 enhanced_llm_analyzer 里面提示词

如果windows导致TUI curse不返回，用直接用法 

  python direct_cli.py audit contract.sol

  python direct_cli.py audit-dir ./contracts

  **Only LLM analysis**
  python direct_cli.py audit-dir ./contracts --no-static --no-validation

结果显示
  **View last 10 results**
  python view_db.py --limit 10

  python view_db.py --severity CRITICAL

## 下一步
可以再把 defi-security-analyst.skill.md 结合到 enhanced_llm_analyzer.py

也许要让提示词防止被风险拒绝"Refuse to run"
  For your case (DeFi security analysis):
  Most likely #1 - Anthropic's filters see vulnerability analysis prompts and exploit code as potentially harmful. Try:
  - Rephrase prompts to emphasize "security research" and "defensive analysis"
  - Add context that this is for whitehat/audit purposes
  - Use less aggressive language in prompts
  - Check if your ANTHROPIC_BASE_URL is routing through a proxy that adds suspicious headers


# Aether v4.7 — Smart Contract Security Analysis Framework

**Version 4.7** | [What's New in v4.7](#whats-new-in-v47) | [Changelog](#changelog)

Aether is a Python-based framework for analyzing Solidity smart contracts, generating vulnerability findings, producing Foundry-based proof-of-concept (PoC) tests, and validating exploits on mainnet forks. It combines Solidity AST parsing, taint analysis, control flow graph analysis, cross-contract analysis, Halmos symbolic execution, 180+ pattern-based static detectors, a structured deep analysis LLM pipeline (GPT/Gemini/Claude), 14 protocol archetypes, a 75+ exploit knowledge base, ML-calibrated detection, token quirks detection, invariant extraction, related contract context resolution, and advanced context-aware filtering into a single persistent full-screen TUI.

## What's New in v4.7

**PoC Auto-Execution** — Generated Foundry PoCs now automatically compile and execute:

- `forge test --json` integration runs PoCs immediately after compilation
- JSON result parsing with `PoCTestResult` dataclass for structured pass/fail/error reporting
- Fork-mode support for mainnet validation of exploits against live state
- New `POC_TESTING` phase in JobManager for live progress tracking in the TUI

**Halmos Symbolic Execution** — Formal verification via symbolic execution:

- `HalmosRunner` for executing Halmos symbolic tests against generated properties
- `HalmosPropertyGenerator` for auto-generating verification properties from extracted invariants
- `HalmosSymbolicNode` pipeline node integrated at validation Stage 1.95
- Config options: `enable_symbolic_verification`, `halmos_timeout`
- Graceful degradation if Halmos is not installed — skips symbolic verification without errors

**Control Flow Graph Analysis** — Compiler-level control flow understanding:

- `BasicBlock`, `CFGEdge`, `ControlFlowGraph` dataclasses in `solidity_ast.py`
- `build_cfg()`, `get_dominators()`, `get_loop_headers()`, `format_cfg_for_llm()` for structural analysis
- Assembly block parsing via `parse_assembly_block()` for inline assembly support
- Branch-aware taint propagation in the taint analyzer for path-sensitive analysis
- CFG context injected into deep analysis Pass 2 alongside taint data

**ML Feedback Loop** — Historical outcome-based calibration:

- `AccuracyTracker.record_finding_outcome()` for tracking submission results and bounty earnings
- `get_detector_accuracy()` and `get_detector_weights()` for per-detector performance stats
- `DetectorStats` dataclass tracking true/false positives and historical accuracy
- Confidence weight adjustment in `EnhancedVulnerabilityDetector` based on detector track record
- Severity calibration from historical data injected into deep analysis Pass 5

**Related Contract Context** — LLM analysis now sees full dependency source code:

- `RelatedContractResolver` automatically discovers parent, interface, library, and dependency contracts
- Project mode uses inter-contract relationship analysis; single-file mode parses import statements
- Per-pass budget system: 200K chars for Gemini Flash passes, 100K for Claude, 50K for GPT
- Standard libraries (@openzeppelin, solmate, solady) summarized to interface-only to save budget
- Single-file audits auto-discover sibling .sol files for context

**Tech Debt Cleanup** — 8,500 lines of dead code removed:

- Deleted: `ai_ensemble.py`, `audit_engine.py`, `fork_verifier.py`
- Removed all ai_ensemble references from CLI, audit runner, TUI screens, report generator
- Removed `slither_project_cache` from database manager
- Removed formal verification stubs from enhanced audit engine

---

## What's New in v4.0

**Solidity AST Parsing** — Aether v4.0 adds compiler-backed code analysis via `py-solc-x`, moving beyond regex-only static analysis:

- Full `solc --ast-json` integration for proper inheritance resolution, function visibility, storage layout with slot numbers, and state variable read/write tracking per function
- Graceful regex fallback when compilation fails (missing imports, wrong compiler version)
- AST structural summary automatically fed into the deep analysis LLM pipeline for better protocol understanding

**Taint Analysis Engine** — Tracks user-controlled inputs through contracts to identify dangerous data flows:

- 8 taint source types: function parameters, msg.sender, msg.value, calldata, external call returns, block.timestamp, block.number, tx.origin
- 12 dangerous sink types: delegatecall, selfdestruct, external calls, ETH transfers, storage writes, array indexing, division by zero, and more
- Sanitizer detection: recognizes require bounds checks, access control modifiers, conditional reverts, Math.min/max clamping, SafeCast
- Cross-contract taint tracking across multiple files
- Integrated into the validation pipeline (Stage 1.85) for taint-aware finding corroboration/refutation

**Cross-Contract Analysis (Pass 3.5)** — New deep analysis pass targeting multi-contract vulnerabilities:

- Inter-contract relationship analyzer: detects inheritance, interface calls, delegatecall, staticcall, typed state variable relationships
- Union-find grouping of related contracts with trust boundary detection
- Dedicated LLM pass analyzing: trust boundary violations, cross-contract state consistency, cross-contract reentrancy, interface compliance, upgrade interactions, privilege escalation
- Cross-contract context also fed into Pass 4 for cross-function awareness

**Token Quirks Database** — 12 categories of non-standard ERC-20 behaviors that cause real exploits:

| Category | Severity | Example Tokens |
|----------|----------|---------------|
| Fee-on-transfer | HIGH | USDT, STA, PAXG |
| Rebasing tokens | HIGH | stETH, AMPL, OHM |
| ERC-777 callbacks | HIGH | imBTC |
| Flash-mintable | HIGH | DAI |
| Non-standard return | MEDIUM | Old USDT |
| Blocklist tokens | MEDIUM | USDC, USDT |
| Pausable tokens | MEDIUM | USDC |
| Low-decimal tokens | MEDIUM | USDC (6), WBTC (8) |
| Transfer hooks | MEDIUM | LINK (ERC-677) |
| Approval race | LOW | Various |
| Multiple entry points | LOW | TUSD |
| Upgradeable tokens | LOW | USDC v2 |

Integrated into static detection pipeline and archetype checklists.

**Enhanced Precision Engine** — Advanced rounding and precision vulnerability detection:

- **Share inflation / first depositor attack** detection for ERC-4626 vaults, lending pools, staking
- **Rounding direction analysis** — deposits should round DOWN, withdrawals should round UP
- **Division truncation tracking** — catches truncated rate variables later used in multiplication
- **Dust exploitation** detection — rounding to zero allows free operations
- **Accumulator overflow** — reward accumulator overflow risk assessment

**Runnable PoC Generation** — Generated Foundry tests now actually compile and run:

- Mock contract library: MockERC20, MockOracle, MockWETH, MockFlashLoanProvider
- Intelligent setUp() generator: extracts constructor params, deploys mocks, handles upgradeable contracts, mints tokens, sets approvals
- Max compile attempts increased from 3 to 5
- LLM prompts include mock API documentation and recommended setUp

**LLM Pipeline Improvements**:

- **Few-shot examples** in Passes 3, 4, 5 — real vulnerability + false positive examples from exploit knowledge base
- **Severity calibration** — concrete thresholds tied to financial impact (Critical >$1M, High >$100K, Medium >$10K)
- **Chain-of-thought enforcement** — mandatory 5-step reasoning before JSON output
- **Multi-provider rotation** — Gemini Flash for cheap passes, Anthropic Claude for reasoning, OpenAI GPT for diversity
- **AI ensemble retired** — the 6-agent ensemble (6x cost, worse context) replaced by provider rotation within the structured pipeline

---

## License

Aether is distributed under the **MIT License**. See the [LICENSE](LICENSE) file for details.

## Author

**Dhillon Andrew Kannabhiran** (@l33tdawg)
- Email: l33tdawg@hitb.org
- Twitter: [@l33tdawg](https://twitter.com/l33tdawg)
- GitHub: [@l33tdawg](https://github.com/l33tdawg)

## Contributing

Contributions are welcome! Please feel free to submit issues, fork the repository, and create pull requests.
