import asyncio
import sys
import types
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from core.aderyn_detector_selector import AderynProjectClassification, SENSITIVE_SETTER_DETECTOR


SAMPLE_CONTRACT = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;
contract Vault {
    address public treasury;
    uint256 public feeBps;
    function setTreasury(address _treasury) external {
        treasury = _treasury;
    }
    function setFeeBps(uint256 _feeBps) external {
        feeBps = _feeBps;
    }
}
"""


class TestEnhancedEngineAderynIntegration(unittest.TestCase):
    def setUp(self):
        fake_lfp = types.ModuleType("core.llm_false_positive_filter")
        fake_db = types.ModuleType("core.database_manager")
        fake_fpg = types.ModuleType("core.foundry_poc_generator")
        fake_report = types.ModuleType("core.enhanced_report_generator")

        class FakeLLMFalsePositiveFilter:
            def __init__(self, *_args, **_kwargs):
                pass

        class FakeDatabaseManager:
            def __init__(self, *_args, **_kwargs):
                pass

        class FakeFoundryPoCGenerator:
            def __init__(self, *_args, **_kwargs):
                pass

        class FakeEnhancedReportGenerator:
            def __init__(self, *_args, **_kwargs):
                pass

        fake_lfp.LLMFalsePositiveFilter = FakeLLMFalsePositiveFilter
        fake_db.DatabaseManager = FakeDatabaseManager
        fake_db.AuditResult = dict
        fake_db.VulnerabilityFinding = dict
        fake_db.LearningPattern = dict
        fake_db.AuditMetrics = dict
        fake_fpg.FoundryPoCGenerator = FakeFoundryPoCGenerator
        fake_report.EnhancedReportGenerator = FakeEnhancedReportGenerator
        self._module_patch = patch.dict(
            sys.modules,
            {
                "core.llm_false_positive_filter": fake_lfp,
                "core.database_manager": fake_db,
                "core.foundry_poc_generator": fake_fpg,
                "core.enhanced_report_generator": fake_report,
            },
        )
        self._module_patch.start()

        import core.enhanced_audit_engine as enhanced_audit_engine

        self._patchers = [
            patch.object(enhanced_audit_engine, "DatabaseManager"),
            patch.object(enhanced_audit_engine, "EnhancedReportGenerator"),
            patch.object(enhanced_audit_engine, "FoundryPoCGenerator"),
            patch.object(enhanced_audit_engine, "VulnerabilityValidator"),
            patch.object(enhanced_audit_engine, "EnhancedLLMAnalyzer"),
            patch.object(enhanced_audit_engine, "EnhancedVulnerabilityDetector"),
            patch.object(enhanced_audit_engine, "FileHandler"),
            patch.object(enhanced_audit_engine, "AderynAdapter"),
        ]
        self.mocks = [patcher.start() for patcher in self._patchers]
        self.addCleanup(self._cleanup_patchers)

        self.enhanced_audit_engine = enhanced_audit_engine
        self.engine = enhanced_audit_engine.EnhancedAetherAuditEngine()
        self.mock_aderyn_cls = self.mocks[-1]

    def _cleanup_patchers(self):
        for patcher in reversed(getattr(self, "_patchers", [])):
            patcher.stop()
        self._module_patch.stop()

    @patch("core.taint_analyzer.TaintAnalyzer")
    @patch("core.access_control_context_analyzer.AccessControlContextAnalyzer")
    @patch("core.vulnerability_deduplicator.VulnerabilityDeduplicator")
    @patch("core.defi_vulnerability_detector.DeFiVulnerabilityDetector")
    @patch("core.solidity_ast.SolidityASTParser")
    @patch("core.delegation_analyzer.DelegationFlowAnalyzer")
    @patch("core.enhanced_audit_engine.classify_project_for_aderyn")
    def test_enhanced_static_analysis_includes_aderyn_bucket(
        self,
        mock_classify,
        mock_dfa_cls,
        mock_ast_cls,
        mock_defi_cls,
        mock_vd_cls,
        mock_acca_cls,
        mock_taint_cls,
    ):
        self.engine.vulnerability_detector.analyze_contract.return_value = []
        self.engine.vulnerability_detector.build_call_graph_from_contracts = MagicMock()
        self.engine.vulnerability_detector.set_contract_context = MagicMock()

        mock_dfa = MagicMock()
        flow = MagicMock()
        flow.has_proxy_pattern = False
        mock_dfa.analyze_delegation_flow.return_value = flow
        mock_dfa_cls.return_value = mock_dfa

        mock_ast = MagicMock()
        mock_ast.ast_available = False
        mock_ast_cls.return_value = mock_ast

        mock_defi = MagicMock()
        mock_defi.analyze_contract.return_value = []
        mock_defi_cls.return_value = mock_defi

        mock_vd = MagicMock()
        mock_vd.remove_subsumed_vulnerabilities.side_effect = lambda items: items
        mock_vd.deduplicate.side_effect = lambda items: items
        mock_vd_cls.return_value = mock_vd

        mock_acca = MagicMock()
        mock_acca_cls.return_value = mock_acca

        mock_taint = MagicMock()
        mock_taint.analyze_multiple.return_value = []
        mock_taint_cls.return_value = mock_taint
        mock_classify.return_value = AderynProjectClassification(
            target_path="src",
            solidity_files_scanned=1,
            sensitive_state_hits=2,
            setter_function_hits=2,
            state_variable_hits=2,
            enabled_detectors={SENSITIVE_SETTER_DETECTOR},
            reasons=["test fixture"],
        )

        mock_aderyn = MagicMock()
        mock_aderyn.run.return_value = MagicMock(
            success=True,
            normalized_findings=[
                {
                    "vulnerability_type": "sensitive-setter-without-guard",
                    "title": "Sensitive setter without guard",
                    "severity": "high",
                    "confidence": 0.85,
                    "line_number": 5,
                    "line": 5,
                    "description": "Setter updates sensitive configuration without authorization checks.",
                    "code_snippet": "",
                    "category": "aderyn_custom",
                    "file": "src/Vault.sol",
                    "tool": "aderyn",
                    "status": "confirmed",
                    "context": {"file_path": "src/Vault.sol", "detector_name": "sensitive-setter-without-guard"},
                }
            ],
            error_message=None,
        )
        self.mock_aderyn_cls.return_value = mock_aderyn

        result = asyncio.run(
            self.engine._run_enhanced_static_analysis(
                [{"path": "src/Vault.sol", "content": SAMPLE_CONTRACT, "name": "Vault.sol"}]
            )
        )

        self.assertIn("aderyn_analysis", result)
        self.assertEqual(len(result["aderyn_analysis"]["vulnerabilities"]), 1)
        self.assertEqual(result["aderyn_analysis"]["errors"], [])
        self.assertEqual(len(result["vulnerabilities"]), 1)
        self.assertEqual(result["vulnerabilities"][0]["tool"], "aderyn")


class TestStaticAnalysisNodeAderynIntegration(unittest.TestCase):
    @patch("core.nodes.audit_nodes.AderynAdapter")
    @patch("core.nodes.audit_nodes.DeFiVulnerabilityDetector")
    @patch("core.improved_vulnerability_detector.ImprovedVulnerabilityDetector")
    @patch("core.nodes.audit_nodes.classify_project_for_aderyn")
    def test_static_node_includes_aderyn_bucket(
        self,
        mock_classify,
        mock_improved_cls,
        mock_defi_cls,
        mock_aderyn_cls,
    ):
        from core.nodes.audit_nodes import StaticAnalysisNode

        mock_improved = MagicMock()
        mock_improved.analyze_contract.return_value = []
        mock_improved_cls.return_value = mock_improved

        mock_defi = MagicMock()
        mock_defi.analyze_contract.return_value = []
        mock_defi_cls.return_value = mock_defi
        mock_classify.return_value = AderynProjectClassification(
            target_path="src",
            solidity_files_scanned=1,
            sensitive_state_hits=2,
            setter_function_hits=2,
            state_variable_hits=2,
            enabled_detectors={SENSITIVE_SETTER_DETECTOR},
            reasons=["test fixture"],
        )

        mock_aderyn = MagicMock()
        mock_aderyn.run.return_value = MagicMock(
            success=True,
            normalized_findings=[
                {
                    "title": "Sensitive setter without guard",
                    "description": "Setter updates sensitive configuration without authorization checks.",
                    "severity": "high",
                    "confidence": 0.85,
                    "file": "src/Vault.sol",
                    "line": 5,
                    "tool": "aderyn",
                    "category": "aderyn_custom",
                    "status": "confirmed",
                    "vulnerability_type": "sensitive-setter-without-guard",
                }
            ],
            error_message=None,
        )
        mock_aderyn_cls.return_value = mock_aderyn

        node = StaticAnalysisNode("static", {})
        context = {
            "contract_files": [("src/Vault.sol", SAMPLE_CONTRACT)],
            "enhanced_mode": False,
        }

        result = asyncio.run(node.execute(context))

        self.assertTrue(result.success)
        self.assertIn("aderyn_analysis", context["static_analysis_results"])
        self.assertEqual(len(context["static_analysis_results"]["aderyn_analysis"]["vulnerabilities"]), 1)
        self.assertEqual(len(context["vulnerabilities"]), 1)
        self.assertEqual(context["vulnerabilities"][0]["tool"], "aderyn")
