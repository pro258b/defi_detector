import sys
import types
import unittest
from unittest.mock import patch


SAMPLE_CONTRACT = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract Vault {
    function withdraw(uint256 amount) external {}
}
"""


class TestEnhancedLLMSkillIntegration(unittest.TestCase):
    def test_prompt_includes_skill_context(self):
        fake_openai = types.ModuleType("openai")

        class FakeOpenAI:
            def __init__(self, *args, **kwargs):
                pass

        fake_openai.OpenAI = FakeOpenAI

        fake_config = types.ModuleType("core.config_manager")

        class FakeConfigManager:
            def __init__(self, *args, **kwargs):
                self.config = types.SimpleNamespace(
                    openai_api_key="",
                    gemini_api_key="",
                    anthropic_api_key="",
                )

        fake_config.ConfigManager = FakeConfigManager
        fake_config.get_model_for_task = lambda _task: "gpt-4o"

        with patch.dict(
            sys.modules,
            {
                "openai": fake_openai,
                "core.config_manager": fake_config,
            },
        ):
            from core.enhanced_llm_analyzer import EnhancedLLMAnalyzer

            analyzer = EnhancedLLMAnalyzer(api_key="sk-test", model="gpt-4o")
            with patch(
                "core.enhanced_llm_analyzer.build_skill_prompt_sections",
                return_value={"one_shot": "## Additional Audit Skills\n- check reentrancy"},
            ):
                prompt = analyzer._create_enhanced_analysis_prompt(SAMPLE_CONTRACT, {})

        self.assertIn("Additional Audit Skills", prompt)
        self.assertIn("check reentrancy", prompt)


if __name__ == "__main__":
    unittest.main()
