import json
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import patch

from core.aderyn_adapter import AderynAdapter


def _sample_report():
    return {
        "high_issues": {
            "issues": [
                {
                    "title": "Sensitive setter without guard",
                    "description": "Setter updates sensitive configuration without authorization checks.",
                    "detector_name": "sensitive-setter-without-guard",
                    "instances": [
                        {
                            "contract_path": "src/Vault.sol",
                            "line_no": 42,
                            "src": "100:12",
                            "src_char": "100:12",
                            "src_char2": "4:12",
                            "hint": "Missing onlyOwner",
                        }
                    ],
                }
            ]
        },
        "low_issues": {
            "issues": [
                {
                    "title": "Unused import",
                    "description": "Unused import increases maintenance overhead.",
                    "detector_name": "unused-import",
                    "instances": [
                        {
                            "contract_path": "src/Vault.sol",
                            "line_no": 3,
                            "src": "5:8",
                            "src_char": "5:8",
                            "src_char2": "1:8",
                        }
                    ],
                }
            ]
        },
    }


class TestAderynAdapter:
    @patch("core.aderyn_adapter.shutil.which", return_value=None)
    @patch("core.aderyn_adapter.os.path.isfile", return_value=False)
    @patch("core.aderyn_adapter.os.access", return_value=False)
    def test_unavailable_without_binary(self, _mock_access, _mock_isfile, _mock_which):
        adapter = AderynAdapter()
        assert not adapter.is_available()
        result = adapter.run(".")
        assert not result.success
        assert result.error_message == "aderyn is not installed"

    @patch("core.aderyn_adapter.shutil.which", return_value="C:\\tools\\aderyn.exe")
    @patch("core.aderyn_adapter.os.path.isfile", return_value=True)
    @patch("core.aderyn_adapter.os.access", return_value=True)
    @patch("core.aderyn_adapter.subprocess.run")
    def test_parse_and_normalize_report(self, mock_run, _mock_access, _mock_isfile, _mock_which):
        mock_run.return_value = subprocess.CompletedProcess(
            args=["aderyn", "--version"],
            returncode=0,
            stdout="aderyn 0.4.2",
            stderr="",
        )
        adapter = AderynAdapter()

        findings = adapter.parse_report(_sample_report())
        assert len(findings) == 2
        assert findings[0].detector_name == "sensitive-setter-without-guard"

        normalized = adapter.normalize_findings(findings)
        assert len(normalized) == 2
        assert normalized[0]["tool"] == "aderyn"
        assert normalized[0]["severity"] == "high"
        assert normalized[0]["line_number"] == 42
        assert normalized[0]["context"]["hint"] == "Missing onlyOwner"
        assert normalized[1]["severity"] == "low"

    @patch("core.aderyn_adapter.shutil.which", return_value="C:\\tools\\aderyn.exe")
    @patch("core.aderyn_adapter.os.path.isfile", return_value=True)
    @patch("core.aderyn_adapter.os.access", return_value=True)
    @patch("core.aderyn_adapter.subprocess.run")
    def test_run_reads_json_report_and_filters_detectors(
        self,
        mock_run,
        _mock_access,
        _mock_isfile,
        _mock_which,
    ):
        def fake_run(cmd, capture_output, text, timeout, env, cwd):
            if "--version" in cmd:
                return subprocess.CompletedProcess(cmd, 0, stdout="aderyn 0.4.2", stderr="")

            output_path = cmd[cmd.index("--output") + 1]
            with open(output_path, "w", encoding="utf-8") as handle:
                json.dump(_sample_report(), handle)

            return subprocess.CompletedProcess(cmd, 0, stdout="ok", stderr="")

        mock_run.side_effect = fake_run
        adapter = AderynAdapter()

        with tempfile.TemporaryDirectory() as tmpdir:
            contract_path = Path(tmpdir) / "Vault.sol"
            contract_path.write_text("contract Vault {}", encoding="utf-8")

            result = adapter.run(
                str(contract_path),
                detector_names=["sensitive-setter-without-guard"],
            )

        assert result.success
        assert len(result.findings) == 1
        assert len(result.normalized_findings) == 1
        assert result.normalized_findings[0]["vulnerability_type"] == "sensitive-setter-without-guard"
        assert result.command[1] == str(contract_path.parent.resolve())
        assert "-i" in result.command
        assert "Vault.sol" in result.command

    @patch("core.aderyn_adapter.shutil.which", return_value="C:\\tools\\aderyn.exe")
    @patch("core.aderyn_adapter.os.path.isfile", return_value=True)
    @patch("core.aderyn_adapter.os.access", return_value=True)
    @patch("core.aderyn_adapter.subprocess.run")
    def test_run_handles_timeout(self, mock_run, _mock_access, _mock_isfile, _mock_which):
        def fake_run(cmd, capture_output, text, timeout, env, cwd):
            if "--version" in cmd:
                return subprocess.CompletedProcess(cmd, 0, stdout="aderyn 0.4.2", stderr="")
            raise subprocess.TimeoutExpired(cmd=cmd, timeout=timeout)

        mock_run.side_effect = fake_run
        adapter = AderynAdapter(timeout=5)
        result = adapter.run(".")
        assert not result.success
        assert "timed out" in result.error_message
