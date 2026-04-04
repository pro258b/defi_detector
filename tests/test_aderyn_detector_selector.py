from pathlib import Path

from core.aderyn_detector_selector import (
    SENSITIVE_SETTER_DETECTOR,
    classify_project_for_aderyn,
    filter_aderyn_findings_for_project,
)


def test_classify_project_enables_sensitive_setter_detector(tmp_path: Path):
    contract = tmp_path / "Vault.sol"
    contract.write_text(
        """
        pragma solidity ^0.8.20;
        contract Vault {
            address public owner;
            address public treasury;
            uint256 public feeBps;

            function setTreasury(address nextTreasury) external {
                treasury = nextTreasury;
            }
        }
        """,
        encoding="utf-8",
    )

    classification = classify_project_for_aderyn(str(tmp_path))

    assert SENSITIVE_SETTER_DETECTOR in classification.enabled_detectors


def test_filter_aderyn_findings_drops_sensitive_setter_for_irrelevant_project(tmp_path: Path):
    contract = tmp_path / "MathLib.sol"
    contract.write_text(
        """
        pragma solidity ^0.8.20;
        library MathLib {
            function add(uint256 a, uint256 b) internal pure returns (uint256) {
                return a + b;
            }
        }
        """,
        encoding="utf-8",
    )

    classification = classify_project_for_aderyn(str(tmp_path))

    findings = [
        {"vulnerability_type": SENSITIVE_SETTER_DETECTOR, "title": "Sensitive Setter Without Guard"},
        {"vulnerability_type": "unused-import", "title": "Unused Import"},
    ]

    filtered = filter_aderyn_findings_for_project(findings, classification)

    assert len(filtered) == 1
    assert filtered[0]["vulnerability_type"] == "unused-import"
