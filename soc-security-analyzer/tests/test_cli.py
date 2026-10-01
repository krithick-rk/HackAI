"""
Tests for Stage 9 Unified CLI (soc-analyzer).
Validates entry points, argument parsing, scan flows, exit codes, and benchmark command.
"""

import sys
import subprocess
import pytest
from unittest.mock import patch, MagicMock

from src.soc_analyzer.config import (
    EXIT_SUCCESS,
    EXIT_FATAL_ERROR,
    EXIT_PARTIAL_ANALYSIS,
    EXIT_FINDINGS_PRESENT,
    EXIT_BENCHMARK_FAILURE,
    AnalyzerConfig,
)
from src.soc_analyzer.cli import main, build_parser as create_parser


def test_cli_parser_defaults():
    parser = create_parser()
    args = parser.parse_args(["scan", "./repo"])
    assert args.command == "scan"
    assert args.repository == "./repo"
    assert args.top is None
    assert args.no_ai is True
    assert args.no_dynamic is False


def test_cli_version(capsys):
    with patch.object(sys, "argv", ["soc-analyzer", "version"]):
        code = main()
        assert code == EXIT_SUCCESS
        captured = capsys.readouterr()
        assert "SoC Security Analyzer" in captured.out
        assert "2." in captured.out


def test_cli_no_command(capsys):
    with patch.object(sys, "argv", ["soc-analyzer"]):
        code = main()
        assert code == EXIT_SUCCESS


def test_cli_invalid_repo(capsys):
    with patch.object(sys, "argv", ["soc-analyzer", "scan", "/nonexistent_repo_dir_12345"]):
        code = main()
        assert code == EXIT_FATAL_ERROR
        captured = capsys.readouterr()
        combined = captured.out + captured.err
        assert "does not exist" in combined


def test_cli_validate_nonexistent(capsys):
    with patch.object(sys, "argv", ["soc-analyzer", "validate", "/nonexistent_repo_dir_12345"]):
        code = main()
        assert code == EXIT_FATAL_ERROR


def test_cli_findings_empty(tmp_path, capsys):
    empty_rep = tmp_path / "empty_report.json"
    empty_rep.write_text('{"run": {"run_id": "test_run"}, "findings": []}')
    with patch.object(sys, "argv", ["soc-analyzer", "findings", "--report", str(empty_rep)]):
        code = main()
        assert code == EXIT_SUCCESS
        captured = capsys.readouterr()
        assert "No findings recorded" in captured.out


def test_cli_findings_with_data(tmp_path, capsys):
    rep_file = tmp_path / "test_report.json"
    rep_file.write_text("""
    {
      "run": {"run_id": "test_run"},
      "findings": [
        {
          "finding_id": "F-001",
          "title": "Secret Key Leak",
          "weakness_class": "ASSET_EXPOSURE",
          "severity": "HIGH",
          "status": "CONFIRMED",
          "lane": "DETERMINISTIC",
          "instance_path": "top.aes"
        }
      ]
    }
    """)
    with patch.object(sys, "argv", ["soc-analyzer", "findings", "--report", str(rep_file)]):
        code = main()
        assert code == EXIT_SUCCESS
        captured = capsys.readouterr()
        assert "F-001" in captured.out
        assert "CONFIRMED" in captured.out


def test_cli_benchmark_invocation(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with patch.object(sys, "argv", ["soc-analyzer", "benchmark"]):
        code = main()
        assert code in (EXIT_SUCCESS, EXIT_BENCHMARK_FAILURE)


def test_cli_exit_code_constants():
    assert EXIT_SUCCESS == 0
    assert EXIT_FATAL_ERROR == 1
    assert EXIT_PARTIAL_ANALYSIS == 2
    assert EXIT_FINDINGS_PRESENT == 3
    assert EXIT_BENCHMARK_FAILURE == 4


def test_verify_pipeline_backwards_compatibility():
    import subprocess
    res = subprocess.run(
        [sys.executable, "verify_pipeline.py", "--help"],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0
    assert "Generic Phase 0 SoC Analyzer Pipeline Runner" in res.stdout
