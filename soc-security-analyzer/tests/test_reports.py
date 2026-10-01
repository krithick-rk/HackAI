"""
Tests for Stage 9 Reporting Engine (JSON and HTML report builders).
Validates schema compliance, reproducibility metadata, sanitization,
proper status distinction (CONFIRMED vs PROBABLE vs LEAD), and cost accounting.
"""

import json
import pytest
from typing import List

from src.soc_analyzer.reports.schemas import RunRecord, FindingReportItem
from src.soc_analyzer.reports.json_report import JSONReportBuilder, sanitize_data
from src.soc_analyzer.reports.html_report import HTMLReportBuilder
from src.soc_analyzer.findings.schemas import (
    Finding,
    FindingStatus,
    FindingLane,
    Severity,
    FindingReason,
)


def test_run_record_serialization():
    run = RunRecord(
        run_id="run_test_123",
        repository="/tmp/dummy_repo",
        source_snapshot_hash="abc1234567890def",
        configuration="default",
        top="aes_top",
        status="COMPLETED",
        tool_versions={"slang": "3.0", "z3": "4.12"},
        finding_summary={"confirmed": 1, "probable": 2, "lead": 0, "weakness_only": 1},
    )

    data = run.to_dict()
    assert data["run_id"] == "run_test_123"
    assert data["source_snapshot_hash"] == "abc1234567890def"
    assert data["tool_versions"]["slang"] == "3.0"

    reconstructed = RunRecord.from_dict(data)
    assert reconstructed.run_id == run.run_id
    assert reconstructed.top == "aes_top"


def test_sanitize_data_scrubs_secrets():
    raw = {
        "repo": "/path/to/repo",
        "api_key": "sk-secret-12345",
        "nested": {
            "auth_token": "token_abc_xyz",
            "normal_field": "safe_value",
            "headers": ["Authorization: Bearer secret_jwt_token_here", "Content-Type: text/json"],
        },
    }

    cleaned = sanitize_data(raw)
    assert cleaned["api_key"] == "[REDACTED]"
    assert cleaned["nested"]["auth_token"] == "[REDACTED]"
    assert cleaned["nested"]["normal_field"] == "safe_value"
    assert cleaned["nested"]["headers"][0] == "[REDACTED]"


def test_json_report_builder_structure():
    run = RunRecord(run_id="run_001", repository="/repo", status="COMPLETED")
    finding_confirmed = Finding(
        finding_id="F-CONFIRMED",
        weakness_class="ASSET_EXPOSURE",
        severity=Severity.HIGH,
        status=FindingStatus.CONFIRMED,
        lane=FindingLane.CONFIRMED,
        file="hw/ip/aes/rtl/aes_core.sv",
        line_range=(20, 25),
        title="Unmasked Key Exposure",
    )
    finding_probable = Finding(
        finding_id="F-PROBABLE",
        weakness_class="ACCESS_BYPASS",
        severity=Severity.CRITICAL,
        status=FindingStatus.PARKED,
        lane=FindingLane.PROBABLE,
        file="hw/ip/aes/rtl/aes_reg.sv",
        line_range=(50, 55),
        title="Bus Lock Bypass",
        parked_reason=FindingReason.NO_WITNESS,
    )

    report_data = JSONReportBuilder.build_report(
        run_record=run,
        design_db=None,
        findings=[finding_confirmed, finding_probable],
        cost_info={"spent_usd": 0.0, "api_status": "DISABLED", "terminal_calls": 2},
    )

    assert "run" in report_data
    assert "findings" in report_data
    assert "cost" in report_data
    assert len(report_data["findings"]) == 2

    # Check that PROBABLE is not mislabeled as CONFIRMED
    f_conf = next(f for f in report_data["findings"] if f["finding_id"] == "F-CONFIRMED")
    f_prob = next(f for f in report_data["findings"] if f["finding_id"] == "F-PROBABLE")

    assert f_conf["status"] == "CONFIRMED"
    assert f_prob["status"] == "PROBABLE"
    assert f_prob["status"] != "CONFIRMED"
    assert "NO_WITNESS" in f_prob["reasons"]


def test_html_report_builder_generation_and_disclosures():
    run = RunRecord(
        run_id="run_html_test",
        repository="/test/repo",
        source_snapshot_hash="112233445566",
        configuration="sec_config",
        top="top_soc",
        status="COMPLETED",
    )
    finding_probable = Finding(
        finding_id="FINDING-PROB-01",
        weakness_class="TROJAN_TRIGGER",
        severity=Severity.MEDIUM,
        status=FindingStatus.PARKED,
        lane=FindingLane.PROBABLE,
        file="rtl/trojan.sv",
        line_range=(10, 15),
        title="Suspicious Counter Trigger",
        parked_reason=FindingReason.HARNESS_UNSUPPORTED,
    )

    report_dict = JSONReportBuilder.build_report(
        run_record=run,
        design_db=None,
        findings=[finding_probable],
        cost_info={"spent_usd": 0.0, "api_status": "DISABLED", "terminal_calls": 3},
        benchmark_summary={"recall": "53.85%", "precision": "63.64%"},
    )

    html_content = HTMLReportBuilder.build_html_report(report_dict)

    # Validate mandatory sections
    assert "Executive Summary" in html_content
    assert "Scan Configuration" in html_content
    assert "Findings" in html_content
    assert "Analyzability" in html_content
    assert "AI Usage / Cost" in html_content
    assert "Benchmark Metrics" in html_content
    assert "Limitations & Disclaimers" in html_content

    # Validate PROBABLE finding status rendering and lack of mislabeling
    assert "FINDING-PROB-01" in html_content
    assert "PROBABLE" in html_content
    assert "Never describe a PROBABLE finding as confirmed" in html_content

    # Validate honest benchmark metrics (53.85% baseline recall)
    assert "53.85%" in html_content

    # Validate analyzability disclosure
    assert "Semantic AI coverage is reduced in degraded/obfuscated regions" in html_content

    # Validate cost disclosure (API: DISABLED, $0.00 spent)
    assert "API: DISABLED" in html_content
    assert "$0.00" in html_content
