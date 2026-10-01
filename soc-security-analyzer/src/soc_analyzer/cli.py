"""
Unified Top-Level Command-Line Interface (Stage 9).
Provides single entry point:
  soc-analyzer scan <repository>
  soc-analyzer validate <repository>
  soc-analyzer benchmark
  soc-analyzer findings
  soc-analyzer version
"""

from __future__ import annotations
import os
import sys

# Ensure repository root is on sys.path so 'src.soc_analyzer' imports resolve cleanly
_cur_dir = os.path.dirname(os.path.abspath(__file__))
_src_dir = os.path.dirname(_cur_dir)
_repo_dir = os.path.dirname(_src_dir)
if _repo_dir not in sys.path:
    sys.path.insert(0, _repo_dir)

import json
import argparse
from typing import List, Optional

from .config import (
    AnalyzerConfig,
    EXIT_SUCCESS,
    EXIT_FATAL_ERROR,
    EXIT_PARTIAL_ANALYSIS,
    EXIT_FINDINGS_PRESENT,
    EXIT_BENCHMARK_FAILURE,
    EXIT_CODE_DESCRIPTIONS,
)
from .pipeline import AnalyzerPipeline
from .benchmark.runner import BenchmarkRunner
from .benchmark.audits.unknown_invariant import UnknownInvariantTester
from .reports.html_report import HTMLReportBuilder
from .phase0.tool_validator import validate_environment

VERSION = "2.0.0"


def print_banner():
    print("==================================================")
    print("           SOC HARDWARE SECURITY ANALYZER         ")
    print(f"                       v{VERSION}                 ")
    print("==================================================")


def cmd_scan(args: argparse.Namespace) -> int:
    """Executes full security scan on target repository."""
    print_banner()

    # Load file config if supplied
    cfg = AnalyzerConfig(repository=args.repository)
    if args.config and os.path.exists(args.config):
        cfg = AnalyzerConfig.from_file(args.config)
        cfg.repository = args.repository or cfg.repository

    # CLI flags override config
    if args.top: cfg.top_module = args.top
    if args.module: cfg.module = args.module
    if args.output: cfg.output_dir = args.output
    if args.budget is not None: cfg.budget = float(args.budget)
    if args.mode: cfg.mode = args.mode
    if args.backend: cfg.backend = args.backend
    if args.no_ai: cfg.no_ai = True
    if args.no_dynamic: cfg.no_dynamic = True
    if args.verbose: cfg.verbose = True
    if args.exit_on_findings: cfg.exit_on_findings = True

    errs = cfg.validate()
    if errs:
        for e in errs:
            print(f"[ERROR] {e}")
        return EXIT_FATAL_ERROR

    print(f"\nRepository:    {os.path.abspath(cfg.repository)}")
    print(f"Configuration: {cfg.config_name}")
    print(f"Top:           {cfg.top_module or 'Auto-discovered'}\n")

    pipeline = AnalyzerPipeline(cfg)
    steps_completed = []

    def on_step(s: str):
        steps_completed.append(s)
        print(f"[✓] {s}")

    run_record, findings, json_path, html_path, exit_code = pipeline.execute(progress_callback=on_step)

    # Print compact summary matching Section 3
    print("\nResults")
    sumry = run_record.finding_summary
    print(f"  Confirmed: {sumry.get('CONFIRMED', 0)}")
    print(f"  Probable:  {sumry.get('PROBABLE', 0)}")
    print(f"  Lead:      {sumry.get('LEAD', 0)}")
    print(f"  Weakness:  {sumry.get('WEAKNESS_ONLY', 0)}")

    print("\nAnalyzability")
    ana = run_record.analyzability_summary
    print(f"  Normal:            {ana.get('normal', 0)}")
    print(f"  Degraded:          {ana.get('degraded', 0)}")
    print(f"  Highly obfuscated: {ana.get('highly_obfuscated', 0)}")

    print("\nAI")
    print(f"  Terminal tasks:        {run_record.cost_summary.get('terminal_calls', 0)}")
    print(f"  API tasks:             0 ({run_record.cost_summary.get('api_status', 'DISABLED')})")
    print(f"  Estimated/actual cost: ${run_record.cost_summary.get('spent_usd', 0.0):.2f}")

    print("\nReports")
    print(f"  {json_path}")
    print(f"  {html_path}\n")

    return exit_code


def cmd_validate(args: argparse.Namespace) -> int:
    """Validates the execution environment and target repository structure."""
    print_banner()
    repo_path = os.path.abspath(args.repository)
    print(f"Validating environment and repository: {repo_path}\n")

    if not os.path.exists(repo_path):
        print(f"[ERROR] Target path does not exist: {repo_path}")
        return EXIT_FATAL_ERROR

    # Check tools
    import shutil
    try:
        import z3
        has_z3 = True
    except ImportError:
        has_z3 = False

    status = {
        "slang": shutil.which("slang") is not None,
        "verilator": shutil.which("verilator") is not None,
        "yosys": shutil.which("yosys") is not None,
        "z3 (Python)": has_z3,
    }
    print("Toolchain Status:")
    for tool, ok in status.items():
        mark = "[✓]" if ok else "[✗]"
        print(f"  {mark} {tool}: {'Ready' if ok else 'Missing/Failed'}")

    all_tools_ok = all(status.values())
    print("\nRepository Structure:")
    # Count SV/V files
    sv_files = []
    for root, _, files in os.walk(repo_path):
        for f in files:
            if f.endswith((".sv", ".v")):
                sv_files.append(os.path.join(root, f))
    print(f"  [✓] Discovered {len(sv_files)} SystemVerilog/Verilog source files")

    if not all_tools_ok:
        print("\n[WARNING] Some optional tools are unconfigured; analysis will fall back to static/emulated modes.")
        return EXIT_PARTIAL_ANALYSIS

    print("\nValidation Succeeded. Environment is ready for scanning.")
    return EXIT_SUCCESS


def cmd_benchmark(args: argparse.Namespace) -> int:
    """Executes deterministic benchmark regression suite."""
    print_banner()
    print("Running Deterministic Security Benchmark Suite (Stage 8)...\n")

    runner = BenchmarkRunner()
    output_json = args.output or "benchmark_result.json"
    report = runner.run_all(output_report_path=output_json)

    # Also generate benchmark HTML report
    output_html = os.path.splitext(output_json)[0] + ".html"
    bm_data = {
        "run": {"run_id": report.run_id, "start_time": report.timestamp, "status": "COMPLETED"},
        "configuration": {"repository": "benchmark_corpus", "active_config": "seeded_cases"},
        "findings": [],
        "cost": {"api_status": "DISABLED", "spent_usd": 0.00, "terminal_calls": report.totals.get("cases", 0)},
        "benchmark_references": {
            "recall": f"{report.metrics.recall * 100:.2f}%",
            "precision": f"{report.metrics.precision * 100:.2f}%",
            "wrong_refutation_rate": f"{report.metrics.wrong_refutation_rate * 100:.2f}%",
            "obfuscation_recall_retention": f"{report.metrics.obfuscation_recall_retention * 100:.2f}%",
        },
    }
    html_str = HTMLReportBuilder.build_html_report(bm_data)
    HTMLReportBuilder.write_html_report(html_str, output_html)

    # UNKNOWN invariant check
    unknown_report = UnknownInvariantTester.test_all_failure_modes()

    print("Benchmark Results:")
    print(f"  Total Cases:                  {report.totals.get('cases', 0)}")
    print(f"  True Positives:               {report.totals.get('true_positive', 0)}")
    print(f"  False Positives:              {report.totals.get('false_positive', 0)}")
    print(f"  True Negatives:               {report.totals.get('true_negative', 0)}")
    print(f"  False Negatives:              {report.totals.get('false_negative', 0)}")
    print(f"  Recall:                       {report.metrics.recall * 100:.2f}%")
    print(f"  Precision:                    {report.metrics.precision * 100:.2f}%")
    print(f"  Wrong Refutations:            {report.metrics.wrong_refutation_count} (0.00%)")
    print(f"  Obfuscation Recall Retention: {report.metrics.obfuscation_recall_retention * 100:.2f}%")
    print(f"  UNKNOWN->Terminal Violations: {unknown_report.unknown_to_terminal_count}")

    print("\nBenchmark Reports Generated:")
    print(f"  {output_json}")
    print(f"  {output_html}\n")

    if unknown_report.unknown_to_terminal_count > 0 or report.metrics.wrong_refutation_count > 0:
        return EXIT_BENCHMARK_FAILURE

    return EXIT_SUCCESS


def cmd_findings(args: argparse.Namespace) -> int:
    """Displays findings from previous scan report."""
    report_file = args.report or "reports/report.json"
    if not os.path.exists(report_file):
        print(f"[ERROR] Findings report not found: {report_file}")
        return EXIT_FATAL_ERROR

    with open(report_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    findings = data.get("findings", [])
    print_banner()
    print(f"Findings Report: {report_file} ({len(findings)} total findings)\n")

    if not findings:
        print("No findings recorded in this report.")
        return EXIT_SUCCESS

    for f in findings:
        status_label = f.get("status") or f.get("lane", "LEAD")
        f_id = f.get("finding_id", "fnd")
        title = f.get("title", "")
        cwe = f.get("cwe", "CWE-UNMAPPED")
        source = f"{f.get('source', '')}:{f.get('line_range', [1, 1])[0]}"
        print(f"[{status_label:9s}] {f_id}: {title} ({source}) [{cwe}]")

    print()
    return EXIT_SUCCESS


def cmd_version(args: argparse.Namespace) -> int:
    """Displays current analyzer version and branch."""
    print(f"SoC Security Analyzer V{VERSION} (develop branch)")
    return EXIT_SUCCESS


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="soc-analyzer",
        description="SoC Security Analyzer V2 — Comprehensive Hardware Security & Vulnerability Auditing",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # scan
    p_scan = subparsers.add_parser("scan", help="Run full security scan on target repository")
    p_scan.add_argument("repository", help="Path to hardware target repository or file")
    p_scan.add_argument("--config", help="Path to YAML/JSON configuration file")
    p_scan.add_argument("--top", help="Top-level module name")
    p_scan.add_argument("--module", help="Specific subsystem or module folder to scan")
    p_scan.add_argument("--output", default="reports", help="Output directory for reports")
    p_scan.add_argument("--budget", type=float, default=0.0, help="AI analysis dollar budget limit")
    p_scan.add_argument("--mode", choices=["fast", "deep"], default="fast", help="Analysis depth mode")
    p_scan.add_argument("--backend", default="agy", help="Primary AI backend (agy | codex)")
    p_scan.add_argument("--no-ai", action="store_true", default=True, help="Disable AI hypothesis generation")
    p_scan.add_argument("--no-dynamic", action="store_true", help="Disable dynamic simulation/witness evaluation")
    p_scan.add_argument("--verbose", action="store_true", help="Enable verbose debug logging")
    p_scan.add_argument("--exit-on-findings", action="store_true", help="Return exit code 3 if findings detected")

    # validate
    p_val = subparsers.add_parser("validate", help="Validate environment, toolchain, and repository")
    p_val.add_argument("repository", help="Target repository path to validate")

    # benchmark
    p_bench = subparsers.add_parser("benchmark", help="Run deterministic benchmark regression audit")
    p_bench.add_argument("--output", help="Output path for benchmark_result.json")

    # findings
    p_find = subparsers.add_parser("findings", help="Display findings from past scan report")
    p_find.add_argument("--report", help="Path to report.json file")

    # version
    subparsers.add_parser("version", help="Print version information")

    # server / dashboard
    p_server = subparsers.add_parser("server", aliases=["dashboard"], help="Start the SoC Security Analyzer web application and dashboard")
    p_server.add_argument("--host", default="0.0.0.0", help="Host interface to bind (default: 0.0.0.0)")
    p_server.add_argument("--port", type=int, default=8080, help="Port to listen on (default: 8080)")
    p_server.add_argument("--reload", action="store_true", help="Enable automatic code reloading during development")

    return parser


def cmd_server(args: argparse.Namespace) -> int:
    """Starts the SoC Analyzer Web Application and Dashboard."""
    import uvicorn
    print_banner()
    print(f"\n[+] Starting SoC Security Analyzer Web Server on http://{args.host}:{args.port}")
    print("[+] Press Ctrl+C to stop.\n")
    uvicorn.run("soc_analyzer.dashboard.server:app", host=args.host, port=args.port, reload=args.reload)
    return EXIT_SUCCESS


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return EXIT_SUCCESS

    if args.command == "scan":
        return cmd_scan(args)
    elif args.command == "validate":
        return cmd_validate(args)
    elif args.command == "benchmark":
        return cmd_benchmark(args)
    elif args.command == "findings":
        return cmd_findings(args)
    elif args.command == "version":
        return cmd_version(args)
    elif args.command in ("server", "dashboard"):
        return cmd_server(args)

    return EXIT_SUCCESS


if __name__ == "__main__":
    sys.exit(main())
