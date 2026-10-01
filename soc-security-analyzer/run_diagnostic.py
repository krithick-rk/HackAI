#!/usr/bin/env python3
"""
run_diagnostic.py — Standalone diagnostic benchmark driver.

Usage:
    python run_diagnostic.py [--out PATH] [--stability-n N] [--no-injection] [--no-obfuscation]

Runs D1 (baseline stability), D2 (gold injection), and D3 (obfuscation ablation)
and writes the JSON report to stdout (or --out PATH if specified).

Exit codes:
  0  — recall >= 0.5 (informational threshold)
  1  — recall < 0.5
  2  — internal error
"""
from __future__ import annotations

import sys
import json
import argparse

# Ensure project root is on the path when run directly
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.soc_analyzer.benchmark.diagnostic import DiagnosticRunner


def main() -> int:
    parser = argparse.ArgumentParser(description="SoC Security Analyzer — Diagnostic Benchmark")
    parser.add_argument("--out", metavar="PATH", help="Write JSON report to this file (default: stdout)")
    parser.add_argument("--stability-n", type=int, default=3, metavar="N",
                        help="Number of stability iterations (D1, default=3)")
    parser.add_argument("--no-injection", action="store_true",
                        help="Skip D2 gold-injection audit")
    parser.add_argument("--no-obfuscation", action="store_true",
                        help="Skip D3 obfuscation-ablation audit")
    parser.add_argument("--quiet", action="store_true",
                        help="Suppress human-readable summary; only output JSON")
    args = parser.parse_args()

    try:
        runner = DiagnosticRunner()
        report = runner.run_diagnostic(
            stability_iterations=args.stability_n,
            include_injection=not args.no_injection,
            include_obfuscation_ablation=not args.no_obfuscation,
            output_path=args.out,
        )
    except Exception as exc:
        print(f"[DIAGNOSTIC ERROR] {exc}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 2

    # ---------------------------------------------------------------
    # Human-readable summary
    # ---------------------------------------------------------------
    if not args.quiet:
        cm = report.get("canonical_metrics", {})
        funnel = report.get("loss_stage_funnel", {})
        inj = report.get("injection_audit", {})
        obf = report.get("obfuscation_ablation", {})
        stab = report.get("stability", {})

        print("\n" + "=" * 72)
        print("  SoC Security Analyzer V2 — Diagnostic Benchmark Report")
        print("=" * 72)

        print(f"\n[D1] Stability ({stab.get('iterations', 0)} runs)")
        print(f"  Stable cases : {stab.get('stable_cases', '?')} / {stab.get('total_cases', '?')}")
        print(f"  Stability    : {stab.get('stability_rate', 0.0):.1%}")
        if stab.get("inconsistent_cases"):
            print(f"  Inconsistent : {stab['inconsistent_cases']}")

        print(f"\n[Canonical Metrics]  ({cm.get('total_cases', 0)} cases)")
        print(f"  TP={cm.get('tp', 0)}  FP={cm.get('fp', 0)}  TN={cm.get('tn', 0)}  FN={cm.get('fn', 0)}")
        print(f"  Recall    : {cm.get('recall', 0.0):.1%}")
        print(f"  Precision : {cm.get('precision', 0.0):.1%}")
        print(f"  F1        : {cm.get('f1', 0.0):.4f}")

        print(f"\n[Loss-Stage Funnel]  (gold TP cases: {funnel.get('total_gold_tp_cases', 0)})")
        sb = funnel.get("stage_breakdown", {})
        for stage, count in sb.items():
            bar = "■" * count
            print(f"  {stage:<24} {count:3d}  {bar}")
        print(f"  {'--- DETECTED ---':<24} {funnel.get('detected', 0):3d}")

        if funnel.get("false_negative_details"):
            print("\n[False Negative Details]")
            for detail in funnel["false_negative_details"]:
                notes_str = "; ".join(detail.get("notes", [])) or "—"
                print(f"  [{detail['loss_stage']:<22}] {detail['case_id']}  ({detail['category']}, {detail['difficulty']})")
                print(f"    notes: {notes_str}")

        if inj:
            print(f"\n[D2] Injection Audit  ({inj.get('total_cases', 0)} TP cases injected)")
            print(f"  Surfaced     : {inj.get('surfaced', 0)}")
            print(f"  Not surfaced : {inj.get('not_surfaced', 0)}")
            print(f"  Pass rate    : {inj.get('injection_pass_rate', 0.0):.1%}")
            for r in inj.get("results", []):
                if not r.get("injected_surfaced"):
                    print(f"    LOST  [{r['stage_if_lost']:<20}] {r['case_id']}  lane={r.get('lane')}")

        if obf and obf.get("pairs", 0) > 0:
            print(f"\n[D3] Obfuscation Ablation  ({obf.get('pairs', 0)} pairs)")
            print(f"  Original recall    : {obf.get('original_recall', 0.0):.1%}")
            print(f"  Obfuscated recall  : {obf.get('obfuscated_recall', 0.0):.1%}")
            print(f"  Retention          : {obf.get('recall_retention', 0.0):.4f}")
            print(f"  Degraded pairs     : {obf.get('degraded_pairs', 0)}")
        elif obf:
            print(f"\n[D3] Obfuscation Ablation: {obf.get('note', 'no pairs')}")

        print("\n" + "=" * 72)
        if args.out:
            print(f"Full JSON report written to: {args.out}")
        print()

    # ---------------------------------------------------------------
    # If no --out, dump JSON to stdout in quiet mode
    # ---------------------------------------------------------------
    if args.quiet or not args.out:
        print(json.dumps(report, indent=2, default=str))

    recall = report.get("canonical_metrics", {}).get("recall", 0.0)
    return 0 if recall >= 0.5 else 1


if __name__ == "__main__":
    sys.exit(main())
