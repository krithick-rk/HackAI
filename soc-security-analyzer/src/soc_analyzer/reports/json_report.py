"""
Machine-Readable JSON Report Generator (Stage 9).
Constructs reproducible, sanitized report.json files mapping findings,
evidence chains, reachability proofs, witness artifacts, and cost accounting.
"""

from __future__ import annotations
import json
import os
import re
from typing import Dict, List, Optional, Any

from src.soc_analyzer.design_db.schemas import DesignDB
from src.soc_analyzer.findings.schemas import Finding, FindingLane, FindingStatus
from .schemas import RunRecord, FindingReportItem

SECRET_PATTERNS = [
    re.compile(r"api[_-]?key", re.IGNORECASE),
    re.compile(r"secret[_-]?key", re.IGNORECASE),
    re.compile(r"auth[_-]?token", re.IGNORECASE),
    re.compile(r"password", re.IGNORECASE),
    re.compile(r"bearer\s+[a-zA-Z0-9_\-\.]+", re.IGNORECASE),
]


def sanitize_data(obj: Any) -> Any:
    """Recursively redacts potential credentials or sensitive tokens from report trees."""
    if isinstance(obj, dict):
        cleaned = {}
        for k, v in obj.items():
            if any(p.search(str(k)) for p in SECRET_PATTERNS):
                cleaned[k] = "[REDACTED]"
            else:
                cleaned[k] = sanitize_data(v)
        return cleaned
    elif isinstance(obj, list):
        return [sanitize_data(x) for x in obj]
    elif isinstance(obj, str):
        for p in SECRET_PATTERNS:
            if p.search(obj):
                return "[REDACTED]"
        return obj
    return obj


class JSONReportBuilder:
    """
    Constructs authoritative, structured report.json artifacts.
    """

    @classmethod
    def build_report(
        cls,
        run_record: RunRecord,
        design_db: Optional[DesignDB],
        findings: List[Finding],
        cost_info: Optional[Dict[str, Any]] = None,
        coverage_info: Optional[Dict[str, Any]] = None,
        benchmark_summary: Optional[Dict[str, Any]] = None,
        audit_summary: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Builds complete dictionary ready for serialization to report.json.
        """
        # 1. Project findings into report items
        finding_items: List[Dict[str, Any]] = []
        witness_items: List[Dict[str, Any]] = []
        evidence_items: List[Dict[str, Any]] = []

        seen_ev_ids = set()

        for f in findings:
            # Map structured reasons
            reasons = []
            if f.parked_reason and f.parked_reason.value != "NONE":
                reasons.append(f.parked_reason.value)
            if f.metadata.get("reasons"):
                for r in f.metadata["reasons"]:
                    if r not in reasons:
                        reasons.append(r)

            # Collect evidence references
            ev_list = []
            for ev in f.evidence_refs:
                ev_dict = ev.to_dict()
                ev_list.append(ev_dict)
                if ev.evidence_id not in seen_ev_ids:
                    seen_ev_ids.add(ev.evidence_id)
                    evidence_items.append(ev_dict)

            # Collect witnesses
            for w in f.witness_refs:
                witness_items.append({"finding_id": f.finding_id, "witness_ref": w})

            item = FindingReportItem(
                finding_id=f.finding_id,
                title=f.title or f"{f.weakness_class} in {f.definition_id or f.file}",
                weakness_class=f.weakness_class,
                severity=f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                status=(f.lane.value if f.lane in (FindingLane.CONFIRMED, FindingLane.PROBABLE, FindingLane.LEAD, FindingLane.WEAKNESS_ONLY) else (f.status.value if hasattr(f.status, "value") else str(f.status))),
                lane=f.lane.value if hasattr(f.lane, "value") else str(f.lane),
                source=f.source or f.file,
                line_range=f.line_range,
                instance_path=f.instance_path,
                configuration=f.configuration,
                asset=f.asset_id,
                attacker=f.attacker_id,
                reachability=f.reachability_result or {},
                witness=f.witness_refs,
                cwe=f.cwe,
                evidence=ev_list,
                reasons=reasons,
                manifestations=[m.to_dict() for m in f.manifestations],
                metadata=f.metadata,
            )
            finding_items.append(item.to_dict())

        # 2. Analyzability breakdown
        analyzability = {}
        if design_db and design_db.analyzability:
            for mod_name, assess in design_db.analyzability.items():
                analyzability[mod_name] = assess.to_dict()
        else:
            analyzability = run_record.analyzability_summary

        # 3. Assemble full report structure
        report_data = {
            "schema_version": "2.0.0",
            "run": run_record.to_dict(),
            "configuration": {
                "active_config": run_record.configuration,
                "top": run_record.top,
                "repository": run_record.repository,
            },
            "analyzability": {
                "summary": run_record.analyzability_summary,
                "modules": analyzability,
                "obfuscation_notice": "Semantic AI coverage is reduced in degraded/obfuscated regions; absence of AI finding does not imply cleanliness.",
            },
            "findings": finding_items,
            "evidence": evidence_items,
            "witnesses": witness_items,
            "cost": cost_info or run_record.cost_summary or {
                "api_status": "DISABLED",
                "run_budget_usd": 0.00,
                "spent_usd": 0.00,
                "remaining_usd": 0.00,
                "terminal_calls": 0,
                "api_calls": 0,
                "cache_hits": 0,
            },
            "runtime": {
                "start_time": run_record.start_time,
                "end_time": run_record.end_time,
            },
            "coverage": coverage_info or {
                "total_modules": len(design_db.definitions) if design_db else 0,
                "analyzed_modules": len(design_db.definitions) if design_db else 0,
            },
            "benchmark_references": benchmark_summary or {},
            "audit_references": audit_summary or {},
        }

        # 4. Sanitize sensitive information
        return sanitize_data(report_data)

    @classmethod
    def write_json_report(cls, report_data: Dict[str, Any], output_path: str) -> str:
        """Writes report dictionary to JSON file."""
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)
        return output_path
