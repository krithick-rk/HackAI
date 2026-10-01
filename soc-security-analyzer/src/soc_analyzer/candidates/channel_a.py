"""
Channel A: AI Hypothesis Generation.
Constructs bounded, scoped prompts for the AI Gateway (TaskType.HYPOTHESIZE).
Enforces HIGHLY_OBFUSCATED skip policy, strict structured output validation,
and generates CandidateClaim objects.
"""

from __future__ import annotations
import json
from typing import List, Dict, Any, Optional

from src.soc_analyzer.design_db.schemas import DesignDB, AnalyzabilityLevel
from src.soc_analyzer.ai_gateway import AIGateway, TaskPacket, TaskType, GatewayOutcome
from .schemas import (
    CandidateClaim,
    SourceChannel,
    CandidateStatus,
    EvidenceRef,
    EvidenceType,
    SecurityCone,
)


def validate_hypothesis_schema(data: Dict[str, Any]) -> bool:
    """Strict schema validator for AI hypothesis response."""
    if not isinstance(data, dict):
        return False
    # Check for NO_FINDING
    if data.get("no_finding") is True or data.get("status") == "NO_FINDING":
        return True
    claims = data.get("candidate_claims")
    if not isinstance(claims, list):
        return False
    for c in claims:
        if not isinstance(c, dict):
            return False
        # Required fields per Section 6
        if not c.get("weakness_class") or not c.get("file") or not c.get("claim"):
            return False
        lines = c.get("lines")
        if not isinstance(lines, list) or len(lines) < 2:
            return False
    return True


class AIHypothesisGenerator:
    """
    Orchestrates Channel A AI hypothesis generation.
    Enforces that AI only sees bounded slices and never sees the whole repository.
    """

    def __init__(self, gateway: Optional[AIGateway] = None):
        self.gateway = gateway or AIGateway()

    def generate_hypotheses(
        self,
        design_db: DesignDB,
        module_name: str,
        security_cone: Optional[SecurityCone] = None,
        source_line_start: int = 1,
        source_line_end: int = 50,
        tool_findings_summary: Optional[str] = None,
    ) -> List[CandidateClaim]:
        """
        Generates candidate claims using AI Gateway for a specific module and cone.
        Skips semantic AI analysis if module is HIGHLY_OBFUSCATED.
        """
        # 1. Analyzability check: Highly obfuscated code must skip AI semantic analysis
        assessment = design_db.analyzability.get(module_name)
        if assessment and assessment.level == AnalyzabilityLevel.HIGHLY_OBFUSCATED:
            # Deterministic channels still run, but semantic AI hypothesis is skipped
            return []

        mod_def = design_db.definitions.get(module_name)
        if not mod_def:
            return []

        # 2. Extract bounded source excerpt (never whole file/tree)
        source_lines = design_db.get_canonical_lines(
            mod_def.file_path,
            start_line=source_line_start,
            end_line=source_line_end,
        )
        source_excerpt = "".join(source_lines)

        # 3. Gather bounded facts
        registered_assets = [
            a.name for a in design_db.get_assets()
            if a.name.startswith(f"{module_name}.") or module_name in a.source_path
        ]

        # 4. Construct scoped prompt
        cone_info = f"Root: {security_cone.root_signal}, Nodes: {len(security_cone.nodes)}" if security_cone else "None"
        prompt = f"""You are an expert hardware security verification assistant.
Analyze this scoped slice of module '{module_name}' for potential security vulnerabilities.

Design facts:
- File: {mod_def.file_path}
- Lines: {source_line_start}-{source_line_end}
- Registered security assets: {registered_assets}
- Security cone: {cone_info}
- Tool warnings: {tool_findings_summary or 'None'}

Source excerpt ({source_line_start}-{source_line_end}):
```systemverilog
{source_excerpt}
```

Instructions:
Identify any potential security weakness (e.g. missing access control, unintended privilege escalation, uninitialized state).
Respond ONLY with a JSON object matching this schema:
{{
  "candidate_claims": [
    {{
      "weakness_class": "NAME_OF_WEAKNESS",
      "file": "{mod_def.file_path}",
      "lines": [{source_line_start}, {source_line_end}],
      "instance_path": "{module_name}",
      "claim": "Detailed security claim describing the vulnerability",
      "rationale": "Evidence and engineering reasoning",
      "quoted_snippet": "Exact snippet from the excerpt if applicable",
      "evidence_refs": ["fact_ref_1"]
    }}
  ]
}}
If no suspicious vulnerability is found, respond with:
{{"no_finding": true}}
"""

        # 5. Call AI Gateway (TaskType.HYPOTHESIZE -> STRONG tier)
        packet = TaskPacket(
            task_type=TaskType.HYPOTHESIZE,
            module=module_name,
            inputs={
                "module": module_name,
                "file": mod_def.file_path,
                "line_start": source_line_start,
                "line_end": source_line_end,
            },
        )

        resp = self.gateway.call(
            packet=packet,
            prompt=prompt,
            schema_validator=validate_hypothesis_schema,
        )

        if not resp.is_success or not resp.parsed_output:
            return []

        # If model returned no_finding, return empty list (not a proof of clean design)
        if resp.parsed_output.get("no_finding") is True or resp.parsed_output.get("status") == "NO_FINDING":
            return []

        raw_claims = resp.parsed_output.get("candidate_claims", [])
        candidates: List[CandidateClaim] = []

        for c in raw_claims:
            lines = c.get("lines", [source_line_start, source_line_end])
            l_start = int(lines[0]) if len(lines) > 0 else source_line_start
            l_end = int(lines[1]) if len(lines) > 1 else l_start

            claim_obj = CandidateClaim(
                source_channel=SourceChannel.AI_HYPOTHESIS,
                weakness_class=c.get("weakness_class", "AI_SUSPECTED_WEAKNESS"),
                title=f"AI Hypothesis: {c.get('weakness_class')} in {module_name}",
                description=c.get("rationale", ""),
                source_file=c.get("file", mod_def.file_path),
                line_range=(l_start, l_end),
                instance_path=c.get("instance_path", module_name),
                definition_id=module_name,
                security_cone=security_cone,
                claim=c.get("claim", ""),
                quoted_snippet=c.get("quoted_snippet"),
                evidence_refs=[
                    EvidenceRef(
                        evidence_type=EvidenceType.AI,
                        source=resp.backend_used,
                        hash_or_reference=packet.task_id,
                        description=f"Generated by {resp.backend_used}: {c.get('rationale', '')}",
                    )
                ],
                configuration=design_db.active_config,
                status=CandidateStatus.CANDIDATE,  # Unverified until Python grounding!
            )
            candidates.append(claim_obj)

        return candidates
