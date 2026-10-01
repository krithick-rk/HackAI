"""
UNKNOWN-to-Fail Invariant Regression Engine (Stage 8).
Enforces the fundamental architectural invariant:
UNKNOWN -> FAIL / REFUTED / UNREACHABLE must NEVER occur.
Injects parser failures, timeouts, unsupported RTL, incomplete registries, budget denials,
opaque cells, simulator failures, and Z3 UNKNOWN results to guarantee that ignorance
is never transformed into negative proof.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Tuple

from src.soc_analyzer.candidates.schemas import (
    CandidateClaim,
    CandidateStatus,
    SourceChannel,
    EvidenceRef,
)
from src.soc_analyzer.findings.schemas import (
    Finding,
    FindingStatus,
    FindingLane,
    FindingReason,
    EvidenceItem,
    EvidenceType,
    VerificationStatus,
)
from src.soc_analyzer.findings.confirmation_policy import ClassConfirmationPolicy
from src.soc_analyzer.findings.state_machine import StateTransitionValidator, InvalidTransitionError


class InjectedFailureMode(str, Enum):
    """Failure scenarios injected into the analysis pipeline."""
    TIMEOUT = "TIMEOUT"
    PARSER_FAILURE = "PARSER_FAILURE"
    UNSUPPORTED_RTL = "UNSUPPORTED_RTL"
    INCOMPLETE_REGISTRY = "INCOMPLETE_REGISTRY"
    INCOMPLETE_CONFIG = "INCOMPLETE_CONFIG"
    BUDGET_DENIAL = "BUDGET_DENIAL"
    OPAQUE_CELL = "OPAQUE_CELL"
    SIMULATOR_FAILURE = "SIMULATOR_FAILURE"
    Z3_UNKNOWN = "Z3_UNKNOWN"


@dataclass
class InvariantViolation:
    """Record of an unlawful transition from UNKNOWN to a terminal negative state."""
    mode: InjectedFailureMode
    candidate_id: str
    resulting_status: FindingStatus
    resulting_lane: FindingLane
    resulting_reason: FindingReason
    explanation: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mode": self.mode.value,
            "candidate_id": self.candidate_id,
            "resulting_status": self.resulting_status.value,
            "resulting_lane": self.resulting_lane.value,
            "resulting_reason": self.resulting_reason.value,
            "explanation": self.explanation,
        }


@dataclass
class UnknownInvariantReport:
    """Audit report for the UNKNOWN-to-Fail invariant."""
    total_injections: int = 0
    passed_injections: int = 0
    unknown_to_terminal_count: int = 0
    violations: List[InvariantViolation] = field(default_factory=list)
    results_by_mode: Dict[str, str] = field(default_factory=dict)

    @property
    def is_invariant_satisfied(self) -> bool:
        return self.unknown_to_terminal_count == 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_injections": self.total_injections,
            "passed_injections": self.passed_injections,
            "unknown_to_terminal_count": self.unknown_to_terminal_count,
            "invariant_satisfied": self.is_invariant_satisfied,
            "violations": [v.to_dict() for v in self.violations],
            "results_by_mode": self.results_by_mode,
        }


class UnknownInvariantTester:
    """
    Executes failure injection suite and verifies that unknown states never
    silently convert into refutations or sound unreachability verdicts.
    """

    TERMINAL_NEGATIVE_STATUSES = {
        FindingStatus.REFUTED,
        FindingStatus.UNREACHABLE,
    }

    TERMINAL_NEGATIVE_LANES = {
        FindingLane.UNREACHABLE,
        FindingLane.REFUTED,
    }

    @classmethod
    def test_all_failure_modes(cls) -> UnknownInvariantReport:
        """Runs the entire suite of 9 failure injection modes."""
        report = UnknownInvariantReport()

        modes = [
            InjectedFailureMode.TIMEOUT,
            InjectedFailureMode.PARSER_FAILURE,
            InjectedFailureMode.UNSUPPORTED_RTL,
            InjectedFailureMode.INCOMPLETE_REGISTRY,
            InjectedFailureMode.INCOMPLETE_CONFIG,
            InjectedFailureMode.BUDGET_DENIAL,
            InjectedFailureMode.OPAQUE_CELL,
            InjectedFailureMode.SIMULATOR_FAILURE,
            InjectedFailureMode.Z3_UNKNOWN,
        ]

        for mode in modes:
            report.total_injections += 1
            passed, violation = cls.test_single_mode(mode)
            if passed:
                report.passed_injections += 1
                report.results_by_mode[mode.value] = "PASS"
            else:
                report.unknown_to_terminal_count += 1
                report.results_by_mode[mode.value] = "VIOLATION"
                if violation:
                    report.violations.append(violation)

        return report

    @classmethod
    def test_single_mode(cls, mode: InjectedFailureMode) -> Tuple[bool, Optional[InvariantViolation]]:
        """Inject a specific failure mode and verify invariant compliance."""
        finding = cls._create_mock_finding_for_failure(mode)

        # Adjudicate using ClassConfirmationPolicy
        lane, reason = ClassConfirmationPolicy.evaluate_adjudication(finding)

        # Check if lane became terminal negative
        is_terminal = (lane in cls.TERMINAL_NEGATIVE_LANES)

        # Also verify state machine transition guard
        # Cannot transition to REFUTED if status is UNKNOWN
        try:
            StateTransitionValidator.validate_transition(
                finding=finding,
                new_status=FindingStatus.REFUTED,
                new_lane=FindingLane.REFUTED,
            )
            # If no exception was raised, that's an unlawful transition!
            violation = InvariantViolation(
                mode=mode,
                candidate_id=finding.finding_id,
                resulting_status=FindingStatus.REFUTED,
                resulting_lane=lane,
                resulting_reason=reason,
                explanation=f"State machine permitted transition to REFUTED on {mode.value} without sound proof",
            )
            return False, violation
        except InvalidTransitionError:
            # Expected! The state machine correctly rejected the transition to REFUTED!
            pass

        if is_terminal:
            violation = InvariantViolation(
                mode=mode,
                candidate_id=finding.finding_id,
                resulting_status=finding.status,
                resulting_lane=lane,
                resulting_reason=reason,
                explanation=f"Failure mode {mode.value} produced terminal negative lane {lane.value} ({reason.value})",
            )
            return False, violation

        return True, None

    @classmethod
    def _create_mock_finding_for_failure(cls, mode: InjectedFailureMode) -> Finding:
        """Create finding fixture representing an incomplete/failed analysis step."""
        base_finding = Finding(
            finding_id=f"f_fail_{mode.value.lower()}",
            weakness_class="LOCK_ACCESS_CONTROL",
            source_channel=SourceChannel.DETERMINISTIC,
            status=FindingStatus.CANDIDATE,
            lane=FindingLane.LEAD,
            parked_reason=FindingReason.NONE,
            file="soc_top.sv",
            line_range=(10, 20),
        )

        if mode == InjectedFailureMode.TIMEOUT:
            base_finding.reachability_result = {
                "result": "UNKNOWN",
                "reason": "Solver timeout after 30s",
                "is_model_complete": False,
            }
            base_finding.metadata["failure_mode"] = "TIMEOUT"

        elif mode == InjectedFailureMode.PARSER_FAILURE:
            base_finding.reachability_result = {
                "result": "UNKNOWN",
                "reason": "Slang parse syntax error at line 42",
                "is_model_complete": False,
            }
            base_finding.metadata["analyzability"] = "UNANALYZABLE"

        elif mode == InjectedFailureMode.UNSUPPORTED_RTL:
            base_finding.reachability_result = {
                "result": "UNKNOWN",
                "reason": "Unsupported system task $fopen in formal path",
                "is_model_complete": False,
            }

        elif mode == InjectedFailureMode.INCOMPLETE_REGISTRY:
            base_finding.reachability_result = {
                "result": "UNKNOWN",
                "reason": "Missing asset anchor in security registry",
                "is_model_complete": False,
            }
            base_finding.asset_id = None  # Missing asset anchor

        elif mode == InjectedFailureMode.INCOMPLETE_CONFIG:
            base_finding.reachability_result = {
                "result": "UNKNOWN",
                "reason": "Unresolved parameter PARAM_KEY_LEN",
                "is_model_complete": False,
            }

        elif mode == InjectedFailureMode.BUDGET_DENIAL:
            base_finding.reachability_result = {"result": "UNKNOWN", "reason": "AI budget exhausted", "is_model_complete": False}
            base_finding.metadata["budget_denied"] = True

        elif mode == InjectedFailureMode.OPAQUE_CELL:
            base_finding.reachability_result = {
                "result": "UNKNOWN",
                "reason": "Opaque blackbox crypto_core_hardmacro has no behavioral model",
                "is_model_complete": False,
            }
            base_finding.metadata["analyzability"] = "OPAQUE"

        elif mode == InjectedFailureMode.SIMULATOR_FAILURE:
            base_finding.reachability_result = {
                "result": "UNKNOWN",
                "reason": "Simulator process crashed or aborted execution",
                "is_model_complete": False,
            }
            base_finding.metadata["sim_status"] = "CRASH"
            # No verified witness
            base_finding.evidence_refs = [
                EvidenceItem(
                    evidence_id="ev_sim_fail",
                    evidence_type=EvidenceType.SIM_TRACE,
                    producer="verilator",
                    verification_status=VerificationStatus.UNVERIFIED,
                )
            ]

        elif mode == InjectedFailureMode.Z3_UNKNOWN:
            base_finding.reachability_result = {
                "result": "UNKNOWN",
                "reason": "Z3 returned unknown (non-linear arithmetic)",
                "is_model_complete": False,
            }

        return base_finding
