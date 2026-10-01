"""
Finding State Machine and Transition Validator (Stage 6).
Enforces deterministic, Python-authoritative state progression.
Rejects illegal state jumps, blocks AI from performing authoritative transitions,
and strictly enforces that UNKNOWN history cannot enter terminal-negative states.
"""

from __future__ import annotations
from typing import Set, Tuple, Optional, Any, List

from .schemas import (
    Finding,
    FindingStatus,
    FindingLane,
    FindingReason,
    VerificationStatus,
)


class InvalidTransitionError(Exception):
    """Raised when an illegal finding state or lane transition is attempted."""
    def __init__(self, message: str, current_state: Optional[str] = None, target_state: Optional[str] = None):
        super().__init__(f"Invalid finding state transition: {message} ({current_state} -> {target_state})")
        self.message = message
        self.current_state = current_state
        self.target_state = target_state


class StateTransitionValidator:
    """
    Validates state transitions according to V2 architecture rules.
    """

    ALLOWED_STATUS_TRANSITIONS: Set[Tuple[FindingStatus, FindingStatus]] = {
        # Forward pipeline progression
        (FindingStatus.CANDIDATE, FindingStatus.GROUNDED),
        (FindingStatus.CANDIDATE, FindingStatus.PARKED),
        (FindingStatus.CANDIDATE, FindingStatus.DUPLICATE),
        (FindingStatus.CANDIDATE, FindingStatus.REFUTED),

        (FindingStatus.GROUNDED, FindingStatus.REACHABLE),
        (FindingStatus.GROUNDED, FindingStatus.UNREACHABLE),
        (FindingStatus.GROUNDED, FindingStatus.REPRODUCED),
        (FindingStatus.GROUNDED, FindingStatus.PARKED),
        (FindingStatus.GROUNDED, FindingStatus.DUPLICATE),
        (FindingStatus.GROUNDED, FindingStatus.REFUTED),

        (FindingStatus.REACHABLE, FindingStatus.REPRODUCED),
        (FindingStatus.REACHABLE, FindingStatus.CONFIRMED),
        (FindingStatus.REACHABLE, FindingStatus.PARKED),
        (FindingStatus.REACHABLE, FindingStatus.DUPLICATE),

        (FindingStatus.REPRODUCED, FindingStatus.CONFIRMED),
        (FindingStatus.REPRODUCED, FindingStatus.PARKED),
        (FindingStatus.REPRODUCED, FindingStatus.DUPLICATE),

        # Resuming from PARKED
        (FindingStatus.PARKED, FindingStatus.REACHABLE),
        (FindingStatus.PARKED, FindingStatus.REPRODUCED),
        (FindingStatus.PARKED, FindingStatus.CONFIRMED),
        (FindingStatus.PARKED, FindingStatus.UNREACHABLE),
        (FindingStatus.PARKED, FindingStatus.REFUTED),
        (FindingStatus.PARKED, FindingStatus.DUPLICATE),
    }

    @classmethod
    def validate_transition(
        cls,
        finding: Finding,
        new_status: FindingStatus,
        new_lane: Optional[FindingLane] = None,
        is_ai_origin: bool = False,
        has_verified_witness: bool = False,
    ) -> None:
        """
        Validate whether finding can transition to new_status and new_lane.
        Raises InvalidTransitionError on any violation.
        """
        curr_status = finding.status

        # Rule 1: AI cannot promote, confirm, refute, reject, or assign final lanes
        if is_ai_origin:
            raise InvalidTransitionError(
                "AI is strictly prohibited from mutating finding status or assigning final lanes",
                current_state=curr_status.value,
                target_state=new_status.value,
            )

        # Rule 2: No-op transitions are valid
        if curr_status == new_status and (new_lane is None or finding.lane == new_lane):
            return

        # Rule 3: Check allowed status transition graph
        if (curr_status, new_status) not in cls.ALLOWED_STATUS_TRANSITIONS:
            raise InvalidTransitionError(
                f"Transition from {curr_status.value} to {new_status.value} is not permitted in pipeline progression",
                current_state=curr_status.value,
                target_state=new_status.value,
            )

        # Rule 4: CANDIDATE or GROUNDED cannot jump directly to CONFIRMED
        if curr_status in (FindingStatus.CANDIDATE, FindingStatus.GROUNDED) and new_status == FindingStatus.CONFIRMED:
            raise InvalidTransitionError(
                "Cannot jump directly to CONFIRMED without reachability analysis or verified reproduction",
                current_state=curr_status.value,
                target_state=new_status.value,
            )

        # Rule 5: GROUNDED -> REPRODUCED requires a verified witness
        if curr_status == FindingStatus.GROUNDED and new_status == FindingStatus.REPRODUCED:
            if not has_verified_witness and not finding.witness_refs:
                raise InvalidTransitionError(
                    "Transition to REPRODUCED from GROUNDED requires a verified witness trace or reproduction result",
                    current_state=curr_status.value,
                    target_state=new_status.value,
                )

        # Rule 6: MANDATORY UNKNOWN RULE (UNKNOWN != FAIL / REFUTED / UNREACHABLE)
        # An UNKNOWN-only history can NEVER transition to terminal-negative states
        if new_status in (FindingStatus.REFUTED, FindingStatus.UNREACHABLE) or new_lane in (FindingLane.REFUTED, FindingLane.UNREACHABLE):
            cls._assert_no_unknown_negative_violation(finding, new_status)

    @classmethod
    def _assert_no_unknown_negative_violation(cls, finding: Finding, target_status: FindingStatus) -> None:
        """
        Asserts that an unproven or unknown finding cannot be silently refuted or marked unreachable.
        """
        # Check reachability result
        reach = finding.reachability_result or {}
        reach_status = reach.get("result")
        is_complete = reach.get("is_model_complete", True)

        if reach_status == "UNKNOWN":
            raise InvalidTransitionError(
                "MANDATORY RULE VIOLATION: UNKNOWN reachability cannot produce a terminal-negative decision (UNKNOWN != FAIL/REFUTED/UNREACHABLE)",
                current_state=finding.status.value,
                target_state=target_status.value,
            )

        # If UNSAT but model was incomplete, it's not a sound proof
        if reach_status == "UNSAT" and not is_complete:
            raise InvalidTransitionError(
                "Cannot mark UNREACHABLE because Z3 model was incomplete or contained opaque/unmodeled logic",
                current_state=finding.status.value,
                target_state=target_status.value,
            )

        # If parked reason is UNKNOWN_REACHABILITY, OBFUSCATED_CONE, or BUDGET_LIMIT
        if finding.parked_reason in (
            FindingReason.UNKNOWN_REACHABILITY,
            FindingReason.OBFUSCATED_CONE,
            FindingReason.BUDGET_LIMIT,
            FindingReason.HARNESS_UNSUPPORTED,
        ):
            raise InvalidTransitionError(
                f"Finding parked due to '{finding.parked_reason.value}' cannot transition to terminal-negative state",
                current_state=finding.status.value,
                target_state=target_status.value,
            )
