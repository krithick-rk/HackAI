"""
Deterministic Stimulus Representation and Legality Validator (Stage 7).
Validates stimulus operations against attacker capabilities, cycles, and signal boundaries.
Strictly rejects internal signal force/deposit and privilege escalations.
"""

from __future__ import annotations
from typing import Dict, List, Optional, Any, Set, Tuple

from src.soc_analyzer.registries.schemas import AttackerEntry
from .schemas import Scenario, StimulusOp, StimulusOpType


class StimulusLegalityValidator:
    """
    Validates stimulus sequences prior to harness compilation and execution.
    """

    ALLOWED_OPERATIONS = {
        StimulusOpType.RESET,
        StimulusOpType.IDLE,
        StimulusOpType.READ,
        StimulusOpType.WRITE,
        StimulusOpType.SET_ENVIRONMENT,
    }

    FORBIDDEN_KEYWORDS = {
        "force",
        "deposit",
        "release",
        "override_net",
        "inject_signal",
        "set_internal",
    }

    @classmethod
    def validate_scenario(
        cls,
        scenario: Scenario,
        attacker: Optional[AttackerEntry] = None,
        internal_signals: Optional[Set[str]] = None,
    ) -> Tuple[bool, List[str]]:
        """
        Validate legality of a scenario and its stimulus sequence.
        Returns:
            (is_legal, violation_reasons)
        """
        violations: List[str] = []
        internals = internal_signals or set()
        prev_cycle = -1

        for i, op in enumerate(scenario.stimulus_sequence):
            # 1. Operation type legality
            if op.operation not in cls.ALLOWED_OPERATIONS:
                violations.append(f"step_{i}: unsupported_operation:{op.operation}")
                continue

            # 2. Cycle monotonicity check
            if op.cycle < 0:
                violations.append(f"step_{i}: negative_cycle:{op.cycle}")
            elif op.cycle < prev_cycle:
                violations.append(f"step_{i}: non_monotonic_cycle:{op.cycle} < {prev_cycle}")
            prev_cycle = op.cycle

            # 3. Check for forbidden force / deposit / internal manipulations
            for k, v in op.arguments.items():
                k_lower = str(k).lower()
                v_lower = str(v).lower()
                if any(kw in k_lower or kw in v_lower for kw in cls.FORBIDDEN_KEYWORDS):
                    violations.append(f"step_{i}: force_deposit_prohibited in arg '{k}'")

                # 4. Check for direct writes to internal signals
                if k in internals or any(k.endswith(f".{sig}") for sig in internals):
                    violations.append(f"step_{i}: internal_write_rejected to '{k}'")

            # 5. Attacker capability enforcement
            if attacker:
                cls._validate_attacker_privileges(op, attacker, i, violations)

            # 6. Operation argument constraints
            if op.operation in (StimulusOpType.READ, StimulusOpType.WRITE):
                if "addr" not in op.arguments:
                    violations.append(f"step_{i}: missing_address_for_bus_operation")
                else:
                    try:
                        addr = int(op.arguments["addr"])
                        if addr < 0:
                            violations.append(f"step_{i}: negative_address:{addr}")
                    except (ValueError, TypeError):
                        violations.append(f"step_{i}: invalid_address_format")

            if op.operation == StimulusOpType.WRITE:
                if "data" not in op.arguments:
                    violations.append(f"step_{i}: missing_data_for_write")

        return len(violations) == 0, violations

    @classmethod
    def _validate_attacker_privileges(
        cls,
        op: StimulusOp,
        attacker: AttackerEntry,
        step_idx: int,
        violations: List[str],
    ) -> None:
        priv_level = (attacker.privilege_level or "").upper()
        req_priv = str(op.arguments.get("priv_level", "UNPRIVILEGED")).upper()

        # Unprivileged attacker cannot assert privileged transactions
        if priv_level in ("UNPRIVILEGED", "SW_UNPRIV"):
            if req_priv in ("PRIVILEGED", "SUPERVISOR", "ROOT", "DEBUG"):
                violations.append(
                    f"step_{step_idx}: privilege_escalation_rejected: unprivileged attacker requested {req_priv}"
                )

        # Check debug authorization
        if op.arguments.get("debug_auth") or op.arguments.get("debug_enable"):
            b_type = (attacker.boundary.boundary_type or "").upper()
            if b_type not in ("DEBUG", "JTAG"):
                violations.append(
                    f"step_{step_idx}: unauthorized_debug_access_rejected for attacker boundary {b_type}"
                )

        # Check bus write capability
        if op.operation == StimulusOpType.WRITE:
            caps = [c.lower() for c in attacker.capabilities]
            stim = [s.lower() for s in attacker.allowed_stimulus]
            if not any("write" in c for c in caps) and not any("write" in s for s in stim):
                violations.append(
                    f"step_{step_idx}: attacker_capability_violation: attacker has no write permissions"
                )
