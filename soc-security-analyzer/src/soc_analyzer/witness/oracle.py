"""
Oracle Engine and Sanity Control (Stage 7).
Evaluates independent hardware verification oracles (register values, assertions, traces).
Implements mandatory oracle sanity control to reject invalid oracles that trigger on benign runs.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Callable

from .schemas import OracleType, OracleStatus, OracleResult


@dataclass
class OracleSpec:
    """Independent specification of an oracle check."""
    oracle_id: str
    oracle_type: OracleType
    property_name: str
    target_signal: str
    expected_value: Optional[Any] = None
    expected_violation: bool = True  # True if the security witness expects violation
    description: str = ""


class OracleEngine:
    """
    Evaluates simulation and formal results against independent oracles.
    Includes sanity verification on benign/golden stimulus.
    """

    @classmethod
    def evaluate(
        cls,
        spec: OracleSpec,
        observed_signals: Dict[str, Any],
        finding_context: Optional[Dict[str, Any]] = None,
    ) -> OracleResult:
        """
        Evaluate observed signals against OracleSpec.
        """
        target = spec.target_signal
        val = observed_signals.get(target)

        # Signal alias lookup
        if val is None:
            for k, v in observed_signals.items():
                if k.endswith(f".{target}") or k.endswith(f":{target}") or target in k:
                    val = v
                    break

        if val is None and spec.oracle_type == OracleType.REGISTER_VALUE:
            return OracleResult(
                oracle_id=spec.oracle_id,
                oracle_type=spec.oracle_type,
                status=OracleStatus.FAILED,
                property_name=spec.property_name,
                details=f"signal_not_observed:{target}",
                sanity_passed=True,
            )

        if spec.oracle_type == OracleType.REGISTER_VALUE:
            # Check if observed value matches expected
            matches = (str(val) == str(spec.expected_value) or
                       int(val) == int(spec.expected_value) if isinstance(val, (int, str)) and isinstance(spec.expected_value, (int, str)) else False)
            status = OracleStatus.PASSED if matches else OracleStatus.FAILED
            details = f"observed {target}={val}, expected {spec.expected_value}"
            return OracleResult(
                oracle_id=spec.oracle_id,
                oracle_type=spec.oracle_type,
                status=status,
                property_name=spec.property_name,
                details=details,
                sanity_passed=True,
            )

        elif spec.oracle_type == OracleType.ASSERTION:
            # Check for assertion failures in output
            has_assert_fail = bool(observed_signals.get("assertion_failed", False))
            status = OracleStatus.PASSED if has_assert_fail else OracleStatus.FAILED
            return OracleResult(
                oracle_id=spec.oracle_id,
                oracle_type=spec.oracle_type,
                status=status,
                property_name=spec.property_name,
                details=f"assertion_failure_triggered={has_assert_fail}",
                sanity_passed=True,
            )

        # Default trace condition
        status = OracleStatus.PASSED if val is not None else OracleStatus.FAILED
        return OracleResult(
            oracle_id=spec.oracle_id,
            oracle_type=spec.oracle_type,
            status=status,
            property_name=spec.property_name,
            details=f"trace condition for {target}",
            sanity_passed=True,
        )

    @classmethod
    def run_sanity_check(
        cls,
        spec: OracleSpec,
        benign_signals: Dict[str, Any],
        finding_context: Optional[Dict[str, Any]] = None,
    ) -> Tuple[bool, OracleResult]:
        """
        Oracle Sanity Control (Section 15):
        Runs a known-good benign scenario. The security violation oracle must NOT trigger.
        If it triggers on benign inputs, the oracle is invalid (ORACLE_INVALID).
        Returns:
            (is_sane: bool, result: OracleResult)
        """
        benign_res = cls.evaluate(spec, benign_signals, finding_context)

        # If oracle passed (meaning security violation condition matched) on benign input,
        # the oracle is buggy and invalid!
        if benign_res.status == OracleStatus.PASSED and spec.expected_violation:
            invalid_result = OracleResult(
                oracle_id=spec.oracle_id,
                oracle_type=spec.oracle_type,
                status=OracleStatus.ORACLE_INVALID,
                property_name=spec.property_name,
                details=f"sanity_check_failed: oracle triggered on benign known-good stimulus: {benign_res.details}",
                sanity_passed=False,
            )
            return False, invalid_result

        benign_res.sanity_passed = True
        return True, benign_res
