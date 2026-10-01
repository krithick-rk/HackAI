"""
Path Condition Data Model (Stage 5).
Structured, composable representations of RTL path predicates independent of any SMT solver.
Supports AND, OR, NOT, EQ, NEQ, BIT_TEST, CONSTANT, SIGNAL_REFERENCE, and UNKNOWN.
"""

from __future__ import annotations
from enum import Enum
from typing import Dict, List, Optional, Any, Set, Union


class OpType(str, Enum):
    AND = "AND"
    OR = "OR"
    NOT = "NOT"
    EQ = "EQ"
    NEQ = "NEQ"
    BIT_TEST = "BIT_TEST"
    CONSTANT = "CONSTANT"
    SIGNAL_REF = "SIGNAL_REF"
    UNKNOWN = "UNKNOWN"


class PathCondition:
    """Base class for all path condition nodes."""
    op: OpType

    def to_dict(self) -> Dict[str, Any]:
        raise NotImplementedError

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> PathCondition:
        op_str = data.get("op", "UNKNOWN")
        try:
            op = OpType(op_str)
        except ValueError:
            op = OpType.UNKNOWN

        if op == OpType.CONSTANT:
            return ConstCondition(value=data.get("value"))
        elif op == OpType.SIGNAL_REF:
            return SignalRefCondition(
                signal_name=data.get("signal_name", ""),
                instance_path=data.get("instance_path", ""),
            )
        elif op == OpType.NOT:
            expr_data = data.get("expr", {})
            return UnaryCondition(op=OpType.NOT, expr=PathCondition.from_dict(expr_data))
        elif op in (OpType.EQ, OpType.NEQ, OpType.BIT_TEST):
            left_data = data.get("left", {})
            right_data = data.get("right", {})
            return BinaryCondition(
                op=op,
                left=PathCondition.from_dict(left_data),
                right=PathCondition.from_dict(right_data),
            )
        elif op in (OpType.AND, OpType.OR):
            terms_data = data.get("terms", [])
            terms = [PathCondition.from_dict(t) for t in terms_data]
            return CompoundCondition(op=op, terms=terms)
        else:
            return UnknownCondition(
                reason=data.get("reason", "unsupported_construct"),
                raw_text=data.get("raw_text"),
            )

    def collect_symbols(self) -> Set[str]:
        """Collect all signal names referenced in the condition."""
        raise NotImplementedError

    def has_unknown(self) -> bool:
        """Return True if any part of the condition tree is UNKNOWN / unsupported."""
        raise NotImplementedError


class ConstCondition(PathCondition):
    """Constant value (boolean, integer, or bit string)."""
    def __init__(self, value: Union[int, bool, str, None]):
        self.op = OpType.CONSTANT
        self.value = value

    def to_dict(self) -> Dict[str, Any]:
        return {
            "op": self.op.value,
            "value": self.value,
        }

    def collect_symbols(self) -> Set[str]:
        return set()

    def has_unknown(self) -> bool:
        return False

    def __repr__(self) -> str:
        return f"CONST({self.value})"


class SignalRefCondition(PathCondition):
    """Reference to a named hardware net/port/signal."""
    def __init__(self, signal_name: str, instance_path: str = ""):
        self.op = OpType.SIGNAL_REF
        self.signal_name = signal_name
        self.instance_path = instance_path

    @property
    def qualified_name(self) -> str:
        if self.instance_path:
            return f"{self.instance_path}.{self.signal_name}"
        return self.signal_name

    def to_dict(self) -> Dict[str, Any]:
        return {
            "op": self.op.value,
            "signal_name": self.signal_name,
            "instance_path": self.instance_path,
        }

    def collect_symbols(self) -> Set[str]:
        return {self.qualified_name}

    def has_unknown(self) -> bool:
        return False

    def __repr__(self) -> str:
        return f"REF({self.qualified_name})"


class UnaryCondition(PathCondition):
    """Unary operation (e.g. NOT)."""
    def __init__(self, op: OpType, expr: PathCondition):
        self.op = op
        self.expr = expr

    def to_dict(self) -> Dict[str, Any]:
        return {
            "op": self.op.value,
            "expr": self.expr.to_dict(),
        }

    def collect_symbols(self) -> Set[str]:
        return self.expr.collect_symbols()

    def has_unknown(self) -> bool:
        return self.expr.has_unknown()

    def __repr__(self) -> str:
        return f"{self.op.value}({self.expr})"


class BinaryCondition(PathCondition):
    """Binary relation (EQ, NEQ, BIT_TEST)."""
    def __init__(self, op: OpType, left: PathCondition, right: PathCondition):
        self.op = op
        self.left = left
        self.right = right

    def to_dict(self) -> Dict[str, Any]:
        return {
            "op": self.op.value,
            "left": self.left.to_dict(),
            "right": self.right.to_dict(),
        }

    def collect_symbols(self) -> Set[str]:
        return self.left.collect_symbols() | self.right.collect_symbols()

    def has_unknown(self) -> bool:
        return self.left.has_unknown() or self.right.has_unknown()

    def __repr__(self) -> str:
        return f"{self.op.value}({self.left}, {self.right})"


class CompoundCondition(PathCondition):
    """N-ary boolean operation (AND, OR)."""
    def __init__(self, op: OpType, terms: List[PathCondition]):
        self.op = op
        self.terms = terms

    def to_dict(self) -> Dict[str, Any]:
        return {
            "op": self.op.value,
            "terms": [t.to_dict() for t in self.terms],
        }

    def collect_symbols(self) -> Set[str]:
        res: Set[str] = set()
        for t in self.terms:
            res |= t.collect_symbols()
        return res

    def has_unknown(self) -> bool:
        return any(t.has_unknown() for t in self.terms)

    def __repr__(self) -> str:
        inner = ", ".join(repr(t) for t in self.terms)
        return f"{self.op.value}({inner})"


class UnknownCondition(PathCondition):
    """Represents an unsupported, opaque, or uninterpretable construct."""
    def __init__(self, reason: str, raw_text: Optional[str] = None):
        self.op = OpType.UNKNOWN
        self.reason = reason
        self.raw_text = raw_text

    def to_dict(self) -> Dict[str, Any]:
        return {
            "op": self.op.value,
            "reason": self.reason,
            "raw_text": self.raw_text,
        }

    def collect_symbols(self) -> Set[str]:
        return set()

    def has_unknown(self) -> bool:
        return True

    def __repr__(self) -> str:
        return f"UNKNOWN({self.reason})"


# --- Helper Builder Functions ---

def cond_true() -> ConstCondition:
    return ConstCondition(1)


def cond_false() -> ConstCondition:
    return ConstCondition(0)


def cond_ref(name: str, instance_path: str = "") -> SignalRefCondition:
    return SignalRefCondition(name, instance_path)


def cond_const(val: Any) -> ConstCondition:
    return ConstCondition(val)


def cond_not(expr: PathCondition) -> UnaryCondition:
    return UnaryCondition(OpType.NOT, expr)


def cond_eq(left: PathCondition, right: PathCondition) -> BinaryCondition:
    return BinaryCondition(OpType.EQ, left, right)


def cond_neq(left: PathCondition, right: PathCondition) -> BinaryCondition:
    return BinaryCondition(OpType.NEQ, left, right)


def cond_and(*terms: PathCondition) -> PathCondition:
    flat_terms: List[PathCondition] = []
    for t in terms:
        if isinstance(t, CompoundCondition) and t.op == OpType.AND:
            flat_terms.extend(t.terms)
        else:
            flat_terms.append(t)
    if not flat_terms:
        return cond_true()
    if len(flat_terms) == 1:
        return flat_terms[0]
    return CompoundCondition(OpType.AND, flat_terms)


def cond_or(*terms: PathCondition) -> PathCondition:
    flat_terms: List[PathCondition] = []
    for t in terms:
        if isinstance(t, CompoundCondition) and t.op == OpType.OR:
            flat_terms.extend(t.terms)
        else:
            flat_terms.append(t)
    if not flat_terms:
        return cond_false()
    if len(flat_terms) == 1:
        return flat_terms[0]
    return CompoundCondition(OpType.OR, flat_terms)


def cond_unknown(reason: str, raw_text: Optional[str] = None) -> UnknownCondition:
    return UnknownCondition(reason, raw_text)
