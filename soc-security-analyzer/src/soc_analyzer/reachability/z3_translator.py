"""
Z3 Path Condition Translator (Stage 5).
Translates solver-independent PathCondition AST into Z3 SMT solver expressions.
Maintains symbol environment and cleanly raises CannotTranslateError for UnknownCondition.
"""

from __future__ import annotations
from typing import Dict, Any, Optional, Set, Tuple
import z3

from .path_condition import (
    PathCondition,
    ConstCondition,
    SignalRefCondition,
    UnaryCondition,
    BinaryCondition,
    CompoundCondition,
    UnknownCondition,
    OpType,
)


class CannotTranslateError(Exception):
    """Raised when a PathCondition cannot be faithfully translated to Z3 (e.g. UnknownCondition)."""
    def __init__(self, reason: str, details: Optional[str] = None):
        super().__init__(f"Cannot translate path condition to Z3: {reason} ({details or ''})")
        self.reason = reason
        self.details = details


class Z3Translator:
    """
    Translates PathCondition trees to Z3 boolean / integer expressions.
    """
    def __init__(self):
        self.symbols: Dict[str, z3.ExprRef] = {}
        self.symbol_types: Dict[str, str] = {}  # "bool" or "int"

    def get_or_create_symbol(self, name: str, prefer_type: str = "bool") -> z3.ExprRef:
        """Retrieve existing Z3 symbol or create new one with preferred type."""
        # Sanitize symbol name for Z3
        clean_name = name.replace(".", "_").replace(":", "_").replace("$", "_")
        if clean_name in self.symbols:
            return self.symbols[clean_name]

        if prefer_type == "int":
            sym = z3.Int(clean_name)
            self.symbol_types[clean_name] = "int"
        else:
            sym = z3.Bool(clean_name)
            self.symbol_types[clean_name] = "bool"

        self.symbols[clean_name] = sym
        return sym

    def translate(self, cond: PathCondition) -> z3.ExprRef:
        """
        Translate a PathCondition node into a Z3 ExprRef.
        Raises CannotTranslateError if cond contains UnknownCondition.
        """
        if isinstance(cond, UnknownCondition):
            raise CannotTranslateError(cond.reason, cond.raw_text)

        if isinstance(cond, ConstCondition):
            val = cond.value
            if val is True or val == 1 or val == "1":
                return z3.BoolVal(True)
            elif val is False or val == 0 or val == "0":
                return z3.BoolVal(False)
            elif isinstance(val, int):
                return z3.IntVal(val)
            elif isinstance(val, str):
                # Try int conversion
                try:
                    return z3.IntVal(int(val, 0))
                except ValueError:
                    # Treat string constant as symbolic integer or enum
                    return self.get_or_create_symbol(val, prefer_type="int")
            else:
                return z3.BoolVal(False)

        if isinstance(cond, SignalRefCondition):
            sym = self.get_or_create_symbol(cond.qualified_name, prefer_type="bool")
            return sym

        if isinstance(cond, UnaryCondition):
            if cond.op == OpType.NOT:
                sub_z3 = self.translate(cond.expr)
                if z3.is_bool(sub_z3):
                    return z3.Not(sub_z3)
                else:
                    return sub_z3 == 0
            raise CannotTranslateError(f"unsupported_unary_op: {cond.op}")

        if isinstance(cond, BinaryCondition):
            # Inspect operands to determine type coercion if needed
            left_z3 = self.translate(cond.left)
            right_z3 = self.translate(cond.right)

            # Normalize comparisons between Bool and 0/1 Int
            if z3.is_bool(left_z3) and z3.is_int(right_z3):
                # e.g. (x == 1) or (x == 0)
                if cond.op == OpType.EQ:
                    return left_z3 if str(right_z3) == "1" else z3.Not(left_z3)
                elif cond.op == OpType.NEQ:
                    return z3.Not(left_z3) if str(right_z3) == "1" else left_z3
            elif z3.is_int(left_z3) and z3.is_bool(right_z3):
                if cond.op == OpType.EQ:
                    return right_z3 if str(left_z3) == "1" else z3.Not(right_z3)
                elif cond.op == OpType.NEQ:
                    return z3.Not(right_z3) if str(left_z3) == "1" else right_z3

            if cond.op == OpType.EQ:
                return left_z3 == right_z3
            elif cond.op == OpType.NEQ:
                return left_z3 != right_z3
            elif cond.op == OpType.BIT_TEST:
                # Bit test: (left & (1 << right)) != 0
                if z3.is_int(left_z3) and z3.is_int(right_z3):
                    return left_z3 != 0
                return left_z3 == True
            raise CannotTranslateError(f"unsupported_binary_op: {cond.op}")

        if isinstance(cond, CompoundCondition):
            terms_z3 = [self.translate(t) for t in cond.terms]
            # Ensure terms are boolean
            bool_terms = []
            for t in terms_z3:
                if z3.is_bool(t):
                    bool_terms.append(t)
                else:
                    bool_terms.append(t != 0)

            if cond.op == OpType.AND:
                return z3.And(*bool_terms) if bool_terms else z3.BoolVal(True)
            elif cond.op == OpType.OR:
                return z3.Or(*bool_terms) if bool_terms else z3.BoolVal(False)
            raise CannotTranslateError(f"unsupported_compound_op: {cond.op}")

        raise CannotTranslateError(f"unrecognized_condition_type: {type(cond).__name__}")
