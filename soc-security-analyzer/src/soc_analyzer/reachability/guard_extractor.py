"""
RTL Guard Extractor (Stage 5).
Deterministically parses and extracts path guards from Verilog/SystemVerilog expressions,
conditional statements, muxes, case items, and AST/netlist facts.
Strictly returns UnknownCondition when an uninterpretable or unsupported construct is encountered.
"""

from __future__ import annotations
import re
from typing import List, Dict, Any, Optional, Tuple

from .path_condition import (
    PathCondition,
    ConstCondition,
    SignalRefCondition,
    UnaryCondition,
    BinaryCondition,
    CompoundCondition,
    UnknownCondition,
    OpType,
    cond_true,
    cond_false,
    cond_ref,
    cond_const,
    cond_not,
    cond_eq,
    cond_neq,
    cond_and,
    cond_or,
    cond_unknown,
)


def normalize_verilog_const(val_str: str) -> Optional[int]:
    """Parse Verilog constant numbers (e.g. 1'b0, 1'b1, 32'h10, 0x10, 42)."""
    val_str = val_str.strip().lower()
    if val_str in ("true", "1'b1", "1"):
        return 1
    if val_str in ("false", "1'b0", "0"):
        return 0
    if val_str in ("'0", "1'0"):
        return 0
    if val_str in ("'1", "1'1"):
        return 1

    # Match Verilog sized constants e.g. 32'hdeadbeef, 8'd10, 4'b1010
    m = re.match(r"^(\d+)'([bhdBHD])([0-9a-fA-F_]+)$", val_str)
    if m:
        base_char = m.group(2).lower()
        num_str = m.group(3).replace("_", "")
        base = 2 if base_char == "b" else (16 if base_char == "h" else 10)
        try:
            return int(num_str, base)
        except ValueError:
            return None

    # Hex or decimal
    try:
        return int(val_str, 0)
    except ValueError:
        return None


class GuardTokenizer:
    """Simple tokenizer for Verilog condition expressions."""
    TOKEN_RE = re.compile(
        r"\s*("
        r"&&|\|\||==|!=|===|!==|<=|>=|<|>|"
        r"!|~|\(|\)|\?|:|"
        r"\d+'[bhdBHD][0-9a-fA-F_]+|"
        r"0x[0-9a-fA-F]+|\d+|"
        r"[a-zA-Z_][a-zA-Z0-9_$.]*"
        r")"
    )

    @classmethod
    def tokenize(cls, expr: str) -> List[str]:
        tokens = []
        pos = 0
        while pos < len(expr):
            match = cls.TOKEN_RE.match(expr, pos)
            if not match:
                remaining = expr[pos:].strip()
                if remaining:
                    tokens.append(remaining)
                break
            tok = match.group(1)
            tokens.append(tok)
            pos = match.end()
        return tokens


class GuardParser:
    """
    Deterministic recursive-descent parser for RTL path conditions.
    Precedence:
      1. Primary: (expr), CONST, IDENTIFIER, !expr
      2. Comparison: ==, !=, ===, !==
      3. Logical AND: &&
      4. Logical OR: ||
      5. Ternary / Mux: cond ? if_true : if_false
    """
    def __init__(self, tokens: List[str], instance_path: str = ""):
        self.tokens = tokens
        self.pos = 0
        self.instance_path = instance_path

    def current(self) -> Optional[str]:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def advance(self) -> str:
        tok = self.tokens[self.pos]
        self.pos += 1
        return tok

    def parse(self) -> PathCondition:
        if not self.tokens:
            return cond_true()
        try:
            res = self.parse_or()
            if self.pos < len(self.tokens):
                # Extra unconsumed tokens
                remaining = " ".join(self.tokens[self.pos:])
                return cond_unknown(f"unconsumed_tokens: {remaining}")
            return res
        except Exception as e:
            return cond_unknown(f"parse_error: {str(e)}")

    def parse_or(self) -> PathCondition:
        left = self.parse_and()
        terms = [left]
        while self.current() == "||":
            self.advance()
            terms.append(self.parse_and())
        return cond_or(*terms) if len(terms) > 1 else left

    def parse_and(self) -> PathCondition:
        left = self.parse_comp()
        terms = [left]
        while self.current() == "&&":
            self.advance()
            terms.append(self.parse_comp())
        return cond_and(*terms) if len(terms) > 1 else left

    def parse_comp(self) -> PathCondition:
        left = self.parse_unary()
        curr = self.current()
        if curr in ("==", "===", "!=", "!=="):
            op = self.advance()
            right = self.parse_unary()
            if op in ("==", "==="):
                return cond_eq(left, right)
            else:
                return cond_neq(left, right)
        return left

    def parse_unary(self) -> PathCondition:
        curr = self.current()
        if curr in ("!", "~"):
            self.advance()
            expr = self.parse_unary()
            return cond_not(expr)
        return self.parse_primary()

    def parse_primary(self) -> PathCondition:
        curr = self.current()
        if not curr:
            return cond_unknown("unexpected_eof")

        if curr == "(":
            self.advance()
            expr = self.parse_or()
            if self.current() == ")":
                self.advance()
                return expr
            return cond_unknown("missing_closing_paren")

        # Check for constant number
        const_val = normalize_verilog_const(curr)
        if const_val is not None:
            self.advance()
            return cond_const(const_val)

        # Identifier
        if re.match(r"^[a-zA-Z_][a-zA-Z0-9_$.]*$", curr):
            self.advance()
            # If followed by ? : (ternary)
            return cond_ref(curr, self.instance_path)

        # Unrecognized symbol
        tok = self.advance()
        return cond_unknown(f"unsupported_token: {tok}")


def parse_guard_expression(expr_str: str, instance_path: str = "") -> PathCondition:
    """
    Deterministically parse an RTL expression string into a structured PathCondition.
    Returns UnknownCondition if the construct cannot be faithfully interpreted.
    """
    clean_str = expr_str.strip()
    if not clean_str or clean_str in ("1", "1'b1", "true"):
        return cond_true()
    if clean_str in ("0", "1'b0", "false"):
        return cond_false()

    tokens = GuardTokenizer.tokenize(clean_str)
    if not tokens:
        return cond_unknown("empty_tokens", clean_str)

    # Check for unsupported Verilog operators (e.g. system functions $past, complex bit-slices)
    for tok in tokens:
        if tok.startswith("$"):
            return cond_unknown(f"unsupported_system_function: {tok}", clean_str)
        if "[" in tok or "]" in tok:
            # Simple bit-select or slice may be unmodeled in standard parser
            return cond_unknown(f"unmodeled_slice: {tok}", clean_str)

    parser = GuardParser(tokens, instance_path=instance_path)
    cond = parser.parse()
    return cond


def extract_mux_guards(
    selector: str,
    if_true_sig: str,
    if_false_sig: str,
    instance_path: str = ""
) -> List[Tuple[str, PathCondition]]:
    """
    Return destination-condition pairs for a mux:
    (if_true_sig, guard=selector)
    (if_false_sig, guard=!selector)
    """
    sel_cond = parse_guard_expression(selector, instance_path)
    return [
        (if_true_sig, sel_cond),
        (if_false_sig, cond_not(sel_cond)),
    ]


def extract_case_guard(
    case_var: str,
    item_val: str,
    instance_path: str = ""
) -> PathCondition:
    """
    Extract guard for a case item: e.g. case (state) with item STATE_RUN -> state == STATE_RUN.
    """
    v_cond = parse_guard_expression(case_var, instance_path)
    item_val_clean = item_val.strip()
    if item_val_clean.lower() == "default":
        # Default branch handling: unknown without exhaustive enumeration
        return cond_unknown("case_default_branch_unmodeled", item_val)
    item_cond = parse_guard_expression(item_val_clean, instance_path)
    return cond_eq(v_cond, item_cond)
