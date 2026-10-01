"""
Deterministic Hardware RTL Obfuscation Engine (Stage 8).
Generates functionality-preserving obfuscated design variants through identifier scrambling,
signal renaming, and comment stripping to test analyzer recall under semantic degradation.
"""

from __future__ import annotations
import re
import hashlib
from typing import Dict, List, Tuple, Set


SV_KEYWORDS: Set[str] = {
    "module", "endmodule", "input", "output", "inout", "logic", "wire", "reg",
    "always", "always_ff", "always_comb", "always_latch", "initial", "begin", "end",
    "if", "else", "case", "endcase", "default", "assign", "posedge", "negedge",
    "parameter", "localparam", "import", "package", "endpackage", "timescale",
    "generate", "endgenerate", "genvar", "for", "while", "return", "function",
    "endfunction", "task", "endtask", "typedef", "struct", "enum", "union",
    "assert", "property", "endproperty", "disable", "iff", "1'b0", "1'b1", "1", "0"
}


class DeterministicObfuscator:
    """
    Applies deterministic, semantics-preserving obfuscations to Verilog/SystemVerilog RTL.
    """

    @classmethod
    def strip_comments(cls, rtl_code: str) -> str:
        """Strip single-line and multi-line comments while preserving lines."""
        # Multi-line comments /* ... */
        no_multiline = re.sub(r"/\*.*?\*/", "", rtl_code, flags=re.DOTALL)
        # Single-line comments // ...
        lines = []
        for line in no_multiline.splitlines():
            line_no_cmt = re.sub(r"//.*$", "", line)
            lines.append(line_no_cmt)
        return "\n".join(lines)

    @classmethod
    def scramble_identifiers(
        cls,
        rtl_code: str,
        preserve_names: Optional[Set[str]] = None,
        prefix: str = "_obf_",
    ) -> Tuple[str, Dict[str, str]]:
        """
        Scramble user-defined signals and register names while preserving Verilog syntax and keywords.
        """
        preserved = preserve_names or set()
        # Find all identifier tokens: [a-zA-Z_][a-zA-Z0-9_]*
        tokens = re.findall(r"\b[a-zA-Z_][a-zA-Z0-9_]*\b", rtl_code)
        ident_map: Dict[str, str] = {}
        idx = 0

        for tok in tokens:
            if tok in SV_KEYWORDS or tok in preserved:
                continue
            if tok not in ident_map:
                # Deterministic hashed identifier
                h = hashlib.md5(f"{tok}_{idx}".encode("utf-8")).hexdigest()[:6]
                ident_map[tok] = f"{prefix}{tok[:3]}_{h}"
                idx += 1

        # Replace identifiers using word boundaries
        def repl(match: re.Match) -> str:
            word = match.group(0)
            return ident_map.get(word, word)

        obfuscated_code = re.sub(r"\b[a-zA-Z_][a-zA-Z0-9_]*\b", repl, rtl_code)
        return obfuscated_code, ident_map

    @classmethod
    def obfuscate_rtl(
        cls,
        rtl_code: str,
        preserve_names: Optional[Set[str]] = None,
        strip_cmts: bool = True,
        scramble_idents: bool = True,
    ) -> Tuple[str, Dict[str, str]]:
        """
        Produce a full obfuscated variant.
        """
        code = rtl_code
        if strip_cmts:
            code = cls.strip_comments(code)

        ident_map: Dict[str, str] = {}
        if scramble_idents:
            code, ident_map = cls.scramble_identifiers(code, preserve_names=preserve_names)

        return code, ident_map
