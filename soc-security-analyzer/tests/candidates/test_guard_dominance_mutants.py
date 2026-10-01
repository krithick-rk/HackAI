"""
Detector-Focused Mutation Evaluation Suite for Guard-Dominance Analysis.
Evaluates 11 mutants across 3 distinct module and design contexts:
1. sec_ctrl_block:
   - Mutant 1 (Positive): OR/disjunction bypass
   - Mutant 2 (Negative): Legitimate protected case
   - Mutant 3 (Positive): Nested guards bypass
   - Mutant 4 (Negative): Legitimate alternate update path (HW clear)
2. crypto_key_mgr:
   - Mutant 5 (Positive): Inline combinational guard bypass
   - Mutant 6 (Negative): Inline combinational guard strictly protected
   - Mutant 7 (Positive): Reordered conditions with disjunction bypass
   - Mutant 8 (Negative): Normal reset and shadow write-once protection
3. debug_auth_reg:
   - Mutant 9 (Positive): Multi-bit / compound condition bypass
   - Mutant 10 (Negative): Multi-bit compound condition strictly protected
   - Mutant 11 (Negative): Legitimate hardware status update (non-attacker RHS)

All evaluations verify that:
- Positive mutants produce REGWEN_BYPASS candidates with solver witness.
- Negative controls produce NO candidates.
- The detector functions independently of downstream AI confirmation.
"""

import os
import tempfile
import pytest

from src.soc_analyzer.design_db.builder import DesignDBBuilder
from src.soc_analyzer.candidates.detectors.lock_access_control import LockAccessControlDetector
from src.soc_analyzer.registries.schemas import AssetEntry, RegisterMetadata, ApprovalStatus


def _build_and_detect(rtl: str, top_module: str, reg_name: str, guard_ref: str, is_writable: bool = True):
    with tempfile.NamedTemporaryFile(suffix=".sv", mode="w", delete=False) as f:
        f.write(rtl)
        path = f.name

    try:
        db = DesignDBBuilder().build_from_files([path], top_module=top_module)
        # Register asset
        asset = AssetEntry(
            id=f"{top_module}.{reg_name}",
            name=f"{top_module}.{reg_name}",
            asset_type="SECURITY_CONFIG_REG",
            sensitivity="CRITICAL",
            source_path=f"{top_module}.{reg_name}",
            register_metadata=RegisterMetadata(
                reg_name=reg_name,
                swaccess="rw" if is_writable else "ro",
                guard_ref=guard_ref,
                regwen=guard_ref,
            ),
            approval_status=ApprovalStatus.APPROVED,
        )
        db.registries.assets.add(asset)

        detector = LockAccessControlDetector()
        return detector.analyze(db)
    finally:
        if os.path.exists(path):
            os.unlink(path)


# ===========================================================================
# Context 1: sec_ctrl_block
# ===========================================================================

def test_mutant_01_positive_or_disjunction_bypass():
    """Mutant 1: if (we && (regwen || bypass_en)) -> POSITIVE BYPASS"""
    rtl = """
    module sec_ctrl_block (
        input logic clk_i,
        input logic rst_ni,
        input logic we,
        input logic regwen,
        input logic bypass_en,
        input logic [31:0] wdata,
        output logic [31:0] cfg_reg
    );
        always_ff @(posedge clk_i or negedge rst_ni) begin
            if (!rst_ni) cfg_reg <= 32'h0;
            else if (we && (regwen || bypass_en)) cfg_reg <= wdata;
        end
    endmodule
    """
    cands = _build_and_detect(rtl, "sec_ctrl_block", "cfg_reg", "regwen")
    assert len(cands) == 1
    assert cands[0].weakness_class == "REGWEN_BYPASS"
    assert cands[0].metadata["witness"]["regwen"] == "False"
    assert cands[0].metadata["witness"]["bypass_en"] == "True"


def test_mutant_02_negative_strictly_protected():
    """Mutant 2: if (we && regwen) -> NEGATIVE CONTROL (Safe)"""
    rtl = """
    module sec_ctrl_block (
        input logic clk_i,
        input logic rst_ni,
        input logic we,
        input logic regwen,
        input logic [31:0] wdata,
        output logic [31:0] cfg_reg
    );
        always_ff @(posedge clk_i or negedge rst_ni) begin
            if (!rst_ni) cfg_reg <= 32'h0;
            else if (we && regwen) cfg_reg <= wdata;
        end
    endmodule
    """
    cands = _build_and_detect(rtl, "sec_ctrl_block", "cfg_reg", "regwen")
    assert len(cands) == 0


def test_mutant_03_positive_nested_guards():
    """Mutant 3: if (we) begin if (regwen || force_debug) -> POSITIVE BYPASS"""
    rtl = """
    module sec_ctrl_block (
        input logic clk_i,
        input logic rst_ni,
        input logic we,
        input logic regwen,
        input logic force_debug,
        input logic [31:0] wdata,
        output logic [31:0] cfg_reg
    );
        always_ff @(posedge clk_i or negedge rst_ni) begin
            if (!rst_ni) begin
                cfg_reg <= 32'h0;
            end else if (we) begin
                if (regwen || force_debug) begin
                    cfg_reg <= wdata;
                end
            end
        end
    endmodule
    """
    cands = _build_and_detect(rtl, "sec_ctrl_block", "cfg_reg", "regwen")
    assert len(cands) == 1
    assert cands[0].weakness_class == "REGWEN_BYPASS"
    assert cands[0].metadata["witness"]["force_debug"] == "True"


def test_mutant_04_negative_alternate_hw_clear():
    """Mutant 4: else if (err_clear) cfg_reg <= 32'h0 -> NEGATIVE CONTROL (HW Clear)"""
    rtl = """
    module sec_ctrl_block (
        input logic clk_i,
        input logic rst_ni,
        input logic we,
        input logic regwen,
        input logic err_clear,
        input logic [31:0] wdata,
        output logic [31:0] cfg_reg
    );
        always_ff @(posedge clk_i or negedge rst_ni) begin
            if (!rst_ni) cfg_reg <= 32'h0;
            else if (we && regwen) cfg_reg <= wdata;
            else if (err_clear) cfg_reg <= 32'h0;
        end
    endmodule
    """
    cands = _build_and_detect(rtl, "sec_ctrl_block", "cfg_reg", "regwen")
    assert len(cands) == 0


# ===========================================================================
# Context 2: crypto_key_mgr
# ===========================================================================

def test_mutant_05_positive_inline_combinational_guard_bypass():
    """Mutant 5: assign effective_lock = regwen || test_override -> POSITIVE BYPASS"""
    rtl = """
    module crypto_key_mgr (
        input logic clk_i,
        input logic rst_ni,
        input logic we,
        input logic regwen,
        input logic test_override,
        input logic [31:0] wdata,
        output logic [31:0] key_reg
    );
        wire effective_lock;
        assign effective_lock = regwen || test_override;

        always_ff @(posedge clk_i or negedge rst_ni) begin
            if (!rst_ni) key_reg <= 32'h0;
            else if (we && effective_lock) key_reg <= wdata;
        end
    endmodule
    """
    cands = _build_and_detect(rtl, "crypto_key_mgr", "key_reg", "regwen")
    assert len(cands) == 1
    assert cands[0].weakness_class == "REGWEN_BYPASS"


def test_mutant_06_negative_inline_combinational_guard_safe():
    """Mutant 6: assign effective_lock = regwen && !test_mode -> NEGATIVE CONTROL (Safe)"""
    rtl = """
    module crypto_key_mgr (
        input logic clk_i,
        input logic rst_ni,
        input logic we,
        input logic regwen,
        input logic test_mode,
        input logic [31:0] wdata,
        output logic [31:0] key_reg
    );
        wire effective_lock;
        assign effective_lock = regwen && (!test_mode);

        always_ff @(posedge clk_i or negedge rst_ni) begin
            if (!rst_ni) key_reg <= 32'h0;
            else if (we && effective_lock) key_reg <= wdata;
        end
    endmodule
    """
    cands = _build_and_detect(rtl, "crypto_key_mgr", "key_reg", "regwen")
    assert len(cands) == 0


def test_mutant_07_positive_reordered_conditions_bypass():
    """Mutant 7: if ((unauth_write || regwen) && we) -> POSITIVE BYPASS"""
    rtl = """
    module crypto_key_mgr (
        input logic clk_i,
        input logic rst_ni,
        input logic we,
        input logic regwen,
        input logic unauth_write,
        input logic [31:0] wdata,
        output logic [31:0] key_reg
    );
        always_ff @(posedge clk_i or negedge rst_ni) begin
            if (!rst_ni) key_reg <= 32'h0;
            else if ((unauth_write || regwen) && we) key_reg <= wdata;
        end
    endmodule
    """
    cands = _build_and_detect(rtl, "crypto_key_mgr", "key_reg", "regwen")
    assert len(cands) == 1
    assert cands[0].weakness_class == "REGWEN_BYPASS"


def test_mutant_08_negative_shadow_write_once_protected():
    """Mutant 8: if (we && regwen && !locked) -> NEGATIVE CONTROL (Safe compound)"""
    rtl = """
    module crypto_key_mgr (
        input logic clk_i,
        input logic rst_ni,
        input logic we,
        input logic regwen,
        input logic locked,
        input logic [31:0] wdata,
        output logic [31:0] key_reg
    );
        always_ff @(posedge clk_i or negedge rst_ni) begin
            if (!rst_ni) key_reg <= 32'h0;
            else if (we && regwen && (!locked)) key_reg <= wdata;
        end
    endmodule
    """
    cands = _build_and_detect(rtl, "crypto_key_mgr", "key_reg", "regwen")
    assert len(cands) == 0


# ===========================================================================
# Context 3: debug_auth_reg
# ===========================================================================

def test_mutant_09_positive_compound_condition_bypass():
    """Mutant 9: if (we && (auth_lock || allow_all)) -> POSITIVE BYPASS"""
    rtl = """
    module debug_auth_reg (
        input logic clk_i,
        input logic rst_ni,
        input logic we,
        input logic auth_lock,
        input logic allow_all,
        input logic [31:0] wdata,
        output logic [31:0] auth_reg
    );
        always_ff @(posedge clk_i or negedge rst_ni) begin
            if (!rst_ni) auth_reg <= 32'h0;
            else if (we && (auth_lock || allow_all)) auth_reg <= wdata;
        end
    endmodule
    """
    cands = _build_and_detect(rtl, "debug_auth_reg", "auth_reg", "auth_lock")
    assert len(cands) == 1
    assert cands[0].weakness_class == "REGWEN_BYPASS"


def test_mutant_10_negative_compound_condition_protected():
    """Mutant 10: if (we && auth_lock && sys_ready) -> NEGATIVE CONTROL (Safe)"""
    rtl = """
    module debug_auth_reg (
        input logic clk_i,
        input logic rst_ni,
        input logic we,
        input logic auth_lock,
        input logic sys_ready,
        input logic [31:0] wdata,
        output logic [31:0] auth_reg
    );
        always_ff @(posedge clk_i or negedge rst_ni) begin
            if (!rst_ni) auth_reg <= 32'h0;
            else if (we && auth_lock && sys_ready) auth_reg <= wdata;
        end
    endmodule
    """
    cands = _build_and_detect(rtl, "debug_auth_reg", "auth_reg", "auth_lock")
    assert len(cands) == 0


def test_mutant_11_negative_hw_status_non_attacker_rhs():
    """Mutant 11: if (hw_status_valid) auth_reg <= hw_status_bus -> NEGATIVE CONTROL (HW status)"""
    rtl = """
    module debug_auth_reg (
        input logic clk_i,
        input logic rst_ni,
        input logic auth_lock,
        input logic hw_status_valid,
        input logic [31:0] hw_status_bus,
        output logic [31:0] auth_reg
    );
        always_ff @(posedge clk_i or negedge rst_ni) begin
            if (!rst_ni) auth_reg <= 32'h0;
            else if (hw_status_valid) auth_reg <= hw_status_bus;
        end
    endmodule
    """
    # Registered with read-only swaccess
    cands = _build_and_detect(rtl, "debug_auth_reg", "auth_reg", "auth_lock", is_writable=False)
    assert len(cands) == 0
