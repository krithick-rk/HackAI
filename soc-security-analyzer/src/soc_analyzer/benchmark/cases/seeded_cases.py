"""
Seeded Vulnerability, False-Positive, and Obfuscated Benchmark Corpus (Stage 8).
Contains ~24 diverse, versioned benchmark cases covering the 8 primary vulnerability classes,
known false-positives (true negatives), provably unreachable cases, and obfuscated variants.
"""

from __future__ import annotations
from typing import List, Dict

from src.soc_analyzer.findings.schemas import FindingLane
from ..schemas import BenchmarkCase, ExpectedOutcome, DifficultyLevel
from ..mutations.obfuscator import DeterministicObfuscator


def get_all_benchmark_cases() -> List[BenchmarkCase]:
    cases: List[BenchmarkCase] = []

    # =========================================================================
    # 1. ACCESS_CONTROL
    # =========================================================================
    # Case 1: TP - Missing regwen
    c1_rtl = """
    module sec_ctrl_reg (
        input logic clk_i,
        input logic rst_ni,
        input logic we,
        input logic [31:0] wdata,
        output logic [31:0] ctrl_out
    );
        // Suspicious: Security configuration register written directly without regwen lock guard
        always_ff @(posedge clk_i or negedge rst_ni) begin
            if (!rst_ni) begin
                ctrl_out <= 32'h0;
            end else if (we) begin
                ctrl_out <= wdata;
            end
        end
    endmodule
    """
    cases.append(BenchmarkCase(
        case_id="case_ac_01_missing_regwen",
        name="Missing Regwen Lock on Security Control",
        category="ACCESS_CONTROL",
        description="Write-enable path to critical control register lacks regwen lock domination",
        source_fixture=c1_rtl.strip(),
        expected_behavior=ExpectedOutcome.TRUE_POSITIVE,
        expected_finding=True,
        weakness_class="LOCK_ACCESS_CONTROL",
        expected_lane=FindingLane.PROBABLE,
        expected_instances=["sec_ctrl_reg"],
        difficulty=DifficultyLevel.BASIC,
        tags=["access_control", "regwen", "detector_channel_d"],
    ))

    # Case 2: TP - Subtle OR guard bypass
    c2_rtl = """
    module guarded_cfg (
        input logic clk_i,
        input logic rst_ni,
        input logic we,
        input logic regwen_i,
        input logic debug_override,
        input logic [31:0] wdata,
        output logic [31:0] sec_cfg
    );
        // Subtle bug: regwen protection is bypassed by debug_override or unconstrained OR
        always_ff @(posedge clk_i or negedge rst_ni) begin
            if (!rst_ni) begin
                sec_cfg <= 32'h0;
            end else if (we && (regwen_i || debug_override)) begin
                sec_cfg <= wdata;
            end
        end
    endmodule
    """
    cases.append(BenchmarkCase(
        case_id="case_ac_02_subtle_guard_bypass",
        name="Subtle Regwen Bypass via Disjunction",
        category="ACCESS_CONTROL",
        description="Regwen lock is bypassed when debug_override is asserted",
        source_fixture=c2_rtl.strip(),
        expected_behavior=ExpectedOutcome.TRUE_POSITIVE,
        expected_finding=True,
        weakness_class="LOCK_ACCESS_CONTROL",
        expected_lane=FindingLane.PROBABLE,
        expected_instances=["guarded_cfg"],
        difficulty=DifficultyLevel.INTERMEDIATE,
        tags=["access_control", "bypass"],
    ))

    # Case 3: TN - Valid Regwen (Safe False-Positive Target)
    c3_rtl = """
    module safe_regwen_cfg (
        input logic clk_i,
        input logic rst_ni,
        input logic we,
        input logic regwen,
        input logic [31:0] wdata,
        output logic [31:0] cfg_q
    );
        // Safe: Strictly dominated by regwen
        always_ff @(posedge clk_i or negedge rst_ni) begin
            if (!rst_ni) begin
                cfg_q <= 32'h0;
            end else if (we && regwen) begin
                cfg_q <= wdata;
            end
        end
    endmodule
    """
    cases.append(BenchmarkCase(
        case_id="case_ac_03_valid_regwen_safe",
        name="Legitimate Regwen Protection (Safe)",
        category="ACCESS_CONTROL",
        description="Properly guarded configuration register strictly gated by regwen",
        source_fixture=c3_rtl.strip(),
        expected_behavior=ExpectedOutcome.TRUE_NEGATIVE,
        expected_finding=False,
        weakness_class="LOCK_ACCESS_CONTROL",
        difficulty=DifficultyLevel.BASIC,
        tags=["access_control", "safe", "true_negative"],
    ))

    # Case 4: UNREACHABLE - Suspicious write path behind statically dead guard
    c4_rtl = """
    module dead_write_path (
        input logic clk_i,
        input logic rst_ni,
        input logic we,
        input logic [31:0] wdata,
        output logic [31:0] key_reg
    );
        // Path to key_reg write has an unsatisfiable condition 1'b0
        always_ff @(posedge clk_i or negedge rst_ni) begin
            if (!rst_ni) begin
                key_reg <= 32'h0;
            end else if (we && 1'b0) begin
                key_reg <= wdata;
            end
        end
    endmodule
    """
    cases.append(BenchmarkCase(
        case_id="case_ac_04_unreachable_write",
        name="Dead Security Write Path (Unreachable)",
        category="ACCESS_CONTROL",
        description="Suspicious write assignment is provably dead and unreachable via sound UNSAT",
        source_fixture=c4_rtl.strip(),
        expected_behavior=ExpectedOutcome.UNREACHABLE,
        expected_finding=True,
        weakness_class="LOCK_ACCESS_CONTROL",
        expected_lane=FindingLane.UNREACHABLE,
        difficulty=DifficultyLevel.INTERMEDIATE,
        tags=["access_control", "unreachable", "formal_unsat"],
    ))

    # =========================================================================
    # 2. RESET ISSUES
    # =========================================================================
    # Case 5: TP - Unreset security register
    c5_rtl = """
    module unreset_key_storage (
        input logic clk_i,
        input logic rst_ni,
        input logic load_key,
        input logic [255:0] key_in,
        output logic [255:0] key_out
    );
        // Bug: key_out register is never cleared on reset
        always_ff @(posedge clk_i) begin
            if (load_key) begin
                key_out <= key_in;
            end
        end
    endmodule
    """
    cases.append(BenchmarkCase(
        case_id="case_rst_01_unreset_security_reg",
        name="Unreset Security Key Register",
        category="RESET",
        description="Key storage register retains state across chip reset cycles",
        source_fixture=c5_rtl.strip(),
        expected_behavior=ExpectedOutcome.TRUE_POSITIVE,
        expected_finding=True,
        weakness_class="RESET_ISSUE",
        expected_lane=FindingLane.PROBABLE,
        difficulty=DifficultyLevel.BASIC,
        tags=["reset", "unreset_state"],
    ))

    # Case 6: TP - Reset polarity inconsistency across siblings
    c6_rtl = """
    module mixed_polarity_regs (
        input logic clk_i,
        input logic rst_ni,
        input logic rst_i,
        input logic we,
        output logic sec_a,
        output logic sec_b
    );
        // Sibling register A uses active-low rst_ni
        always_ff @(posedge clk_i or negedge rst_ni) begin
            if (!rst_ni) sec_a <= 1'b0;
            else if (we) sec_a <= 1'b1;
        end
        // Sibling register B uses active-high rst_i
        always_ff @(posedge clk_i or posedge rst_i) begin
            if (rst_i) sec_b <= 1'b0;
            else if (we) sec_b <= 1'b1;
        end
    endmodule
    """
    cases.append(BenchmarkCase(
        case_id="case_rst_02_polarity_inconsistency",
        name="Reset Polarity Mismatch Across Siblings",
        category="RESET",
        description="Peer security controls use conflicting reset polarities",
        source_fixture=c6_rtl.strip(),
        expected_behavior=ExpectedOutcome.TRUE_POSITIVE,
        expected_finding=True,
        weakness_class="RESET_ISSUE",
        difficulty=DifficultyLevel.INTERMEDIATE,
        tags=["reset", "polarity_mismatch"],
    ))

    # Case 7: TN - Safe Verified Reset
    c7_rtl = """
    module safe_reset_ctrl (
        input logic clk_i,
        input logic rst_ni,
        input logic we,
        input logic d,
        output logic q
    );
        // Safe: Synchronous or async reset to 0
        always_ff @(posedge clk_i or negedge rst_ni) begin
            if (!rst_ni) q <= 1'b0;
            else if (we) q <= d;
        end
    endmodule
    """
    cases.append(BenchmarkCase(
        case_id="case_rst_03_safe_reset_defaults",
        name="Safe Clean Reset Implementation",
        category="RESET",
        description="All sequential registers are cleanly zeroed on reset assertion",
        source_fixture=c7_rtl.strip(),
        expected_behavior=ExpectedOutcome.TRUE_NEGATIVE,
        expected_finding=False,
        weakness_class="RESET_ISSUE",
        difficulty=DifficultyLevel.BASIC,
        tags=["reset", "safe", "true_negative"],
    ))

    # =========================================================================
    # 3. FSM STRUCTURAL ISSUES
    # =========================================================================
    # Case 8: TP - Missing default in security FSM
    c8_rtl = """
    module sec_fsm (
        input logic clk_i,
        input logic rst_ni,
        input logic [1:0] cmd,
        output logic auth_ok
    );
        typedef enum logic [1:0] { IDLE=2'b00, AUTH=2'b01, RUN=2'b10 } state_e;
        state_e state;
        always_comb begin
            case (state)
                IDLE: auth_ok = 1'b0;
                AUTH: auth_ok = (cmd == 2'b11);
                RUN:  auth_ok = 1'b1;
                // Bug: Missing default handler for 2'b11!
            endcase
        end
    endmodule
    """
    cases.append(BenchmarkCase(
        case_id="case_fsm_01_missing_default_state",
        name="Missing FSM Default State Handler",
        category="FSM",
        description="Security FSM omits default recovery branch for unencoded state values",
        source_fixture=c8_rtl.strip(),
        expected_behavior=ExpectedOutcome.TRUE_POSITIVE,
        expected_finding=True,
        weakness_class="FSM_STRUCTURAL",
        difficulty=DifficultyLevel.BASIC,
        tags=["fsm", "missing_default"],
    ))

    # Case 9: TN - Safe FSM with explicit default recovery
    c9_rtl = """
    module safe_sec_fsm (
        input logic clk_i,
        input logic rst_ni,
        output logic ok
    );
        typedef enum logic [1:0] { S0=2'b00, S1=2'b01 } state_e;
        state_e state;
        always_comb begin
            case (state)
                S0: ok = 1'b0;
                S1: ok = 1'b1;
                default: ok = 1'b0; // Safe default error recovery
            endcase
        end
    endmodule
    """
    cases.append(BenchmarkCase(
        case_id="case_fsm_03_legal_fsm_with_default",
        name="Safe FSM with Error Recovery Default",
        category="FSM",
        description="FSM safely returns to inert state on undefined encodings",
        source_fixture=c9_rtl.strip(),
        expected_behavior=ExpectedOutcome.TRUE_NEGATIVE,
        expected_finding=False,
        weakness_class="FSM_STRUCTURAL",
        difficulty=DifficultyLevel.BASIC,
        tags=["fsm", "safe", "true_negative"],
    ))

    # =========================================================================
    # 4. DEBUG_TEST_GATING
    # =========================================================================
    # Case 10: TP - Ungated debug port directly driving register write
    c10_rtl = """
    module ungated_debug_master (
        input logic clk_i,
        input logic rst_ni,
        input logic debug_force_we,
        input logic [31:0] debug_data,
        output logic [31:0] key_data
    );
        // Bug: debug_force_we directly writes key without lifecycle authorization
        always_ff @(posedge clk_i or negedge rst_ni) begin
            if (!rst_ni) key_data <= 32'h0;
            else if (debug_force_we) key_data <= debug_data;
        end
    endmodule
    """
    cases.append(BenchmarkCase(
        case_id="case_dbg_01_ungated_debug_bus",
        name="Ungated Debug Override on Security Register",
        category="DEBUG_TEST_GATING",
        description="Debug force input allows direct unauthenticated write to key storage",
        source_fixture=c10_rtl.strip(),
        expected_behavior=ExpectedOutcome.TRUE_POSITIVE,
        expected_finding=True,
        weakness_class="DEBUG_GATING",
        expected_lane=FindingLane.PROBABLE,
        difficulty=DifficultyLevel.BASIC,
        tags=["debug", "ungated_port"],
    ))

    # Case 11: TN - Properly lifecycle-gated debug
    c11_rtl = """
    module gated_debug_ctrl (
        input logic clk_i,
        input logic rst_ni,
        input logic debug_req,
        input logic lc_debug_en,
        output logic dbg_active
    );
        // Safe: Debug port strictly qualified with lifecycle debug enable token
        assign dbg_active = debug_req && lc_debug_en;
    endmodule
    """
    cases.append(BenchmarkCase(
        case_id="case_dbg_02_properly_lifecycle_gated",
        name="Properly Lifecycle-Gated Debug Port",
        category="DEBUG_TEST_GATING",
        description="Debug activation requires authorized hardware lifecycle enablement",
        source_fixture=c11_rtl.strip(),
        expected_behavior=ExpectedOutcome.TRUE_NEGATIVE,
        expected_finding=False,
        weakness_class="DEBUG_GATING",
        difficulty=DifficultyLevel.INTERMEDIATE,
        tags=["debug", "safe", "lifecycle_gated"],
    ))

    # =========================================================================
    # 5. DECODE_ADDRESS
    # =========================================================================
    # Case 12: TP - Decode overlap
    c12_rtl = """
    module addr_overlap_regs (
        input logic [7:0] addr_i,
        input logic [31:0] wdata_i,
        output logic [31:0] reg_alpha,
        output logic [31:0] reg_beta
    );
        // Colliding address offset 0x10 maps to both reg_alpha and reg_beta
        always_comb begin
            reg_alpha = (addr_i == 8'h10) ? wdata_i : 32'h0;
            reg_beta  = (addr_i == 8'h10) ? wdata_i : 32'h0;
        end
    endmodule
    """
    cases.append(BenchmarkCase(
        case_id="case_dec_01_address_overlap",
        name="Conflicting Address Decode Aliasing",
        category="DECODE_ADDRESS",
        description="Two distinct security control registers map to colliding address offset 0x10",
        source_fixture=c12_rtl.strip(),
        expected_behavior=ExpectedOutcome.TRUE_POSITIVE,
        expected_finding=True,
        weakness_class="DECODE_OVERLAP",
        difficulty=DifficultyLevel.BASIC,
        tags=["decode", "address_collision"],
    ))

    # Case 13: TN - Documented Array Multiregs (Safe)
    c13_rtl = """
    module multireg_key (
        input logic [7:0] addr_i,
        output logic [31:0] key_slice [0:3]
    );
        // Legitimate multireg slices with consecutive distinct offsets
        assign key_slice[0] = (addr_i == 8'h00) ? 32'h1 : 32'h0;
        assign key_slice[1] = (addr_i == 8'h04) ? 32'h2 : 32'h0;
        assign key_slice[2] = (addr_i == 8'h08) ? 32'h3 : 32'h0;
        assign key_slice[3] = (addr_i == 8'h0C) ? 32'h4 : 32'h0;
    endmodule
    """
    cases.append(BenchmarkCase(
        case_id="case_dec_02_documented_mirror_safe",
        name="Distinct Array Multiregs (Safe)",
        category="DECODE_ADDRESS",
        description="Standard word-aligned multireg array without overlapping slices",
        source_fixture=c13_rtl.strip(),
        expected_behavior=ExpectedOutcome.TRUE_NEGATIVE,
        expected_finding=False,
        weakness_class="DECODE_OVERLAP",
        difficulty=DifficultyLevel.BASIC,
        tags=["decode", "safe", "multireg"],
    ))

    # =========================================================================
    # 6. CONSTANT_SECURITY_CONTROL
    # =========================================================================
    # Case 14: TP - Security enable tied to constant 1
    c14_rtl = """
    module hardcoded_bypass (
        output logic sec_bypass_en
    );
        // Bug: Security bypass enable permanently asserted
        assign sec_bypass_en = 1'b1;
    endmodule
    """
    cases.append(BenchmarkCase(
        case_id="case_crypto_01_hardcoded_key_enable",
        name="Hardcoded Crypto Key Enable Constant",
        category="CRYPTO_CONTROL",
        description="Crypto security bypass enable line is tied high to static 1'b1",
        source_fixture=c14_rtl.strip(),
        expected_behavior=ExpectedOutcome.TRUE_POSITIVE,
        expected_finding=True,
        weakness_class="CRYPTO_CONTROL",
        difficulty=DifficultyLevel.BASIC,
        tags=["crypto", "constant", "hardcoded_enable"],
    ))

    # Case 15: TN - Intentional tie-off on unused pin
    c15_rtl = """
    module tie_low_test_pin (
        output logic unused_test_pin
    );
        // Safe: Unused external pin tied low
        assign unused_test_pin = 1'b0;
    endmodule
    """
    cases.append(BenchmarkCase(
        case_id="case_const_02_intentional_tieoff_safe",
        name="Benign Ground Tie-off on Unused Net",
        category="CRYPTO_CONTROL",
        description="Inert ground connection on non-security external test point",
        source_fixture=c15_rtl.strip(),
        expected_behavior=ExpectedOutcome.TRUE_NEGATIVE,
        expected_finding=False,
        weakness_class="CRYPTO_CONTROL",
        difficulty=DifficultyLevel.BASIC,
        tags=["crypto", "safe", "tie_off"],
    ))

    # =========================================================================
    # 7. INFORMATION_FLOW
    # =========================================================================
    # Case 16: TP - Secret key leaking directly to debug output
    c16_rtl = """
    module secret_leak_debug (
        input logic [127:0] root_key_i,
        output logic [127:0] dbg_out
    );
        // Bug: Secret key flows directly to unauthenticated debug output
        assign dbg_out = root_key_i;
    endmodule
    """
    cases.append(BenchmarkCase(
        case_id="case_inf_01_unmasked_secret_leak",
        name="Direct Key Leakage to Diagnostic Port",
        category="INFORMATION_FLOW",
        description="Cryptographic key root is routed without masking to observable port",
        source_fixture=c16_rtl.strip(),
        expected_behavior=ExpectedOutcome.TRUE_POSITIVE,
        expected_finding=True,
        weakness_class="INFORMATION_FLOW",
        expected_lane=FindingLane.PROBABLE,
        difficulty=DifficultyLevel.INTERMEDIATE,
        tags=["information_flow", "leak"],
    ))

    # Case 17: TN - Approved Crypto Declassifier (Safe)
    c17_rtl = """
    module approved_hash_declass (
        input logic [127:0] secret_input,
        output logic [31:0] hash_digest
    );
        // Safe: Secret passes through one-way hash declassification
        assign hash_digest = secret_input[31:0] ^ secret_input[63:32];
    endmodule
    """
    cases.append(BenchmarkCase(
        case_id="case_inf_02_approved_declassifier_safe",
        name="Approved One-Way Declassification",
        category="INFORMATION_FLOW",
        description="Declassifier registry authorized one-way digest publication",
        source_fixture=c17_rtl.strip(),
        expected_behavior=ExpectedOutcome.TRUE_NEGATIVE,
        expected_finding=False,
        weakness_class="INFORMATION_FLOW",
        difficulty=DifficultyLevel.INTERMEDIATE,
        tags=["information_flow", "safe", "declassifier"],
    ))

    # =========================================================================
    # 8. FAULT_INJECTION
    # =========================================================================
    # Case 18: TP - Single-bit critical auth branch
    c18_rtl = """
    module fragile_auth_branch (
        input logic clk_i,
        input logic auth_bit,
        output logic privileged_mode
    );
        // Critical transition dependent on single unhardened bit
        always_ff @(posedge clk_i) begin
            privileged_mode <= auth_bit;
        end
    endmodule
    """
    cases.append(BenchmarkCase(
        case_id="case_fi_01_ungarded_critical_branch",
        name="Unhardened Single-Bit Security Branch",
        category="FAULT_INJECTION",
        description="Security privilege mode transition vulnerable to single-clock glitch",
        source_fixture=c18_rtl.strip(),
        expected_behavior=ExpectedOutcome.TRUE_POSITIVE,
        expected_finding=True,
        weakness_class="FAULT_INJECTION",
        in_scope=False,
        difficulty=DifficultyLevel.HARD,
        tags=["fault_injection", "glitch", "out_of_scope"],
    ))

    # Case 19: TN - Hardened Dual-Rail Check (Safe)
    c19_rtl = """
    module dual_rail_hardened_auth (
        input logic clk_i,
        input logic auth_true,
        input logic auth_false,
        output logic priv_mode
    );
        // Safe: Requires complementary dual-rail validation
        always_ff @(posedge clk_i) begin
            if (auth_true && !auth_false) priv_mode <= 1'b1;
            else priv_mode <= 1'b0;
        end
    endmodule
    """
    cases.append(BenchmarkCase(
        case_id="case_fi_02_redundant_dual_rail_safe",
        name="Dual-Rail Hardened State Transition",
        category="FAULT_INJECTION",
        description="Complementary dual-rail logic prevents single-bit fault exploitation",
        source_fixture=c19_rtl.strip(),
        expected_behavior=ExpectedOutcome.TRUE_NEGATIVE,
        expected_finding=False,
        weakness_class="FAULT_INJECTION",
        difficulty=DifficultyLevel.HARD,
        tags=["fault_injection", "safe", "dual_rail"],
    ))

    # =========================================================================
    # 9. OBFUSCATED VARIANTS (Parity Tracking)
    # =========================================================================
    # Case 20: Obfuscated variant of Case 1 (Missing Regwen)
    obf_c1, _ = DeterministicObfuscator.obfuscate_rtl(c1_rtl)
    cases.append(BenchmarkCase(
        case_id="case_ac_01_obf",
        name="[Obfuscated] Missing Regwen Lock",
        category="ACCESS_CONTROL",
        description="Obfuscated variant with scrambled identifiers and stripped comments",
        source_fixture=obf_c1.strip(),
        expected_behavior=ExpectedOutcome.TRUE_POSITIVE,
        expected_finding=True,
        weakness_class="LOCK_ACCESS_CONTROL",
        expected_lane=FindingLane.PROBABLE,
        obfuscation_variant=True,
        original_case_id="case_ac_01_missing_regwen",
        difficulty=DifficultyLevel.INTERMEDIATE,
        tags=["access_control", "obfuscated", "parity"],
    ))

    # Case 21: Obfuscated variant of Case 5 (Unreset Key)
    obf_c5, _ = DeterministicObfuscator.obfuscate_rtl(c5_rtl)
    cases.append(BenchmarkCase(
        case_id="case_rst_01_obf",
        name="[Obfuscated] Unreset Security Register",
        category="RESET",
        description="Obfuscated unreset state with renamed signals",
        source_fixture=obf_c5.strip(),
        expected_behavior=ExpectedOutcome.TRUE_POSITIVE,
        expected_finding=True,
        weakness_class="RESET_ISSUE",
        obfuscation_variant=True,
        original_case_id="case_rst_01_unreset_security_reg",
        difficulty=DifficultyLevel.INTERMEDIATE,
        tags=["reset", "obfuscated", "parity"],
    ))

    # Case 22: Obfuscated variant of Case 3 (Safe Regwen)
    obf_c3, _ = DeterministicObfuscator.obfuscate_rtl(c3_rtl)
    cases.append(BenchmarkCase(
        case_id="case_ac_03_obf",
        name="[Obfuscated] Legitimate Regwen (Safe)",
        category="ACCESS_CONTROL",
        description="Obfuscated safe regwen design to verify false-positive immunity under renaming",
        source_fixture=obf_c3.strip(),
        expected_behavior=ExpectedOutcome.TRUE_NEGATIVE,
        expected_finding=False,
        weakness_class="LOCK_ACCESS_CONTROL",
        obfuscation_variant=True,
        original_case_id="case_ac_03_valid_regwen_safe",
        difficulty=DifficultyLevel.INTERMEDIATE,
        tags=["access_control", "safe", "obfuscated", "true_negative"],
    ))

    # Case 23: Obfuscated variant of Case 10 (Ungated Debug)
    obf_c10, _ = DeterministicObfuscator.obfuscate_rtl(c10_rtl)
    cases.append(BenchmarkCase(
        case_id="case_dbg_01_obf",
        name="[Obfuscated] Ungated Debug Override",
        category="DEBUG_TEST_GATING",
        description="Scrambled debug interface testing deterministic structural detection parity",
        source_fixture=obf_c10.strip(),
        expected_behavior=ExpectedOutcome.TRUE_POSITIVE,
        expected_finding=True,
        weakness_class="DEBUG_GATING",
        expected_lane=FindingLane.PROBABLE,
        obfuscation_variant=True,
        original_case_id="case_dbg_01_ungated_debug_bus",
        difficulty=DifficultyLevel.INTERMEDIATE,
        tags=["debug", "obfuscated", "parity"],
    ))

    return cases
