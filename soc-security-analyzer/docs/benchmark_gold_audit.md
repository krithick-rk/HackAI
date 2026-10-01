# Benchmark Ground-Truth & Taxonomy Audit (V2)

> **Taxonomy Version:** `2`  
> **Branch:** `develop`  
> **Purpose:** Authoritative ground-truth provenance verification, root-cause/consequence separation, and adjudication of disputed gold labels.  

---

## Executive Summary

An exhaustive audit was conducted on all 23 benchmark cases in the SoC Security Analyzer V2 corpus to determine whether the recent gold-label changes to `case_crypto_01`, `case_inf_01`, and `case_fi_01` were legitimate or constituted an improper adaptation of the benchmark to the detector output.

### Key Audit Findings

1. **All three disputed gold label changes are INVALID and REJECTED:**
   - **`case_crypto_01` (`CRYPTO_CONTROL` -> `LOCK_ACCESS_CONTROL`):** The module is purely combinational (`assign sec_bypass_en = 1'b1;`). It contains no register, clock, or write-enable lock. The detector alert `MISSING_REGWEN` is a spurious harness artifact triggered because the benchmark asset injector registered a mock asset for the output port. The finding exists identically in the clean design (`BASELINE_PRESENT`). Relabeling to `LOCK_ACCESS_CONTROL` is **INVALID**.
   - **`case_inf_01` (`INFORMATION_FLOW` -> `DEBUG_TEST_GATING`):** The seeded defect is unmasked propagation of a 128-bit root key to an observable diagnostic port (`assign dbg_out = root_key_i;`). The detector alert `MISSING_DEBUG_GATING` fired purely because the port name matched prefix `dbg_` without analyzing data flow; the alert persists identically if the output is tied to zero (`BASELINE_PRESENT`). Relabeling to `DEBUG_TEST_GATING` is **INVALID**.
   - **`case_fi_01` (`FAULT_INJECTION` -> `RESET_ISSUE`):** The seeded defect is single-rail unhardened authorization susceptible to clock/voltage glitching. The detector alert `MISSING_RESET` is an incidental hygiene artifact present in both the buggy single-rail mutant and the safe dual-rail clean design (`BASELINE_PRESENT`). Furthermore, general fault injection is **OUT_OF_SCOPE** for V2 static structural analysis. Relabeling to `RESET_ISSUE` is **INVALID**.

2. **Strict vs Adjudicated Metrics:**
   - **Strict View (Original Gold):** Recall **53.85%** (7/13), Precision **63.64%** (7/11).
   - **Adjudicated View (Provenance-Supported):** In-scope Recall **58.33%** (7/12) with `case_fi_01` marked `OUT_OF_SCOPE`, Precision **63.64%** (7/11).
   - **Unadjudicated Current View (Artificially Inflated):** Recall 84.62% (11/13), Precision 73.33% (11/15) achieved by improper label adaptation.

---

## Gold Taxonomy Audit Table

| Case | Mutation | Root Cause | Consequence | Domain | Attacker | Current Gold | Audited Gold | Detector Finding | Relationship | In Scope? | Credit? | Reason |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `case_ac_01_missing_regwen` | OMIT_LOCK_GUARD | LOCK_ACCESS_CONTROL | UNAUTHORIZED_REGISTER_WRITE | ACCESS_CONTROL | UNTRUSTED_SOFTWARE_MASTER | LOCK_ACCESS_CONTROL | LOCK_ACCESS_CONTROL | MISSING_REGWEN, MISSING_RESET | EXACT | Yes | Yes | Detector correctly detects missing regwen lock at register write site. |
| `case_ac_02_subtle_guard_bypass` | DISJUNCTION_INSERTION | LOCK_ACCESS_CONTROL | ACCESS_CONTROL_BYPASS | ACCESS_CONTROL | DEBUG_OVERRIDE_EXPLOITER | LOCK_ACCESS_CONTROL | LOCK_ACCESS_CONTROL | None | NONE | Yes | No | Genuine false negative; detector does not yet analyze AST disjunction bypasses. |
| `case_rst_01_unreset_security_reg` | OMIT_RESET_BRANCH | RESET_ISSUE | RESIDUAL_STATE_RETENTION | RESET | POST_RESET_SNOOPER | RESET_ISSUE | RESET_ISSUE | MISSING_RESET | EXACT | Yes | Yes | Detector correctly detects unreset security register. |
| `case_rst_02_polarity_inconsistency` | POLARITY_INVERSION | RESET_ISSUE | ASYNCHRONOUS_RESET_DESYNCHRONIZATION | RESET | RESET_GLITCH_ADVERSARY | RESET_ISSUE | RESET_ISSUE | RESET_POLARITY_INCONSISTENCY | EXACT | Yes | Yes | Detector correctly flags mixed reset polarities across sibling security registers. |
| `case_fsm_01_missing_default_state` | OMIT_DEFAULT_CLAUSE | FSM_STRUCTURAL | ILLEGAL_STATE_HANG_OR_ESCAPE | FSM | FAULT_STATE_INJECTOR | FSM_STRUCTURAL | FSM_STRUCTURAL | FSM_MISSING_DEFAULT | EXACT | Yes | Yes | Detector correctly flags missing default state recovery; normalized via exact FSM family alias. |
| `case_dbg_01_ungated_debug_bus` | OMIT_LIFECYCLE_GATING | DEBUG_TEST_GATING | UNAUTHENTICATED_OVERRIDE | DEBUG_TEST_GATING | EXTERNAL_JTAG_ATTACKER | DEBUG_GATING | DEBUG_TEST_GATING | MISSING_DEBUG_GATING | EXACT | Yes | Yes | Detector correctly detects ungated debug override on security register. |
| `case_dec_01_address_overlap` | COLLIDING_ADDRESS_DECODE | DECODE_ADDRESS | ADDRESS_SPACE_COLLISION | DECODE_ADDRESS | SOFTWARE_BUS_MASTER | DECODE_OVERLAP | DECODE_ADDRESS | DECODE_OVERLAP | EXACT | Yes | Yes | Detector correctly identifies colliding address offsets. |
| `case_crypto_01_hardcoded_key_enable` | CONSTANT_TIE_HIGH | CONSTANT_SECURITY_CONTROL | PERMANENT_SECURITY_BYPASS | CRYPTO_CONTROL | UNAUTHENTICATED_CALLER | LOCK_ACCESS_CONTROL | CONSTANT_SECURITY_CONTROL | MISSING_REGWEN | SAME_SITE_OTHER_BUG | Yes | No | Module is purely combinational with no register, clock, or write lock. Detector MISSING_REGWEN alert is a spurious harness artifact triggered on both mutant and clean designs (BASELINE_PRESENT). Rejection of gold change is required. |
| `case_inf_01_unmasked_secret_leak` | DIRECT_SECRET_PROPAGATION | INFORMATION_FLOW | SECRET_DATA_LEAKAGE | INFORMATION_FLOW | EXTERNAL_PORT_OBSERVER | DEBUG_TEST_GATING | INFORMATION_FLOW | MISSING_REGWEN, MISSING_DEBUG_GATING | SAME_SITE_OTHER_BUG | Yes | No | Detector flagged MISSING_DEBUG_GATING solely due to port name 'dbg_out' without analyzing data flow; clean design triggers identical alert (BASELINE_PRESENT). Rejection of gold change is required. |
| `case_fi_01_ungarded_critical_branch` | SINGLE_RAIL_DEGRADATION | FAULT_INJECTION | GLITCH_INDUCED_PRIVILEGE_ESCALATION | FAULT_INJECTION | FAULT_INJECTION_ADVERSARY | RESET_ISSUE | FAULT_INJECTION | MISSING_REGWEN, MISSING_RESET | BASELINE_PRESENT | No | No | Mutation is single-rail vs dual-rail glitch vulnerability. MISSING_RESET is an incidental fixture artifact present in both mutant and clean designs (BASELINE_PRESENT). Fault injection is OUT_OF_SCOPE for V2 static analysis. Rejection of gold change is required. |
| `case_ac_01_obf` | DETERMINISTIC_OBFUSCATION | LOCK_ACCESS_CONTROL | UNAUTHORIZED_REGISTER_WRITE | ACCESS_CONTROL | UNTRUSTED_SOFTWARE_MASTER | LOCK_ACCESS_CONTROL | LOCK_ACCESS_CONTROL | MISSING_REGWEN, MISSING_RESET | EXACT | Yes | Yes | Detector successfully retains detection of missing regwen lock under obfuscation. |
| `case_rst_01_obf` | DETERMINISTIC_OBFUSCATION | RESET_ISSUE | RESIDUAL_STATE_RETENTION | RESET | POST_RESET_SNOOPER | RESET_ISSUE | RESET_ISSUE | MISSING_RESET, MISSING_REGWEN | EXACT | Yes | Yes | Detector successfully retains detection of unreset security register under obfuscation. |
| `case_dbg_01_obf` | DETERMINISTIC_OBFUSCATION | DEBUG_TEST_GATING | UNAUTHENTICATED_OVERRIDE | DEBUG_TEST_GATING | EXTERNAL_JTAG_ATTACKER | DEBUG_GATING | DEBUG_TEST_GATING | MISSING_REGWEN, MISSING_RESET | NONE | Yes | No | Genuine false negative under obfuscation; regex port matching fails when signal names are scrambled. |

---

## Special Case Audits

### 1. Special Audit: `case_crypto_01_hardcoded_key_enable`
- **RTL Fixture:**
  ```systemverilog
  module hardcoded_bypass (
      output logic sec_bypass_en
  );
      // Bug: Security bypass enable permanently asserted
      assign sec_bypass_en = 1'b1;
  endmodule
  ```
- **Clean Reference:** `tie_low_test_pin` (inert tie-off) / dynamic control
- **Seeded Defect:** Security bypass enable line permanently asserted to static `1'b1`.
- **Clean vs. Mutant Test:** Reverting `sec_bypass_en = 1'b1` to dynamic input or `0` leaves `MISSING_REGWEN` active on both designs.
- **Root-Cause Analysis:** The module is purely combinational. It has no clock, no sequential state, and no bus slave register interface. The detector alert `MISSING_REGWEN` is a spurious artifact of benchmark harness asset auto-discovery creating a synthetic register entry for port `sec_bypass_en`.
- **Taxonomy Dimension:** Root Cause = `CONSTANT_SECURITY_CONTROL`, Consequence = `PERMANENT_SECURITY_BYPASS`, Domain = `CRYPTO_CONTROL`, Attacker = `UNAUTHENTICATED_CALLER`.
- **Verdict:** **INVALID**. Match relationship is `SAME_SITE_OTHER_BUG` / `BASELINE_PRESENT`. Credit: **NO**.

### 2. Special Audit: `case_inf_01_unmasked_secret_leak`
- **RTL Fixture:**
  ```systemverilog
  module secret_leak_debug (
      input logic [127:0] root_key_i,
      output logic [127:0] dbg_out
  );
      // Bug: Secret key flows directly to unauthenticated debug output
      assign dbg_out = root_key_i;
  endmodule
  ```
- **Clean Reference:** `approved_hash_declass` (one-way digest) / zeroed diagnostic port
- **Seeded Defect:** Direct unmasked propagation of raw 128-bit cryptographic root key to observable diagnostic port.
- **Clean vs. Mutant Test:** Reverting `assign dbg_out = root_key_i;` to `assign dbg_out = 128'b0;` produces an identical `MISSING_DEBUG_GATING` finding.
- **Root-Cause Analysis:** The detector `DebugGatingDetector` matches port names with prefix `dbg_` lacking `lc_state`/`auth` ports. It does not perform taint or information-flow analysis from `root_key_i`.
- **Taxonomy Dimension:** Root Cause = `INFORMATION_FLOW`, Consequence = `SECRET_DATA_LEAKAGE`, Domain = `INFORMATION_FLOW`, Attacker = `EXTERNAL_PORT_OBSERVER`.
- **Verdict:** **INVALID**. Match relationship is `SAME_SITE_OTHER_BUG` / `BASELINE_PRESENT`. Credit: **NO**.

### 3. Special Audit: `case_fi_01_ungarded_critical_branch`
- **RTL Fixture:**
  ```systemverilog
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
  ```
- **Clean Reference:** `dual_rail_hardened_auth` (complementary dual-rail check `if (auth_true && !auth_false)`)
- **Seeded Defect:** Single-rail unhardened privilege transition vulnerable to clock/voltage fault injection.
- **Clean vs. Mutant Test:** Safe clean design `dual_rail_hardened_auth` ALSO produces `MISSING_RESET` because both test fixtures omit reset ports.
- **Root-Cause Analysis:** The seeded bug is strictly a fault injection vulnerability. `MISSING_RESET` is an incidental fixture artifact present in both mutant and clean designs (`BASELINE_PRESENT`). Furthermore, V2 static structural analysis does not support fault injection verification.
- **Taxonomy Dimension:** Root Cause = `FAULT_INJECTION`, Consequence = `GLITCH_INDUCED_PRIVILEGE_ESCALATION`, Domain = `FAULT_INJECTION`, Attacker = `FAULT_INJECTION_ADVERSARY`.
- **Verdict:** **INVALID**. Match relationship is `BASELINE_PRESENT`. Scope: **OUT_OF_SCOPE**. Credit: **NO**.

---

## Negative-Control (False Positive) Audit

| Case ID | Expected | Actual Lane | Classification | Detailed Root Cause |
|---|---|---|---|---|
| `case_ac_04_unreachable_write` | `UNREACHABLE` | `PROBABLE` | `FALSE` | Reachability engine failed to prove unsatisfiability of statically dead guard `we && 1'b0`; finding remained grounded in PROBABLE lane. |
| `case_rst_03_safe_reset_defaults` | `TRUE_NEGATIVE` | `PROBABLE` | `FALSE` | Slang procedural block fact extractor failed to extract active-low reset signal `rst_ni` from sensitivity list, causing `ResetIssueDetector` to flag clocked module as lacking resets. |
| `case_dbg_02_properly_lifecycle_gated` | `TRUE_NEGATIVE` | `LEAD` | `FALSE` | `DebugGatingDetector` keyword regex requires `lc_state` or `auth` in port names; it failed to recognize legitimate lifecycle authorization token port `lc_debug_en`. |
| `case_ac_03_obf` | `TRUE_NEGATIVE` | `PROBABLE` | `ENVIRONMENT_ARTIFACT` | Benchmark runner test harness relies on literal port name matching `regwen` to configure mock register assets; identifier obfuscation scrambled `regwen`, causing the harness to synthesize an un-gated asset (`regwen=None`). |

---

## Strict vs Adjudicated Metrics Comparison

| Metric | Strict View (Original Gold) | Adjudicated View (Provenance-Supported) | Current Unadjudicated View (Adapted) |
|---|---|---|---|
| **Total Vulnerabilities** | 13 | 13 (12 in-scope, 1 out-of-scope) | 13 |
| **True Positives (TP)** | 7 | 7 | 11 |
| **False Negatives (FN)** | 6 | 5 (in-scope) | 2 |
| **False Positives (FP)** | 4 | 4 | 4 |
| **True Negatives (TN)** | 6 | 6 | 6 |
| **Recall** | **53.85%** (7/13) | **58.33%** (7/12 in-scope) / **53.85%** (all) | 84.62% (11/13) *(inflated)* |
| **Precision** | **63.64%** (7/11) | **63.64%** (7/11) | 73.33% (11/15) |
| **Wrong Refutations** | 0 | 0 | 0 |
| **Obfuscation Retention** | 66.67% (2/3) | 66.67% (2/3) | 66.67% (2/3) |

---

## Benchmark Taxonomy Governance Policy

1. **Taxonomy Versioning:** Any modification to benchmark gold labels requires incrementing `taxonomy_version` (current: `2`).
2. **Provenance Mandate:** Every benchmark case must define `mutation_site`, `mutation_operator`, `clean_rtl_reference`, and `root_cause_property` independently of detector behavior.
3. **Baseline Invariance Rule:** If reverting the seeded mutation does not remove a detector finding, that finding is classified as `BASELINE_PRESENT` and cannot receive detection credit.
4. **Dimensional Separation:** Gold labels must strictly separate `root_cause_property`, `consequence_property`, `asset_domain`, and `attacker_class`.
5. **No Silent Edits:** All taxonomy updates require an auditable entry in `docs/benchmark_gold_audit.json` with an explicit rationale.
