# Dynamic Analysis Strategy for OpenTitan IP Modules

*Compiled from direct inspection of the `lowRISC/opentitan` repository. All directory structures, file names, and tool references below were verified against the live repository rather than assumed.*

---

## 1. Purpose

This document defines a repeatable approach for performing dynamic analysis (simulation-based testing, fuzzing, and fault injection) against an individual IP module in the OpenTitan hardware root-of-trust codebase. It also establishes which existing verification assets should be reused rather than rebuilt, using the AES module as a concrete, verified case study.

---

## 2. Core Principle: Simulation Operates on an Elaborated Hierarchy, Not Individual Files

An IP module folder (e.g. `hw/ip/aes/rtl/`) typically contains dozens of `.sv` files. A common misconception is that dynamic analysis should run per file. In reality:

- A `.sv` file is a source-organization unit, not a simulation unit.
- A simulator (Verilator, iverilog) elaborates a design starting from one chosen top-level module and pulls in every module that top instantiates, directly or transitively — regardless of which file each one is defined in.
- For AES specifically: `aes_core.sv` instantiates `aes_prng_clearing`, `aes_ctr`, `aes_cipher_core`, `aes_ghash`, `aes_control`, and several `aes_sel_buf_chk` instances; `aes_cipher_core` in turn instantiates `aes_sub_bytes`, `aes_shift_rows`, `aes_mix_columns`, `aes_key_expand`, and a selected S-box variant. All 39 files under `hw/ip/aes/rtl/` collapse into one elaborated design under a single top (`aes.sv`).

**Implication:** dynamic analysis of a module means selecting the correct DUT (Design Under Test) boundary and running simulation/fuzzing against that boundary — not running separate campaigns per file. File-level granularity re-enters the picture only for specific sub-analyses (Section 5).

---

## 3. Standard Step-by-Step Dynamic Analysis Approach

1. **Build.** Compile the module hierarchy (Verilator/iverilog) starting from its top-level wrapper. Confirm clean elaboration before proceeding.
2. **Stand up the existing testbench.** Nearly every IP already has a working verification environment (see Section 4). Run its existing smoke tests first to establish a known-good baseline.
3. **Measure existing coverage.** Run the existing test suite with coverage enabled to identify which internal states/branches are already well-exercised versus thin. Thin coverage indicates where further effort should be concentrated.
4. **Layer randomized stimulus on top of existing sequences.** Randomize register writes, data, timing, and operation ordering, while keeping the existing reference-model scoreboard active — every mismatch between RTL output and the reference model is an automatic bug flag.
5. **Deliberately exercise illegal and edge-case sequences.** Aborting mid-operation, switching configuration while busy, and back-to-back operations without proper clearing are common sources of real bugs — more so than core functional correctness, which is typically already well tested.
6. **Enable assertions (SVA) throughout.** Assertions catch internal protocol/invariant violations even when final output appears correct.
7. **Run fault injection as a separate pass from functional fuzzing.** This targets a different question: when an internal signal is corrupted, does the module fail safely (alert raised, no leakage, no silently wrong output)?
8. **Handle small, purely combinational sub-blocks separately.** Blocks with a small enough input space (e.g. an 8-bit S-box, 256 possible inputs) should be exhaustively tested or formally verified rather than randomly fuzzed.
9. **Feed coverage results back into stimulus generation.** Bias further fuzzing toward unexercised states rather than continuing to sample randomly without direction.
10. **Triage every failure to root cause.** Scoreboard mismatches, assertion failures, missing alerts, or hangs should be traced back to the responsible RTL signal/line using waveform inspection (GTKWave) — this is the step that converts a candidate finding into a confirmed bug.

---

## 4. Existing Verification Infrastructure — Directory Reference

OpenTitan IP modules generally ship with multiple, purpose-distinct verification asset directories. Reusing these is significantly more efficient than building analysis infrastructure from scratch.

| Directory | Purpose | Typical Contents |
|---|---|---|
| `dv/` | Primary, full-scale verification environment (usually UVM-based) | `env/` (scoreboard, sequencer, reference model hookup), `tb/` (top-level testbench file instantiating the DUT), `tests/`, `sva/` (assertions), `cov/` (coverage collection), `err_injection_if/` (fault-injection force interfaces) |
| `dv/tb/` | The specific file that instantiates the DUT and connects it to the verification environment | Typically a single `tb.sv` |
| `pre_dv/` | Present on some modules only; older or lightweight standalone unit-level testbenches, often predating the full `dv/` environment | Per-submodule testbenches (e.g. isolated S-box or cipher-core testbenches), occasionally a logic-equivalence-checking setup |
| `pre_sca/` | Present on select security-critical modules; pre-configured integrations with third-party side-channel-leakage evaluation tools | Formal masking-verification and probing-based leakage-evaluation tool configurations (see Section 5) |
| `model/` | Reference software/behavioral model used for output comparison | Reference implementation used by the scoreboard |

**Key point:** `tb/` is typically a subdirectory *within* `dv/` (the testbench top file), not a sibling, alternative directory to `dv/`. Where a standalone `pre_dv/` exists at the module's top level, it represents a separate, usually lighter-weight, unit-level testing approach that coexists with the full `dv/` environment rather than replacing it.

---

## 5. Case Study: AES Module — Verified Existing Assets

The AES module (`hw/ip/aes/`) was inspected directly and demonstrates the fullest example of this layered structure within OpenTitan.

### 5.1 `dv/` — Full Functional Verification Environment

Contains a complete UVM environment: scoreboard, sequence library, an assertion set (`sva/`), coverage binding (`cov/`), a C reference-model comparison via DPI (`aes_model_dpi/`), and a dedicated fault-injection interface directory (`err_injection_if/`) providing force-based wrappers into specific internal FSMs (`fi_cipher_fsm_wrapper.sv`, `fi_ctr_fsm_wrapper.sv`, `fi_control_fsm_wrapper.sv`, `fi_ghash_wrapper.sv`).

**Recommended reuse:** extend the existing sequence library for randomized/illegal-sequence fuzzing (Steps 4–5) and extend the existing fault-injection wrappers for Step 7, rather than building new bus-stimulus generation or new internal force points.

### 5.2 `pre_dv/` — Standalone Unit-Level Testbenches

Contains pre-built, isolated testbenches: `aes_sbox_tb`, `aes_cipher_core_tb`, `aes_wrap_tb`, `aes_tlul_shim_tb`, and a logic-equivalence-checking setup (`aes_sbox_lec`, Yosys-based).

**Recommended reuse:** these solve the "how do I instantiate this submodule in isolation" problem already; use them directly for Step 8 (isolated/exhaustive testing of small combinational sub-blocks) instead of writing new standalone harnesses.

### 5.3 `pre_sca/` — Pre-Integrated Side-Channel-Leakage Evaluation Tooling

This is the most significant existing asset for security-focused dynamic analysis, and is already configured for two established third-party tools:

- **ALMA** (`pre_sca/alma/`) — formal masking-verification tool (IAIK, "Execution-aware Masking Verification"). Pre-configured with working scripts (`verify_aes.sh`) to formally verify the masking of `aes_sbox`, and configurable for `aes_sub_bytes` or `aes_reduced_round`.
- **PROLEAD** (`pre_sca/prolead/`) — probing-based hardware leakage-detection tool. Pre-configured (`evaluate.sh`, `aes_cipher_core_config.set`) to evaluate the masked `aes_cipher_core` together with its PRNG, reporting statistical leakage significance (`-log10(p)`) per internal probing location.
- **`pre_sca/alma_post_syn/`** — extends the ALMA flow to post-synthesis netlists rather than RTL, closing part of the gap between RTL-level masking claims and physical-implementation-level verification.

**Recommended reuse:** these tools already produce formal/statistical leakage assessments of the masked S-box and cipher core. Running and interpreting these existing flows should precede any custom leakage-evaluation tooling for this module.

### 5.4 `model/` — Reference Behavioral Model

Supplies the reference implementation used by the `dv/` scoreboard for automated output comparison during simulation.

---

## 6. Handling Multiple "Top-Level" Files Within a Module

It is common, not anomalous, for a module to contain more than one file that looks like a top-level module. Verified examples:

| Module | Extra top-level file | Confirmed purpose |
|---|---|---|
| AES | `aes_wrap.sv` (alongside production `aes.sv`) | Source header explicitly identifies this as a wrapper built for fault-injection experiments, separate from the production chip integration |
| AES (within `pre_sca/alma/`) | `aes_sbox_masked_wrapper.sv` | Wrapper built specifically to give the ALMA tool a clean interface for isolated masked S-box verification |
| OTBN | `dv/uvm/tb.sv` vs. `dv/verilator/otbn_top_sim.sv` | Two distinct testbench tops for two distinct purposes: full UVM functional verification versus a lightweight Verilator-native harness used for fast random-instruction-driven fuzzing |
| `rv_core_ibex` (cross-module, documented separately) | Independently generated per-chip wrapper copies across each top-level chip configuration | Not alternative candidates; each is the correct, chip-specific integration for its respective chip |

**Resolution approach:** when multiple top-level candidates exist, identify the correct one by (a) the containing directory, since `pre_sca/`, `pre_dv/`, `dv/uvm/`, and `dv/verilator/` each signal a distinct analysis purpose, and (b) the file's own header comment, which in every verified case explicitly stated its purpose. The correct top is the one matching the specific analysis being performed, not a single universal choice.

---

## 7. Summary Recommendations

1. Identify the module's actual DUT boundary before planning any simulation or fuzzing campaign; do not plan work at individual file granularity.
2. Inventory and reuse existing `dv/`, `pre_dv/`, and `pre_sca/` assets before building new test infrastructure — for security-critical modules, this can include already-integrated formal masking-verification and leakage-evaluation tooling.
3. Treat functional fuzzing, assertion-based checking, and fault injection as three separate passes with different objectives, all run against the same elaborated hierarchy.
4. Reserve exhaustive/formal verification for small, purely combinational sub-blocks where the input space is small enough to fully enumerate, rather than applying random fuzzing uniformly across the entire module.
5. When multiple top-level files exist, resolve ambiguity using directory context and source header comments rather than assuming a single correct top applies to all analysis types.
