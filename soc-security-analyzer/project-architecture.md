# AI-Powered SoC Hardware Security Analyzer
## Project Architecture & Workflow

---

## 1. Overview

A multi-agent AI system that audits a Verilog/SystemVerilog SoC hardware project for bugs and
security vulnerabilities. The system combines open-source static and dynamic analysis tools with
AI reasoning across a hierarchy of isolated agent instances. A Python orchestration layer handles
all mechanical work (file routing, assignment tracking, error counting, deduplication, CWE
pre-processing) so that AI instances are reserved exclusively for reasoning tasks. A human
operator retains full visibility and control throughout via a local GUI dashboard.

**Core design principles:**

- RTL source files are **never modified** under any circumstance — this is an audit of an
  already-finalized design.
- Every finding (static or dynamic) must be backed by a **working exploit and a demonstration**,
  not just a description.
- **Python does all mechanical work.** File routing, assignment tracking, deduplication,
  error counting, CWE API calls, log compression, and inter-agent data passing are all Python.
  AI is never used where deterministic code suffices.
- Context window overload is the primary AI failure mode — addressed through agent isolation,
  per-module artifact slicing, and progressive loading.
- AI hallucination is treated as inevitable and is caught through a dedicated verification
  layer that checks every claim against the actual source code.
- Tool environment failures are a **first-class concern** — solved once in Phase 0 per module,
  non-blocking (failures in one module do not stop analysis of others).
- The human operator is never locked out — pipeline is pausable, resumable, and steerable at
  every phase.

---

## 2. Agent & Component Hierarchy

```
┌─────────────────────────────────────────────────────────┐
│             THROWAWAY AI  (Phase 0 only)                │
│   context generation · synthesis · tool validation      │
│             discarded when Phase 0 completes            │
└───────────────────────┬─────────────────────────────────┘
                        │ writes artifacts to disk
                        ▼
┌─────────────────────────────────────────────────────────┐
│          PYTHON ORCHESTRATOR  (persistent)              │
│  reads Phase 0 artifacts · assigns modules to workers   │
│  tracks worker state · routes findings · deduplicates   │
│  calls CWE API · compresses tool output · manages GUI   │
│  NO AI — purely deterministic Python                    │
└───────────────────────┬─────────────────────────────────┘
                        │ spawns and monitors
          ┌─────────────┼──────────────┐
          ▼             ▼              ▼
    Worker AI #1   Worker AI #2   Worker AI #N
    (isolated)     (isolated)     (isolated)
          │
          └── on findings: Python deduplicates before storing
                        │
                        ▼
┌─────────────────────────────────────────────────────────┐
│               MASTER AI  (Phase 4–5 only)               │
│  hallucination verification · exploit chaining          │
│  final report assembly                                  │
└─────────────────────────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────┐
│            RE-CHECK AI  (on-demand, per finding)        │
│  spawned only when human requests re-check of a         │
│  hallucination-flagged or disputed finding              │
│  scoped to one finding only — discarded after           │
└─────────────────────────────────────────────────────────┘
```

### Throwaway AI (Phase 0)
Single-use. Handles all whole-project upfront reasoning: dependency graph analysis, context
generation, synthesis coordination, fuzzing candidate recommendation. Writes structured artifacts
to disk and is discarded. Never participates in bug analysis. Everything it reasons about lives
in files, not in its conversational memory.

### Python Orchestrator
Replaces what was previously called "Master AI for distribution." All mechanical orchestration
— reading Phase 0 artifacts, deciding which files go to which worker, tracking worker state,
counting retry attempts, routing tool outputs, deduplicating findings across sources, calling the
CWE API, and compressing logs before AI sees them — is pure Python. No AI token budget is spent
on mechanical operations.

### Worker AI
Spawned per module-group assignment by the Python orchestrator. Operates in full isolation.
The invocation map gives workers a **validated starting point** for tool commands — workers are
free to modify flags and options (add `--coverage`, change solver backend, add `--Wall`, try
different elaboration options) when their analysis requires it. The map prevents from-scratch
path discovery; it does not constrain analysis choices.

### Master AI (Phase 4–5 only)
Lightweight, activated only after all workers complete. Receives structured finding JSONs (never
raw source). Performs hallucination ground-truth checks, cross-module exploit chaining, and final
report assembly.

### Re-Check AI (on-demand)
A fresh, single-purpose instance spawned only when the human operator requests a re-check of a
specific hallucination-flagged or disputed finding. Receives only: the flagged finding, the exact
source code at the reported lines, and the original worker's reasoning. Scoped to that one
finding and discarded after. This is not automatic — it is an explicit human-triggered action
from the GUI.

---

## 3. Phase-by-Phase Workflow

---

### Phase 0 — Environment Setup, Context Generation & Synthesis
**Agent:** Throwaway AI + Python scripts
**Blocking:** No. Sub-stages produce per-module artifacts. Modules that pass proceed immediately
to worker assignment while failed modules wait for human resolution in parallel.

Phase 0 produces per-module artifact files (not one monolithic JSON) plus shared artifacts:

```
/workspace/phase0_artifacts/
├── shared/
│   ├── context_artifact.json          # full project: hierarchy, signal flow, trust map
│   ├── netlist/                       # Yosys synthesis outputs
│   │   └── <module>.json             # per-module netlist slice
│   └── ast_cache/                    # Slang AST dumps, one file per module
│
├── per_module/
│   └── <module_name>/
│       ├── invocation_map.json        # per-module, per-tool, validated commands
│       ├── validation_status.json     # VALIDATED / PARTIAL / NEEDS_STUB / FAILED
│       └── stubs/                    # any stubs created for this module (never in source)
│
└── fuzzing_candidates.json           # Throwaway AI's recommended modules for Phase 3b
```

**Why per-module files instead of one monolithic map:**
Python can read and route `per_module/uart_core/invocation_map.json` to exactly the worker
assigned to `uart_core` without loading or passing the entire project's invocation data. Workers
never see invocation data for modules they are not assigned to.

---

#### Sub-stage 0.1 — Dependency Graph Resolution (Python + Throwaway AI)

**Python first:** A Python script statically scans all files for `import`, `` `include ``,
module instantiation references, and package declarations. It builds a raw dependency graph
without AI involvement — this is text parsing, not reasoning.

**Throwaway AI second:** Reviews the Python-produced graph for anything that requires
interpretation (ambiguous include paths, parameterized instantiations, conditional compilation
blocks) and resolves them. Produces the final dependency map that feeds Sub-stage 0.2.

This split keeps AI out of mechanical text-scanning work while using it where interpretation
is genuinely needed.

---

#### Sub-stage 0.2 — Tool Validation (Python executes, non-blocking per module)

Python runs validation for every module × tool combination using the dependency map from 0.1.
This is fully automated Python — no AI involved in running the checks.

**Validation result states:**

```
VALIDATED        tool ran successfully, output captured
PARTIAL          ran with non-blocking warnings, noted
NEEDS_STUB       missing primitive; Python auto-generates a minimal stub in
                 /phase0_artifacts/per_module/<module>/stubs/ and retries
TOOL_UNAVAILABLE binary missing or version incompatible; flagged to GUI
FAILED           error persists after 3 Python retry attempts (each with
                 a different flag combination); flagged to GUI
```

**Non-blocking failure handling:**
When a module × tool combination hits TOOL_UNAVAILABLE or FAILED after 3 attempts:
- Python writes a `failure_report.json` for that specific combination (exact commands tried,
  exact error outputs for all three attempts, hypothesis about cause).
- GUI surfaces the failure immediately with the full report visible.
- **That specific module × tool combination waits for human resolution.**
- **All other modules and tools continue processing without pause.**
- Human resolves (or explicitly waives) the failure; Python resumes that specific combination.
- Pipeline never stops globally because one module has a tool issue.

**Per-module invocation map entry (worker can modify flags freely):**

```json
{
  "module": "uart_core",
  "slang": {
    "base_command": "slang --lint-only",
    "files": [
      "hw/ip/uart/rtl/uart_core.sv",
      "hw/ip/uart/rtl/uart_rx.sv",
      "hw/ip/uart/rtl/uart_tx.sv"
    ],
    "include_paths": [
      "/home/user/opentitan/hw/ip/uart/rtl/",
      "/home/user/opentitan/hw/ip/prim/rtl/"
    ],
    "required_companions": ["uart_rx.sv", "uart_tx.sv"],
    "stubs_required": [],
    "status": "VALIDATED",
    "validation_output_summary": "0 errors, 2 warnings",
    "worker_note": "base_command is a validated starting point — worker may
                    add or change flags as analysis requires (e.g. --error-limit 0,
                    --allow-use-before-declare). Include paths and companion
                    files must be preserved."
  },
  "verilator": { "...": "..." },
  "verible":   { "...": "..." },
  "symbiyosys": { "...": "..." }
}
```

**Worker command flexibility:** The `base_command` is a validated starting point. Workers may
add flags, change options, or try different configurations as their analysis requires. They must
preserve the include paths and companion files (since those are correctness requirements, not
style choices). They are not locked to the exact command as validated.

---

#### Sub-stage 0.3 — Context Generation (Throwaway AI)

Throwaway AI uses the Slang AST (produced during 0.2 validation runs, cached to
`ast_cache/<module>.json`) to generate `context_artifact.json`:

- Module hierarchy tree
- Signal flow graph (across the full design)
- Port and interface map per module
- Instantiation map
- Clock domain map
- Trust boundary map
- Secret signal tagging (by naming convention: `key`, `secret`, `password`, `priv`,
  `credential`; and by any trust annotations in design documentation)
- Per-module compressed summaries (used by Python when giving workers their neighbor-reference
  context — workers load summaries of neighbors, not full neighbor source)

The context artifact is **indexed and sectioned**. Python extracts and delivers only the relevant
slice to each worker. No worker loads the full context artifact.

---

#### Sub-stage 0.4 — Shared Synthesis (Python runs Yosys, Throwaway AI interprets)

Python runs Yosys synthesis on the full design. Python parses the output and splits it into
per-module netlist slices stored in `netlist/<module>.json`. Throwaway AI reviews the synthesis
log for security-relevant synthesis transformations (e.g., constant-time comparisons being
optimized into non-constant-time implementations) and annotates findings into the relevant
per-module context slices.

---

#### Sub-stage 0.5 — Fuzzing Candidate Recommendation (Throwaway AI, non-blocking)

Throwaway AI reviews the module hierarchy, trust boundaries, and signal flow graph and produces
`fuzzing_candidates.json` — a ranked list of modules recommended for Phase 3b coverage-guided
fuzzing, with reasoning per module (e.g., "aes_core: crypto core handling key material,
high-value fuzzing target").

This recommendation is surfaced to the human in the GUI as a checklist — pre-populated with the
Throwaway AI's selections but fully editable. Human can add, remove, or reorder modules.

**This is non-blocking.** The GUI presents the checklist and human can update it at any time
before Phase 3b begins. All other phases continue without waiting.

**Throwaway AI is discarded after Sub-stage 0.5.**

---

### Python Orchestrator — Module Assignment

After Phase 0, Python reads all `per_module/<module>/validation_status.json` files and
`context_artifact.json`. It assigns modules to workers based on the following — **no AI
involved:**

- Modules are grouped by their position in the hierarchy (parent + children assigned together
  where possible) to maximize each worker's ability to reason about cross-module signal flow
  within its assignment
- Primary files: full source, deep analysis target
- Neighbor files: Python delivers the compressed per-module summary from `context_artifact.json`
  — not the raw source. Raw neighbor source is available on-demand if a worker explicitly
  requests it, not pre-loaded
- Python writes a `worker_manifest.json` per worker into their sandbox directory:
  which modules they are assigned, where their invocation maps are, where their output goes,
  which modules are their neighbors

Python tracks all worker states (queued / running / stuck / done) in a
`pipeline_state.json` updated in real time — this is what the GUI reads, not an AI summary.

---

### Phase 1 — Worker Static Analysis (parallel, isolated)
**Agent:** Workers, in parallel
**Orchestration:** Python (state tracking, retry counting, finding ingestion, deduplication)

Each worker receives its `worker_manifest.json` and the relevant slices from Phase 0 artifacts.
Workers run the following sub-stages against their assigned primary files.

| Stage | Tool | Who runs it | Finding Confidence Tier |
|---|---|---|---|
| 1 | Verible | Worker (Python counts retries) | TOOL_DETECTED |
| 2-static | Verilator + iverilog lint-only | Worker (Python diffs outputs) | TOOL_DETECTED |
| 1.5 | AI manual review — 3 focused passes | Worker AI | AI_PATTERN_MATCH |
| 6 | SymbiYosys + Boolector/Z3 | Worker (Python runs solver) | FORMALLY_PROVEN |
| 7 | Custom IFT (Python graph traversal) | Python (AI interprets results) | TOOL_DETECTED |

**Cross-simulator divergence** (Verilator vs. iverilog output differences) is detected by Python
mechanical diff — no AI needed to detect the divergence, only to interpret its security
significance. Divergence findings are tagged `SIMULATOR_DIVERGENCE`.

---

#### Stage 1.5 — AI Manual Code Review (3 separate passes)

After tool stages complete, the worker AI reads the pre-processed source (comment-stripped,
security keywords preserved) and all tool findings already collected. Three separate, focused
prompts — not one large prompt — reduce hallucination risk and token consumption:

- **Pass 1 — Security patterns:** hardcoded values and credentials, debug backdoors, privilege
  bypasses, illegal or unreachable FSM states, anomalous logic cones suggesting hardware trojans
- **Pass 2 — Logic correctness:** uninitialized registers in security-critical paths, race
  conditions in handshake protocols, address decode errors, missing reset conditions
- **Pass 3 — Trust boundary check:** given this module's trust level from the context slice,
  does it safely handle inputs from lower-trust modules?

Each pass explicitly receives the list of findings already found by tools so it does not
re-report them. Findings from this stage carry confidence tier `AI_PATTERN_MATCH` and are
subject to the most rigorous hallucination checking in Phase 4.

---

#### Stage 6 — Formal Verification

Worker AI authors SVA security properties for its assigned modules (e.g.,
`assert property (@(posedge clk) !(debug_out == secret_key));`). Python runs SymbiYosys
with Boolector or Z3. Python captures and parses the solver output. Worker AI interprets
counterexample traces. A counterexample trace is itself a working exploit demonstration and
is stored directly in the finding's `demonstration/` folder. Confidence tier: `FORMALLY_PROVEN`
— the highest in the pipeline.

---

#### Stage 7 — Information Flow Tracking

Entirely Python graph-traversal code operating on the signal_flow_graph from
`context_artifact.json`. For every secret-tagged signal, Python traces forward through
assign/always blocks and flags any path reaching an output port or a lower-trust module
boundary. Worker AI receives the Python-produced flagged paths and interprets whether each
is an unintended leak or an intentional, properly-gated export. AI interprets; Python finds.

---

#### Exploit Development

Every finding from every sub-stage gets an exploit and demonstration before the worker moves
to Phase 2. This is not deferred. Exploits drive the DUT externally (stimulus only — never
RTL modification).

---

#### Finding Deduplication (Python, continuous)

As each worker produces findings, Python immediately checks them against the global
`findings_registry.json` before writing them. Deduplication key: `(file, line_range, weakness_class)`.

If a finding already exists (same file, overlapping lines, same weakness class) from a
different tool or a different worker's AI pass:
- The existing entry is updated with the additional source (e.g., both Verilator and AI
  independently flagged the same signal — this increases confidence, it doesn't create two entries)
- No duplicate finding is written to the registry
- The confidence tier of the finding is upgraded if the new source is higher-tier than the
  existing one (e.g., if AI found it first as `AI_PATTERN_MATCH` and then formal verification
  independently proves it, the tier becomes `FORMALLY_PROVEN`)

This runs continuously throughout Phase 1 and Phase 3, not only at report time.

---

#### CWE Lookup (Python, not AI)

When a worker identifies a finding's weakness class, Python handles the CWE API interaction:

```python
# Python CWE utility — called by worker via tool interface, not AI reasoning

def fetch_cwe(candidate_id: int) -> dict:
    # 1. Check local cache first (cwe_cache/<id>.json)
    # 2. If not cached: GET https://cwe-api.mitre.org/api/v1/cwe/weakness/<id>
    # 3. Cache the result
    # 4. Return compressed summary for AI consumption:
    return {
        "id": entry["CWE_ID"],
        "name": entry["Name"],
        "description": entry["Description"][:300],   # truncated — AI doesn't need full text
        "mitigations": [m["Description"][:200]        # first 200 chars per mitigation
                        for m in entry.get("Potential_Mitigations", {})
                                      .get("Mitigation", [])],
        "related_weaknesses": [r["CWE_ID"]
                                for r in entry.get("Related_Weaknesses", {})
                                              .get("Related_Weakness", [])]
    }
```

**Hard rule:** AI never states a CWE ID from memory. The worker AI proposes a candidate ID;
Python fetches and verifies it; Python returns the compressed summary; AI uses the verified
data. CWE-1194 (hardware weakness root) and its full descendant tree are pre-fetched and cached
at pipeline startup by Python — this covers the majority of hardware security findings and
eliminates repeated API calls for common CWE IDs.

Master AI also re-verifies every cited CWE ID in Phase 4 as part of hallucination checking.

---

### Phase 2 — Testbench Authoring & Simulation Coordination
**Agents:** Workers author testbenches; Python compiles and runs simulation; workers interpret

**One testbench per worker.** Each worker authors a single cocotb testbench file covering all
its assigned modules. Python compiles the full design with all worker testbenches together
(simulation requires whole-design compilation).

**Testbench error handling (Python-managed, 3-attempt limit):**
1. Python attempts to compile the full design + all testbenches.
2. If compilation fails, Python parses the error output and routes the relevant error
   (with file and line reference) to the specific worker whose testbench caused it.
3. Worker has 3 attempts to fix the testbench error. Python counts attempts.
4. If error persists after 3 attempts: Python writes a detailed error report (all 3 attempts,
   all error outputs), surfaces it to the GUI, and pauses that specific worker's testbench.
5. Other workers' testbenches that compiled cleanly are not affected — simulation proceeds
   with the passing testbenches while human resolves the failing one.
6. Human reviews, optionally injects context, resumes the specific worker.

Python runs the simulation (Verilator primary, iverilog cross-check) and routes relevant
waveform slices and log output back to each worker for interpretation.

---

### Phase 3a — Worker Dynamic Analysis (parallel)
**Agent:** Workers, in parallel

- Workers interpret their waveform slices and simulation logs.
- Cross-simulator divergence is mechanically detected by Python (Verilator vs. iverilog diff)
  and flagged as a `SIMULATOR_DIVERGENCE` finding for the worker to interpret.
- cocotb directed tests target both confirmed static findings (dynamic confirmation) and
  known hardware vulnerability classes only observable at runtime.
- GTKWave trace inspection on anomalous behavior — visual confirmation for timing side-channel
  indicators, unexpected FSM state transitions, etc.
- Exploit development for every dynamic finding.
- Python deduplication runs continuously as findings come in.

---

### Phase 3b — Coverage-Guided Fuzzing (opt-in, human-confirmed, non-blocking)
**Agents:** Python (execution) + Workers (interpretation)

Python uses Verilator's `--coverage` output to steer test generation toward unexplored
branches and FSM states. This targets deep security bugs — privilege escalation paths,
unreachable-looking backdoors — that directed simulation misses.

**Module selection process (non-blocking):**
- Throwaway AI's `fuzzing_candidates.json` recommendation (from Phase 0.5) is displayed
  in the GUI as a pre-populated checklist with reasoning visible per module.
- Human reviews, approves, modifies the list at any time.
- The checklist can be updated while Phases 1, 2, and 3a are running — human is not forced
  to decide before other work completes.
- Phase 3b begins only after human confirms the final module list.

Iterative loop: simulate → Python measures coverage → Python generates new stimulus targeting
uncovered paths → repeat until iteration or time budget exhausted. Reference: TheHuzz.

---

### Phase 4 — Master Verification & Exploit Chaining
**Agent:** Master AI (activated after all worker phases complete)
**Support:** Python (reads source code, does mechanical comparisons, routes data)

#### Hallucination / Ground-Truth Check

For every finding in `findings_registry.json`:

1. Python reads the actual source code at the reported `file` + `line_range` and passes
   it to Master AI alongside the finding's claim. Master AI does not search for the code
   itself — Python provides it.
2. Master AI determines:
   - **VERIFIED** — code at those lines matches the described bug → finding passes to
     human review queue
   - **HALLUCINATION_SUSPECTED** — code does not match the claim → Master AI writes a
     side-by-side (worker's claim vs. actual code); Python flags the finding in the registry;
     GUI surfaces it in the "Requires Human Review" section
   - **NEEDS_HUMAN_REVIEW** — Master AI cannot confidently verify or refute → escalated
     to human with both the code and the claim visible side by side

3. For HALLUCINATION_SUSPECTED findings: Python automatically reduces scope (extracts just
   the specific code section + the original finding) and queues it for optional Re-Check AI
   invocation. **Re-check is not automatic** — it appears in the GUI as a button the human
   can press per finding. Human decides whether to trigger it.

4. CWE ID re-verification: Python re-fetches the CWE entry for every cited ID and Master AI
   confirms the description matches the finding. CWE-mismatch hallucinations (correct-sounding
   but wrong CWE number) are flagged separately from content hallucinations.

#### Deduplication Final Pass

Python runs a final deduplication pass on the full findings registry before Master AI
assembles the report — catching any cross-phase duplicates that slipped through the
continuous deduplication during Phases 1 and 3.

#### Exploit Chaining

Master AI analyzes connections across verified findings from all workers using the
signal_flow_graph (provided by Python from `context_artifact.json`). It constructs
cross-module exploit chains — multi-step attack paths that no individual worker could
have assembled because each worker only sees their own module slice.

Example pattern:
```
Step 1: Debug register accessible without privilege check (Worker 1's module)
     ↓  signal: debug_sel reaches uart_core from soc_top without gating
Step 2: Debug mode enables raw key output path (Worker 2's module)
     ↓  signal: key_out_debug not gated by secure_boot_done
Step 3: Key material reaches external debug port (Worker 3's module)
     Result: full key extraction via JTAG interface
```

Exploit chain verification is assigned back to the relevant workers as targeted follow-up tasks.

---

### Phase 5 — Final Report Generation
**Agent:** Master AI assembles; Python generates the report file

See Section 6 for full report structure.

---

## 4. Re-Check AI — On-Demand Per-Finding Re-Analysis

**Triggered:** Human clicks "Re-check this finding" on any hallucination-flagged or
disputed finding in the GUI.

**What it receives (Python prepares this package):**
- The specific finding JSON
- The exact source code at the reported file and line numbers
- The original worker's reasoning (from the finding's `bug_report.md`)
- The Master AI's hallucination note (why it was flagged)

**What it does:**
- Re-analyzes only this one finding from scratch
- Either confirms it (with clearer reasoning), refutes it, or reclassifies it
- Writes its conclusion to the finding's record

**What it does not do:**
- It does not have access to any other findings
- It does not have access to any other source files
- It is not asked to look for additional bugs

Discarded after completing the single finding re-analysis.

---

## 5. Cross-Cutting Systems

### 5.1 Worker Isolation

```
/workspace/worker_N/
├── input/                    # assigned files — READ-ONLY (OS-level)
├── context_slice/            # Python-extracted slice of context_artifact.json
├── invocation_maps/          # per-module invocation maps for assigned modules only
├── terminal/                 # isolated bash environment
├── scratch/                  # worker's own space: stubs, helpers, temp files
│                               (never contains RTL source)
└── output/
    └── findings/
        └── finding_XXX/
            ├── finding.json          # structured finding data
            ├── bug_report.md         # full explanation
            ├── cwe_info.json         # Python-fetched, pre-compressed CWE data
            ├── suggested_fix.md      # root cause + fix description + illustrative diff
            ├── exploit/
            │   ├── exploit.py        # cocotb-based attack stimulus
            │   └── exploit.sv        # SVA-based where appropriate
            └── demonstration/
                ├── run.sh            # single command to reproduce
                ├── simulation.log    # captured output
                └── waveform.vcd      # visual proof
```

RTL source files are mounted read-only at the OS level. This is not a convention — it is
architecturally enforced.

### 5.2 RTL Read-Only Error Handling

When a tool encounters an error against read-only source, workers follow a fixed decision
tree and do not loop:

1. **Missing include/package** — use the include paths in the invocation map; if still
   missing, search the project tree, add the path, retry.
2. **Missing primitive/cell** — create a stub in `scratch/` (never in source), update the
   command to reference it, rerun. Note stub usage explicitly in the finding report.
3. **Tool version/syntax incompatibility** — try the alternate tool listed in the invocation
   map (e.g., iverilog fallback for Verilator).
4. **Unresolvable after 3 attempts** — write exactly what was tried and what failed, mark
   the file/finding as `PARTIAL_ANALYSIS`, move on.

### 5.3 Anti-Loop / Human-in-the-Loop Mechanism

Python counts all retry attempts — not AI. The AI never tracks its own attempts.

- **MAX_ATTEMPTS = 3** per tool invocation, counted by Python
- **Stuck detection:** Python detects same command + same error repeating
- **On 3rd failure:** Python collects all three attempt records (command, flags used,
  full error output) and writes a `stuck_report.json`. GUI surfaces the alert immediately.
- Worker pauses. Does not retry.
- Human reviews all three attempts in the GUI, optionally injects context, chooses:
  Resume (attempt counter resets) / Skip / Reassign to fresh worker instance.

This mechanism applies identically in Phase 0, Phase 1, Phase 2, Phase 3a, and Phase 3b.

### 5.4 Python Responsibilities (full list)

The following are never done by AI — Python only:

- File system operations (copy, route, read, write)
- Module-to-worker assignment
- Worker state tracking (`pipeline_state.json`)
- Retry attempt counting
- Tool command execution (workers instruct via structured requests; Python executes)
- Tool output capture and log compression (raw logs → structured JSON before AI sees them)
- Cross-simulator output diffing (Verilator vs. iverilog)
- IFT graph traversal on signal_flow_graph
- CWE API calls and response caching/compression
- Finding deduplication (continuous, keyed on `file + line_range + weakness_class`)
- Slang AST caching and slice extraction
- Worker manifest generation and delivery
- GUI state updates

### 5.5 Comment Pre-Processing (Python)

Before any file reaches a worker, Python runs:

```
1. Strip single-line comments (//) except lines containing:
   SECURITY · FIXME · HACK · TODO · BUG · WORKAROUND · CRITICAL · BACKDOOR · DEBUG
2. Strip block comments (/* ... */) with same keyword exceptions
3. Strip blank lines
4. Normalize whitespace
```

Security-relevant annotations are preserved. Maintenance noise is eliminated. Reduces
file size passed to workers without losing security-critical documentation.

### 5.6 Tool Output Compression (Python)

Raw tool outputs are never passed to AI. Python pre-processes them:

```
Verilator raw output (hundreds of lines):
  "%Warning-UNUSED: rtl/aes.sv:45:8: Signal is not driven, ..."
  (repeated for every warning)

Python-compressed output (structured JSON):
  {
    "UNUSED_SIGNALS":    [{"file":"aes.sv","line":45,"signal":"debug_out"}, ...],
    "UNDRIVEN_SIGNALS":  [...],
    "CDC_VIOLATIONS":    [...],
    "LINT_ERRORS":       [...]
  }
```

AI receives the structured JSON. Token consumption drops dramatically. Pattern is applied
to Verilator, iverilog, Verible, SymbiYosys, and Yosys outputs.

### 5.7 CWE Integration

**All CWE API interactions are Python.** AI proposes; Python fetches and verifies;
Python returns a compressed summary; AI uses verified data.

```
Startup: Python pre-fetches full CWE-1194 descendant tree → cached locally
         (CWE-1194 = Hardware Design weakness root — covers most hardware findings)

Worker flow:
  1. Worker AI identifies weakness pattern, proposes candidate CWE ID
  2. Python: GET cwe-api.mitre.org/api/v1/cwe/weakness/{id}
  3. Python: compress response to ~400 tokens (id, name, description[:300],
             mitigations[:200 each], related IDs)
  4. Python: deliver compressed summary to worker
  5. Worker AI: confirms match or requests traversal to parent/child IDs
  6. If no match: finding marked CWE_UNMAPPED — never forced to wrong ID

Phase 4: Python re-fetches every cited CWE ID; Master AI re-verifies match
```

**Hard rule:** AI never writes a CWE ID that has not been Python-fetched and verified
in the same session.

### 5.8 GUI Dashboard (localhost)

FastAPI backend + lightweight HTML/JS frontend.

**Displays:**
- Real-time status of every worker and every phase
- Phase 0 tool validation results per module × tool (VALIDATED / PARTIAL / FAILED)
- Live finding feed as findings are registered, with confidence tier shown
- Per-worker terminal log (every command, every output, in real time)
- Click-to-jump to any flagged file and line number in source
- Fuzzing candidate checklist (pre-populated from Throwaway AI, editable by human)
- Hallucination-flagged findings with side-by-side code vs. claim view
- Re-check AI trigger button per hallucination-flagged finding

**Human control surfaces:**
- Pause / resume any individual worker
- Pause / resume entire pipeline
- Inject free-text context into any stuck worker or Phase 0 sub-stage
- Manually confirm or reject any finding
- Skip a specific phase for a specific worker
- Edit fuzzing module selection list at any time before Phase 3b begins
- Trigger Re-check AI for any hallucination-flagged finding
- Resume from any phase after manual intervention
- View exact tool commands for any module at any time

---

## 6. Tool Stack

| Stage | Tool | Who executes | Mode |
|---|---|---|---|
| Dependency scanning | Python (text parsing) | Python | Pre-analysis |
| Parsing / elaboration / AST | Slang | Python runs, AI interprets | Static |
| Style / lint | Verible | Python runs, AI interprets | Static |
| Simulation — primary | Verilator | Python runs, worker interprets | Static (lint) + Dynamic (sim) |
| Simulation — cross-check | iverilog | Python runs, worker interprets | Static + Dynamic |
| Scripted testbenches | cocotb (Python) | Worker authors, Python runs | Dynamic |
| Coverage-guided fuzzing | Verilator `--coverage` + Python steering | Python runs | Dynamic |
| Waveform inspection | GTKWave | Worker (on anomaly) | Dynamic / debug |
| Synthesis | Yosys | Python runs, Throwaway AI interprets log | Static / prep |
| Formal verification | SymbiYosys + Boolector / Z3 | Worker authors SVA, Python runs solver | Static / formal |
| IFT | Custom Python on Slang AST + signal flow graph | Python runs, worker AI interprets | Static |
| CWE classification | CWE REST API | Python only — never AI directly | Cross-cutting |
| Side-channel | **OUT OF SCOPE** | — | N/A |

**On side-channel analysis:** Power, EM, and physical timing side-channels cannot be assessed
by any RTL-level tool in this pipeline. This is explicitly stated in every final report.
Physical-level side-channel validation requires dedicated tooling (ChipWhisperer or equivalent)
on actual FPGA/silicon and is out of scope.

---

## 7. Finding & Report Structure

### Confidence Tiers

| Tier | Label | Source | Notes |
|---|---|---|---|
| 1 | **FORMALLY_PROVEN** | SymbiYosys counterexample | Mathematical proof — property violation proven across all reachable states. Counterexample trace = ready-made exploit. |
| 2 | **TOOL_DETECTED** | Verible / Verilator / iverilog / IFT | Deterministic. Reproducible. Not AI judgment. |
| 3 | **DYNAMICALLY_OBSERVED** | cocotb / coverage-guided fuzzing | Real simulation behavior — not static inference. |
| 4 | **AI_PATTERN_MATCH** | Stage 1.5 manual AI review | No tool or proof backing. Highest hallucination scrutiny in Phase 4. |

Tier is **upgraded** if multiple independent sources find the same issue (e.g., AI finds it
as tier 4; formal verification independently proves it → tier becomes 1).

### Per-Finding Schema

```
finding.json
├── id                     unique identifier (Python-assigned, sequential per worker)
├── file                   source file path (absolute)
├── line_range             [start_line, end_line] — verified against source in Phase 4
├── title                  short descriptive title
├── confidence_tier        FORMALLY_PROVEN | TOOL_DETECTED |
│                          DYNAMICALLY_OBSERVED | AI_PATTERN_MATCH
├── analysis_type          STATIC | DYNAMIC
├── sources[]              all tools/passes that independently found this issue
│                          (populated by Python deduplication — shows corroboration)
├── cwe
│   ├── id                 Python-fetched and verified — never from AI memory
│   ├── name               from API
│   ├── description        from API (compressed by Python)
│   └── mapping_confidence EXACT | CLOSEST_ANCESTOR | UNMAPPED
├── hallucination_check    VERIFIED | HALLUCINATION_SUSPECTED | NEEDS_HUMAN_REVIEW | PENDING
└── recheck_result         null | CONFIRMED | REFUTED | RECLASSIFIED
                           (populated only if Re-check AI was triggered)

bug_report.md
├── What the bug is
├── Where it is (file, lines, code excerpt — exact quote from source)
├── Why it is a security concern
└── How it was found (tool name / AI pass)

suggested_fix.md
├── Root cause (2–3 sentences)
├── Recommended fix approach
├── Illustrative code diff — clearly marked ILLUSTRATIVE ONLY / NOT APPLIED TO SOURCE
├── Trade-offs of the fix
└── CWE-recommended mitigations (from API mitigation field, Python-fetched)

exploit/
├── exploit.py   (cocotb-based — drives DUT inputs externally, never modifies RTL)
└── exploit.sv   (SVA-based where appropriate, e.g. for formal counterexample replays)

demonstration/
├── run.sh              single command to reproduce
├── simulation.log      captured output showing the bug triggered
└── waveform.vcd        visual proof, viewable in GTKWave
```

### Final Report Contents (Phase 5 output)

- Executive summary: total findings by tier, by module, by weakness class
- All findings, grouped by confidence tier (1→4), sorted by severity within each tier
- Every finding includes: bug report, CWE mapping, suggested fix, exploit, and demonstration
- Cross-module exploit chains documented as a dedicated section with full kill-chain paths
- Hallucination-flagged findings in a "Requires Human Review" section with side-by-side
  code vs. claim comparisons and Re-check AI results where triggered
- Simulator divergence findings documented separately
- Phase 0 tool validation summary: what validated, what failed, what stubs were used
- Explicit out-of-scope statement: side-channel analysis (power/EM/physical timing)
  was not performed by this pipeline

---

## 8. Deferred / Pending

- **Exact finding and inter-agent JSON schemas** — working draft in Section 7;
  final version pending research partner input.
- **Coverage-guided fuzzing steering logic** — scoped as its own build; informed by TheHuzz.
- **Custom IFT tool** — genuine build project; no off-the-shelf equivalent.
  Reuses signal_flow_graph from Phase 0.
- **Prompt templates** — per agent type; deferred until schemas and tool integrations are
  complete.

---

## 9. Recommended Build Order

1. **Python pre-processing pipeline** — comment stripper (keyword-aware) + tool output
   compressor (raw logs → structured JSON). No dependencies on anything else. Build first.

2. **Phase 0 dependency scanner + tool validation** — Python dependency graph builder +
   per-module invocation map generator + tool health check runner. Validates real-world
   tool environment before any AI logic is built on top of it.

3. **CWE API wrapper** — Python utility with local caching. Pre-fetch CWE-1194 subtree
   at startup. Build early since every finding depends on it.

4. **Context artifact generator** — Slang integration, module hierarchy, signal flow graph,
   secret signal tagging, per-module summary generation.

5. **Python orchestrator** — worker manifest generation, state tracking (`pipeline_state.json`),
   finding registry with continuous deduplication, GUI state updates. This is the backbone
   everything else plugs into.

6. **GUI skeleton** — FastAPI + minimal frontend. Build before worker parallelization so
   you can observe the system from the beginning, not as an afterthought.

7. **Single worker, end-to-end, static analysis only** — prove the full pipeline (Phase 0
   artifacts → worker → finding with exploit + CWE + suggested fix) on one worker before
   any parallelization.

8. **Worker parallelization** — once single-worker pipeline is proven stable.

9. **Dynamic analysis pipeline** — Phase 2 + Phase 3a (testbench compilation, simulation
   coordination, waveform routing).

10. **Master AI** — hallucination checking, exploit chaining, final report assembly
    (Phase 4 + Phase 5). Activated last because it depends on all worker output existing.

11. **Re-check AI** — small addition once Master AI is working; hooks into existing
    finding registry and GUI.

12. **Formal verification** — SymbiYosys + Boolector/Z3, SVA property generation (Stage 6).

13. **IFT tool** — custom Python graph traversal (Stage 7).

14. **Coverage-guided fuzzing** — Phase 3b, last, most research-heavy component.
