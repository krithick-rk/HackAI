# V2 Architecture Migration Status & Implementation Note

## 1. Audit Summary

The repository currently contains the **Phase 0** foundation of the SoC Hardware Security Analyzer, including SystemVerilog dependency scanning, FuseSoC resolution for OpenTitan, multi-tool validation (Slang, Verilator, Verible), comment stripping with whitespace preservation, log compression, Yosys synthesis orchestration, and a FastAPI + Svelte dashboard.

The V2 target architecture transitions the system from the initial experimental multi-agent hierarchy into a deterministic, Python-authoritative hardware security verification pipeline with a centralized AI Gateway, deterministic structural detectors (Channel D), triaged tool diagnostics (Channel T), bounded AI hypothesis generation (Channel A), Python grounding, three-valued reachability reasoning, and a witness replay engine.

---

## 2. Existing Components

| Component | Path | Current Status & Capabilities |
|---|---|---|
| **Dependency Scanner** | `src/soc_analyzer/phase0/dependency_scanner.py` | Regex/token-based AST scanner, module/package discovery, include directives, generate/ifdef block detection. |
| **FuseSoC Resolver** | `src/soc_analyzer/phase0/fusesoc_resolver.py` | OpenTitan core resolution via FuseSoC, file ordering, include path extraction, top-level detection. |
| **Invocation Map Builder** | `src/soc_analyzer/phase0/invocation_map_builder.py` | Generates tool command templates for Slang, Verilator, and Verible. |
| **Tool Validator** | `src/soc_analyzer/phase0/tool_validator.py` | Subprocess execution with retries, stub generation for missing primitives, diagnostic categorization (missing deps, version drift, genuine findings). |
| **Context Generator** | `src/soc_analyzer/phase0/context_generator.py` | Hierarchy tree, port/signal extraction, trust boundary map, secret signal keyword tagging. |
| **Synthesis Orchestrator** | `src/soc_analyzer/phase0/synthesis_orchestrator.py` | Yosys synthesis execution, netlist slicing, gate-level inspection. |
| **Fuzzing Recommender** | `src/soc_analyzer/phase0/fuzzing_recommender.py` | Heuristic scoring of netlist slices based on cell complexity and security keywords. |
| **Comment Stripper** | `src/soc_analyzer/preprocessing/comment_stripper.py` | Strips comments while strictly maintaining line numbers and column offsets; preserves security keywords. |
| **Log Compressor** | `src/soc_analyzer/preprocessing/log_compressor.py` | Regex-based compiler error and warning extraction. |
| **Config Manager** | `src/soc_analyzer/dashboard/config_manager.py` | Project config persistence and duplicate resolution tracking. |
| **Dashboard API Server** | `src/soc_analyzer/dashboard/server.py` | FastAPI backend with endpoints for folder browsing, scanning, running validation, log streaming, and synthesis status. |
| **Dashboard GUI** | `gui/src/` | Svelte + Vite web interface with folder tree picker, module validation status badges, log modals, and synthesis viewer. |
| **CLI Validation Runner** | `verify_pipeline.py` | CLI entry point for Phase 0 execution across designs. |
| **Schemas** | `src/soc_analyzer/common/schemas.py` | TypedDict schemas for logs, invocation maps, and tool details. |
| **Filesystem Utils** | `src/soc_analyzer/common/fs_utils.py` | Atomic and recursive JSON artifact read/write helpers. |

---

## 3. Components to Modify

| Component | Target File(s) | Required Changes |
|---|---|---|
| **Tool Validator Bugfix** | `src/soc_analyzer/phase0/tool_validator.py` | Remove premature `verilator` unconditional `PARTIAL` override that breaks `test_tool_validator_happy_path` and `test_tool_validator_needs_stub`. |
| **Schemas** | `src/soc_analyzer/common/schemas.py` | Add V2 schemas: `TaskPacket`, `Finding`, `EvidenceAtom`, `AnalyzabilityReport`, `RegistryEntry`, `WitnessSpec`, `LedgerEntry`. |
| **Tool Invocation / Channel T** | `src/soc_analyzer/phase0/tool_validator.py` | Feed genuine tool diagnostics cleanly into Channel T candidate channel. |
| **Dashboard Server** | `src/soc_analyzer/dashboard/server.py` | Expose endpoints for V2 findings, evidence inspection, analyzability rating, budget status, and AI usage ledger. |
| **Dashboard UI** | `gui/src/App.svelte` | Add views for V2 finding cards (CANDIDATE through CONFIRMED), evidence atoms, analyzability, and cost ledger. |
| **CLI Entry Point** | `src/soc_analyzer/cli.py` / `verify_pipeline.py` | Implement unified `soc-analyzer scan <path>` CLI conforming to section 22. |

---

## 4. Components to Add (V2 Architecture)

### Stage 1: Front End / `design_db`
- `src/soc_analyzer/design_db/slang_elaborator.py`: Slang elaboration driver producing authoritative AST and design facts.
- `src/soc_analyzer/design_db/source_snapshot.py`: Source line mapping, canonical source hashing, byte/line offset preservation.
- `src/soc_analyzer/design_db/config_discovery.py`: Shipped-configuration discovery (e.g., Earl Grey ASIC, Darjeeling ASIC, English Breakfast).
- `src/soc_analyzer/design_db/connectivity_graph.py`: Guarded module-level connectivity graph with parameter resolution, tie-offs, and clock/reset facts.
- `src/soc_analyzer/design_db/register_overlay.py`: HJSON register overlay integrating OpenTitan register and field definitions, access locks, and permissions.
- `src/soc_analyzer/design_db/analyzability.py`: Deterministic assessment (`NORMAL`, `DEGRADED`, `HIGHLY_OBFUSCATED`) based on elaboration success, identifier informativeness, and flattening.

### Stage 2: Registries
- `src/soc_analyzer/registries/store.py`: Small, explicit registries for attacker classes, protected assets, and declassifiers (YAML/JSON with provenance).
- `src/soc_analyzer/registries/proposals.py`: Python gating for AI `PROPOSE_REGISTRY` proposals (marked unapproved until human acceptance).

### Stage 3: AI Gateway & Budget
- `src/soc_analyzer/ai_gateway/gateway.py`: Centralized `call(task_type, task_packet, tier)`.
- `src/soc_analyzer/ai_gateway/task_packet.py`: Immutable task packets with bounded excerpts, schema, and budget slice.
- `src/soc_analyzer/ai_gateway/adapters/`:
  - `terminal_claude.py`, `terminal_codex.py`, `terminal_gemini.py`: CLI adapters running without API keys.
  - `direct_api.py`: Configurable direct API backend (disabled by default).
- `src/soc_analyzer/ai_gateway/budget_manager.py`: Run/module budgets, per-call cap, token limits, concurrency control, and validation reserve.
- `src/soc_analyzer/ai_gateway/cache.py`: Exact-match cache keyed on `(task_type, packet_hash, prompt_version, model_id)`.
- `src/soc_analyzer/ai_gateway/usage_ledger.py`: Per-call accounting of tokens, cost, latency, backend, and outcome.
- `src/soc_analyzer/ai_gateway/sandbox.py`: Security isolation for terminal workers (read-only source, scratch dirs).

### Stage 4: Candidate Sources
- `src/soc_analyzer/candidates/channel_d.py`: Deterministic structural detectors (missing lock/access guard, unsafe reset, constant security key, debug/test gating, FSM issues, dead checks, decode overlap, sibling-guard asymmetry, unreset state).
- `src/soc_analyzer/candidates/channel_t.py`: Triaged tool warnings (Slang, Verilator, Verible).
- `src/soc_analyzer/candidates/channel_a.py`: Bounded security-cone AI hypothesis generator with strict schema and `NO_FINDING` support.

### Stage 5: Grounding & Reachability
- `src/soc_analyzer/grounding/grounder.py`: Python verification of file, line range, AST/symbol identity, configuration, instance path, source quote, and bounded re-anchor.
- `src/soc_analyzer/reachability/engine.py`: Three-valued reasoning (`PASS`, `FAIL`, `UNKNOWN`) where UNKNOWN never becomes FAIL, with Z3 solver integration and attacker provenance.

### Stage 6: Finding State Model & Adjudication
- `src/soc_analyzer/findings/state_model.py`: States `CANDIDATE` -> `GROUNDED` -> `REACHABLE` -> `REPRODUCED` -> `CONFIRMED`; parked lanes (`PROBABLE`, `LEAD`, `WEAKNESS_ONLY`); terminal negatives (`REFUTED`, `UNREACHABLE`, `DUPLICATE`).
- `src/soc_analyzer/findings/evidence_store.py`: Structured evidence atoms (G, W, O, C, P, A1, A2, A3, F).
- `src/soc_analyzer/findings/dedup.py`: Definition-space + instance-manifestation deduplication with evidence merging.
- `src/soc_analyzer/findings/cwe_map.py`: Deterministic Python CWE mapping.

### Stage 7: Witness Engine & Generic Harness
- `src/soc_analyzer/witness/engine.py`: DV asset reuse scanner (`dv/`, `pre_dv/`), Verilator/cocotb/SymbiYosys execution, witness replay, trace capture.
- `src/soc_analyzer/witness/generic_harness.py`: Bus-IP harness classifying clock, reset, bus, alert, lifecycle, OTP, pin, and interrupt signals.

### Stage 8: Benchmark
- `src/soc_analyzer/benchmark/suite.py`: ~20 seeded benchmark cases (vulnerabilities, false positives, unreachable cases, obfuscated variants).
- `tests/test_invariants.py`: Invariant regression testing ensuring `UNKNOWN -> FAIL` never occurs.

### Stage 9: Reporting & CLI
- `src/soc_analyzer/reporting/generator.py`: Generates `report.json`, `report.html`, and evidence packages.
- `src/soc_analyzer/cli.py`: Unified `soc-analyzer scan` CLI.

---

## 5. Components to Remove / Deprecate

1. **Direct HTTP AI Calls**:
   - `src/soc_analyzer/phase0/failure_repairer.py`: Deprecate `call_llm_for_repair` in favor of `ai_gateway`.
   - `src/soc_analyzer/phase0/context_generator.py`: Deprecate `call_llm_fallback` in favor of `ai_gateway`.
   - `src/soc_analyzer/phase0/synthesis_orchestrator.py`: Deprecate `call_llm_for_synthesis_interpretation` in favor of `ai_gateway`.
2. **Hardcoded Credentials & Environment Key Assumptions**:
   - Eliminate direct checks for `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `OPENAI_API_KEY` in business logic; move configuration to `config.yaml` with providers disabled by default.
3. **One-Off Patch Scripts**:
   - `patch_array.py`, `patch_ibex_pkg.py`, `patch_remove_preproc.py`, `patch_script.py`, `patch_synthesis.py`: Keep archived or remove from active paths; integrate necessary fixes directly into the codebase.

---

## 6. CURRENT -> V2 Architecture Mapping

| Current V1 Subsystem | V2 Target Component | Primary Change |
|---|---|---|
| Text-based `dependency_scanner` | `design_db` (Slang Elaboration) | Upgraded to authoritative Slang AST, original line hashing, parameter resolution, and definition<->instance map. |
| Heuristic module discovery | `shipped-config detection` | Discovers top-level chip targets (Earl Grey, Darjeeling, etc.) via configuration without hardcoded paths. |
| No analyzability check | `analyzability.py` | Deterministic `NORMAL` / `DEGRADED` / `HIGHLY_OBFUSCATED` per security cone. |
| Ad-hoc regex keywords | `registries/store.py` | Explicit YAML/JSON registries for attacker classes, protected assets, declassifiers. |
| Compiler errors / warnings | Candidate Channels D, T, A | Channel D (structural detectors), Channel T (triaged tools), Channel A (AI hypotheses with strict schema). |
| Unverified LLM outputs | `grounding/grounder.py` | Python-enforced AST, line range, and symbol identity grounding before any finding advances. |
| Unchecked reachability | `reachability/engine.py` | Three-valued logic (`PASS`, `FAIL`, `UNKNOWN`) with Z3; UNKNOWN never becomes FAIL. |
| No witness engine | `witness/engine.py` | Independent simulation harness, DV reuse, Verilator/cocotb/sby replay, seed and trace storage. |
| Direct HTTP calls to APIs | `ai_gateway/gateway.py` | Centralized gateway: terminal-first adapters, API fallback, budget manager, exact-match cache, usage ledger. |
| Flat finding dictionary | `findings/state_model.py` | Strict state machine (`CANDIDATE` to `CONFIRMED`), evidence atoms, and definition-instance dedup. |
| No benchmark suite | `benchmark/suite.py` | ~20 seeded benchmark cases measuring recall, precision, cost, and verifying invariants. |

---

## 7. Implementation Order

1. **Stage 1**: Front End / `design_db` & Analyzability Assessment
2. **Stage 2**: Registries (Attacker classes, assets, declassifiers, proposal gate)
3. **Stage 3**: AI Gateway, Budget Manager, Usage Ledger, Exact-Match Cache & Terminal Adapters
4. **Stage 4**: Candidate Sources (Channel D structural detectors, Channel T triage, Channel A hypothesis)
5. **Stage 5**: Python Grounding & Reachability / Provenance Engine (Z3)
6. **Stage 6**: Finding State Model, Evidence Store, Adjudication Policy & Deduplication
7. **Stage 7**: Witness Engine & Generic Bus-IP Harness
8. **Stage 8**: Benchmark Suite & Invariant Tests
9. **Stage 9**: Unified CLI (`soc-analyzer scan`), Reports & Dashboard Integration

---

## 8. Current Test Commands

Execute tests inside the `soc-security-analyzer` directory:

```bash
# Run full pytest suite using active environment
cd /home/hackdac/Documents/AI/hackAI/soc-security-analyzer
PYTHONPATH=. ~/.HACK_AI/bin/pytest tests/

# Run targeted test suites
PYTHONPATH=. ~/.HACK_AI/bin/pytest tests/preprocessing/
PYTHONPATH=. ~/.HACK_AI/bin/pytest tests/phase0/test_dependency_scanner.py
PYTHONPATH=. ~/.HACK_AI/bin/pytest tests/phase0/test_context_generator.py

# Build GUI frontend
cd gui && npm run build && cd ..

# Launch FastAPI dashboard
PYTHONPATH=. ~/.HACK_AI/bin/python3 -m src.soc_analyzer.dashboard.server
```

*Note on baseline tests:* In the current baseline, 25 tests pass and 2 tests in `tests/phase0/test_tool_validator.py` fail due to an unconditional `PARTIAL` status override for Verilator in `tool_validator.py`. Fixing this is scheduled as the immediate first modification before Stage 1 implementation.
