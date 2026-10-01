# SoC / RTL Hardware Security Analyzer & Web Application

An end-to-end hardware security auditing platform for System-on-Chip (SoC) and Register-Transfer Level (RTL) designs. The system combines deterministic static security property checking, Z3 SMT solver reachability analysis, simulation witness evaluation, and a provider-agnostic AI Gateway into a user-driven web application.

---

## 🚀 Key Features

* **Arbitrary Repository Ingestion**: Select and analyze any local SoC/RTL hardware repository (SystemVerilog, Verilog, C/C++) with zero hardcoded repository assumptions.
* **Dynamic Repository Discovery**: Automatically discovers file composition, detects hardware languages and config files, indexes all modules, and verifies toolchain readiness (Slang, Verilator, Z3).
* **Dynamic Module Inspector**: Real-time AST-based module extraction displaying source file locations, port signatures, child instance trees, and inferred clock/reset domains.
* **Multi-Stage Security Pipeline**:
  1. Repository Discovery & DesignDB construction
  2. Security assets & register extraction
  3. Deterministic static security detectors (Missing Regwen, Lock bypass, Shadow registers, etc.)
  4. Symbolic reachability analysis via Z3 SMT solver
  5. Witness reproduction and validation
  6. AI-assisted reasoning & remediation guidance
* **Human-Readable Findings**:
  * Plain-English explanation of **What is wrong** and **Why it matters**.
  * Visual **Attack Path** diagram.
  * Formal **Evidence** (Z3 SAT/UNSAT status, witness verification).
  * Specific **Recommended Fix** with side-effect warnings.
  * Interactive **Source Code Snippet Viewer** with safe range highlighting.
  * **Revalidate Finding** capability to test fixes against updated source code.
* **Provider-Agnostic AI Gateway**:
  * Configurable in UI: OpenAI, Anthropic Claude, Google Gemini, DeepSeek, Zhipu GLM, Moonshot Kimi, or Custom OpenAI-compatible endpoints.
  * Dynamic model selection and automatic task routing.
  * Secure server-side credential storage with masked keys and live connection latency testing.
  * **Resilient Execution**: Analysis continues without interruption using deterministic rules if AI providers are unreachable or unconfigured.
* **Comprehensive Reporting**: Generates downloadable machine-readable JSON and executive HTML security audit reports.

---

## 🖥️ Starting the Web Server

The web application runs on **http://localhost:8080**.

### Method 1: Using the Unified Analyzer CLI (Recommended)

From the `soc-security-analyzer` directory:

```bash
# Using the project Python virtual environment:
/home/hackdac/.HACK_AI/bin/python3 -m soc_analyzer server
```

With custom port or auto-reload:
```bash
/home/hackdac/.HACK_AI/bin/python3 -m soc_analyzer server --host 0.0.0.0 --port 8080 --reload
```

If your virtual environment is already activated (`source /home/hackdac/.HACK_AI/bin/activate`):
```bash
soc-analyzer server
```

---

### Method 2: Using Uvicorn Directly

```bash
cd soc-security-analyzer
/home/hackdac/.HACK_AI/bin/python3 -m uvicorn soc_analyzer.dashboard.server:app --host 0.0.0.0 --port 8080 --reload
```

---

### Method 3: Running in the Background (Daemon)

To start the server in the background:
```bash
nohup /home/hackdac/.HACK_AI/bin/python3 -m uvicorn soc_analyzer.dashboard.server:app --host 0.0.0.0 --port 8080 > server.log 2>&1 &
```

To stop a running background server:
```bash
pkill -f "soc_analyzer.dashboard.server:app"
```

---

## 🛠️ Building the Web Frontend

The frontend is built using Svelte, TypeScript, and Vite. Static assets are compiled into `gui/dist` and served automatically by the FastAPI backend.

```bash
cd gui
npm install
npm run build
cd ..
```

---

## 🔍 Command-Line Interface (CLI)

The repository provides a unified CLI for headless security analysis, validation, and benchmarking:

```bash
# Run security analysis on a hardware repository
python3 -m soc_analyzer scan /path/to/rtl --top top_module_name

# Validate toolchain environment (slang, verilator, z3)
python3 -m soc_analyzer validate /path/to/rtl

# Run the deterministic security benchmark audit suite
python3 -m soc_analyzer benchmark

# Display findings from a previous report
python3 -m soc_analyzer findings --report reports/report.json

# Start the web dashboard
python3 -m soc_analyzer server --port 8080
```

---

## 🧪 Running Automated Tests

Run the comprehensive pytest suite covering routing, repository discovery, pipeline execution, AI providers, and security detectors:

```bash
# Run user workflow and routing tests
/home/hackdac/.HACK_AI/bin/python3 -m pytest tests/test_user_workflow.py tests/test_routing_and_browse.py tests/test_dashboard_v2.py -v

# Run the entire security analysis test suite
/home/hackdac/.HACK_AI/bin/python3 -m pytest tests/
```

---

## 📁 Repository Structure

```text
soc-security-analyzer/
├── gui/                             # Svelte + TypeScript Web Frontend
│   ├── src/
│   │   ├── App.svelte               # Main application views, modals, & routing
│   │   ├── router.ts                # Client-side router and URL synchronization
│   │   └── folderPicker.ts          # Native directory selection bridge
│   └── dist/                        # Compiled production assets
├── src/soc_analyzer/
│   ├── dashboard/
│   │   ├── server.py                # FastAPI REST API & static file server
│   │   ├── repository_discovery.py  # AST-based dynamic repository scanner
│   │   ├── analysis_job.py          # Background analysis job runner & finding enrichment
│   │   └── ai_provider_manager.py   # Multi-provider AI Gateway & key vault
│   ├── candidates/                  # Deterministic security detectors
│   ├── design_db/                   # Hardware design database & AST models
│   ├── reachability/                # Z3 SMT solver reachability engine
│   ├── witness/                     # Dynamic witness generation & testbenches
│   ├── reports/                     # HTML and JSON report generators
│   ├── cli.py                       # Unified command-line interface
│   └── pipeline.py                  # End-to-end security analysis orchestrator
├── config/                          # Security registries and rule definitions
├── reports/                         # Generated security audit reports
└── tests/                           # Unit and integration test suites
```
