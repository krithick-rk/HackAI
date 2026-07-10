# SoC Hardware Security Analyzer & Validation Dashboard

This repository contains the deterministic preprocessing, validation pipeline, and visual dashboard for the SoC Hardware Security Analyzer. It is designed to audit RTL modules, track compiler validations, inspect diagnostic reports, and manage stubs.

---

## 🚀 Key Features

### 1. Interactive Directory Selection Tree
* **Hierarchical Visualization**: Replaces flat path lists with a collapsible, nested folder tree of the target design.
* **Recursive Checkbox Propagation**: Toggling a parent folder recursively selects or deselects all of its subdirectories.
* **Smart Expansion & Noise Reduction**:
  * **Show All Folders**: Displays the entire directory structure to allow exploration and editing.
  * **Collapse Unselected**: Activates a clean view that collapses fully selected folders and completely hides unselected folders (noise) from the tree hierarchy, showing only active directories.

### 2. Multi-Tool Validation Pipeline
* Runs compiler validation checks across several analysis tools (e.g., **slang**, **verilator**, **verible**).
* Dynamically scans for missing package imports, includes, and stubs.
* Generates required stub packages (`stubs/`) to allow compilation to proceed.

### 3. Integrated Audit Dashboard
* **Real-time Status Tracking**: Color-coded badges categorizing modules by status:
  * `VALIDATED` (Green): Passed compilation.
  * `MISSING STUB` (Yellow/Orange): Compiled successfully with stub injection.
  * `FAILED` (Red): Encountered compiler errors or missing tools.
  * `QUEUED` (Grey): Awaiting audit.
* **Interactive Diagnostics**: Click status badges to open a details modal displaying compiler logs, exit codes, and required stubs.
* **Terminal Stream**: Watch the validation pipeline output run live from the dashboard interface.

---

## 📁 Repository Structure

```text
├── src/
│   └── soc_analyzer/
│       ├── dashboard/       # FastAPI server, endpoints, and status aggregator
│       ├── phase0/          # Dependency scanner, invocation map builder, validator
│       ├── preprocessing/   # Comment strippers and tool output parsers
│       └── common/          # Shared TypedDict schemas and filesystem utilities
├── gui/
│   ├── src/                 # Svelte frontend components (App.svelte, FolderTreeNode.svelte)
│   ├── dist/                # Production static assets served by FastAPI
│   └── package.json         # Node dependency definition
├── verify_pipeline.py       # CLI validation runner script
└── tests/                   # Extensive pytest suite
```

---

## 🛠️ Getting Started

### 1. Rebuild the Frontend
To compile Svelte and Vite into production static assets served by FastAPI:
```bash
cd gui
npm run build
cd ..
```

### 2. Launch the Dashboard Server
Start the FastAPI server locally (runs on `http://127.0.0.1:8000`):
```bash
PYTHONPATH=. ~/.HACK_AI/bin/python3 -m src.soc_analyzer.dashboard.server
```

### 3. Run Pipeline CLI Verification
To trigger validations directly via the CLI:
```bash
python3 verify_pipeline.py --design-dir /home/hackdac/opentitan --project-name opentitan
```

### 4. Run Unit Tests
To run the automated Python test suite:
```bash
pytest tests/
```
