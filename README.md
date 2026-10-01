# SoC / RTL Hardware Security Analyzer

A comprehensive hardware security auditing platform and web application for System-on-Chip (SoC) and Register-Transfer Level (RTL) designs.

---

## ⚡ Quick Start: Start the Web Server

The web application runs on **http://localhost:8080**.

### Starting the Server

```bash
cd soc-security-analyzer
/home/hackdac/.HACK_AI/bin/python3 -m soc_analyzer server --host 0.0.0.0 --port 8080 --reload
```

Or using uvicorn directly:
```bash
cd soc-security-analyzer
/home/hackdac/.HACK_AI/bin/python3 -m uvicorn soc_analyzer.dashboard.server:app --host 0.0.0.0 --port 8080 --reload
```

Once started, open your browser at **[http://localhost:8080](http://localhost:8080)**.

---

## 🚀 Key Features

* **Dynamic Repository Discovery**: Select and analyze any local SoC/RTL hardware repository (SystemVerilog, Verilog, C/C++) with dynamic AST module indexing.
* **Module-Wise Inspector**: Explore module interfaces, port lists, child instances, and inferred clock/reset domains.
* **Multi-Stage Security Pipeline**: Structural property checking, symbolic reachability analysis with the Z3 SMT solver, and simulation witness validation.
* **Human-Readable Findings**: Security engineer explanations, attack path diagrams, Z3 SAT/UNSAT evidence, source code viewer, and one-click finding revalidation.
* **Multi-Provider AI Gateway**: Built-in support for OpenAI, Anthropic Claude, Google Gemini, DeepSeek, Zhipu GLM, Moonshot Kimi, or Custom APIs with masked keys and live connection latency testing. Non-fatal fallback ensures analysis never stops if AI is unavailable.
* **Interactive Reporting**: Generate and download comprehensive JSON and executive HTML security audit reports.

---

## 🛠️ Rebuilding the Frontend

```bash
cd soc-security-analyzer/gui
npm install
npm run build
```

---

## 🧪 Automated Testing

```bash
cd soc-security-analyzer
/home/hackdac/.HACK_AI/bin/python3 -m pytest tests/test_user_workflow.py tests/test_routing_and_browse.py tests/test_dashboard_v2.py -v
```

For full documentation, see [`soc-security-analyzer/README.md`](soc-security-analyzer/README.md).
