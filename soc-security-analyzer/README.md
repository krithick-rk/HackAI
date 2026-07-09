# SoC Hardware Security Analyzer (Phase 0 & Pre-processing)

This repository contains the foundational deterministic Python pipeline for the AI-powered SoC Hardware Security Analyzer.

## Repository Structure

- `src/soc_analyzer/preprocessing`: Python modules for comment stripping and tool log parsing.
- `src/soc_analyzer/phase0`: Python modules for static dependency scanning, invocation map generation, and tool validator.
- `src/soc_analyzer/common`: Dataclasses, schemas, and filesystem utilities.
- `fixtures/`: Sample RTL designs and mock tool logs for testing.
- `tests/`: Extensive unit testing suite.

## Getting Started

1. Install requirements or development dependencies.
2. Run tests:
   ```bash
   pytest tests/
   ```
