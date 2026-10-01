# V2 Architecture Migration Status & Implementation Note

See canonical document at `docs/v2_migration_status.md` in repository root.

Summary of key sections:
1. Executive summary of repository audit
2. Existing components (`phase0`, `preprocessing`, `dashboard`, `common`, `gui`)
3. Components to modify (`tool_validator.py` bugfix, `schemas.py`, `dashboard/server.py`, `gui/App.svelte`)
4. Components to add (`design_db`, `registries`, `ai_gateway`, `candidates`, `grounding`, `reachability`, `findings`, `witness`, `benchmark`, `reporting`, `cli`)
5. Components to remove/deprecate (direct HTTP AI calls, hardcoded API keys)
6. Implementation order (Stages 1 through 9)
7. Current test commands & baseline status
