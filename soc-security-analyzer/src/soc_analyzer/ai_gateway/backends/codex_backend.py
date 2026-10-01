"""
Codex CLI Backend Adapter.
Secondary terminal backend for fallback and complementary checks.
"""

from __future__ import annotations
import os
import time
import subprocess
import json
import shutil
from typing import Dict, Any, Optional
from .base import BaseAIBackend, BackendResult, BackendDisabledError
from ..schemas import TaskPacket


class CodexCLIBackend(BaseAIBackend):
    """
    Secondary terminal backend using Codex CLI.
    Configurable and callable through the unified BaseAIBackend interface.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(name="codex", config=config)
        self.executable = (
            self.config.get("executable")
            or os.environ.get("CODEX_EXECUTABLE")
            or "codex"
        )
        self.working_dir = self.config.get("working_dir")
        self.timeout = float(self.config.get("timeout", 60.0))
        self.model = self.config.get("model")
        self.extra_args = self.config.get("extra_args", [])

    def is_enabled(self) -> bool:
        if not self.enabled:
            return False
        return bool(shutil.which(self.executable)) or os.path.exists(self.executable)

    def get_identity(self) -> str:
        model_name = self.model or "default"
        return f"codex:{model_name}"

    def execute(self, packet: TaskPacket, prompt: str) -> BackendResult:
        if not self.enabled:
            raise BackendDisabledError("Codex backend is disabled in configuration.")

        resolved_exe = shutil.which(self.executable) or self.executable
        if not (os.path.exists(resolved_exe) or shutil.which(self.executable)):
            return BackendResult(
                error=f"Codex executable '{self.executable}' not found in PATH or environment."
            )

        cmd = [resolved_exe, "exec", prompt]
        if self.model:
            cmd.extend(["--model", self.model])
        if self.extra_args:
            cmd.extend(self.extra_args)

        env = os.environ.copy()
        if "env" in self.config and isinstance(self.config["env"], dict):
            env.update(self.config["env"])

        start_time = time.time()
        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=self.working_dir,
                env=env,
                timeout=self.timeout,
            )
            elapsed = time.time() - start_time

            if res.returncode != 0:
                err_msg = res.stderr.strip() or f"CLI returned code {res.returncode}"
                return BackendResult(
                    raw_text=res.stdout,
                    error=f"Codex CLI failed (exit {res.returncode}): {err_msg}",
                    latency=elapsed,
                    wall_time=elapsed,
                    turn_count=1,
                )

            raw_out = res.stdout.strip()
            parsed_json = None
            if raw_out.startswith("{") and raw_out.endswith("}"):
                try:
                    parsed_json = json.loads(raw_out)
                except Exception:
                    pass

            return BackendResult(
                raw_text=raw_out,
                parsed_output=parsed_json,
                input_tokens=None,
                output_tokens=None,
                latency=elapsed,
                wall_time=elapsed,
                turn_count=1,
            )

        except subprocess.TimeoutExpired:
            elapsed = time.time() - start_time
            return BackendResult(
                error=f"Codex CLI execution timed out after {self.timeout}s",
                latency=elapsed,
                wall_time=elapsed,
                turn_count=1,
            )
        except Exception as e:
            elapsed = time.time() - start_time
            return BackendResult(
                error=f"Codex CLI invocation error: {str(e)}",
                latency=elapsed,
                wall_time=elapsed,
            )
