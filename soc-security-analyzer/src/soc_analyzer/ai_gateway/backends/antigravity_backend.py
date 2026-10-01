"""
Antigravity / AGY Terminal Backend Adapter.
Primary active backend invoking configured AGY CLI non-interactively
with sandbox and workspace isolation.
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


class AntigravityTerminalBackend(BaseAIBackend):
    """
    Primary active backend using the Google Antigravity (AGY) CLI.
    Supports configurable executable, working directory, timeout, sandbox, and environment.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(name="antigravity", config=config)
        # Determine executable: config -> env var -> 'agy'
        self.executable = (
            self.config.get("executable")
            or os.environ.get("AGY_EXECUTABLE")
            or "agy"
        )
        self.working_dir = self.config.get("working_dir")
        self.timeout = float(self.config.get("timeout", 60.0))
        self.sandbox = bool(self.config.get("sandbox", True))
        self.model = self.config.get("model")
        self.extra_args = self.config.get("extra_args", [])

    def is_enabled(self) -> bool:
        if not self.enabled:
            return False
        # Verify executable can be located
        return bool(shutil.which(self.executable)) or os.path.exists(self.executable)

    def get_identity(self) -> str:
        model_name = self.model or "default"
        return f"antigravity:{model_name}"

    def execute(self, packet: TaskPacket, prompt: str) -> BackendResult:
        if not self.enabled:
            raise BackendDisabledError("Antigravity backend is disabled in configuration.")

        # Check if executable exists
        resolved_exe = shutil.which(self.executable) or self.executable
        if not (os.path.exists(resolved_exe) or shutil.which(self.executable)):
            return BackendResult(
                error=f"Antigravity executable '{self.executable}' not found in PATH or environment."
            )

        cmd = [resolved_exe, "-p", prompt, "--output-format", "json"]
        if self.sandbox:
            cmd.append("--sandbox")
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
                    error=f"AGY CLI failed (exit {res.returncode}): {err_msg}",
                    latency=elapsed,
                    wall_time=elapsed,
                    turn_count=1,
                )

            # Try parsing structured JSON if output is JSON formatted
            raw_out = res.stdout.strip()
            parsed_json = None
            input_tokens = None
            output_tokens = None
            wall_time = elapsed
            turn_count = 1

            if raw_out.startswith("{") and raw_out.endswith("}"):
                try:
                    wrapper = json.loads(raw_out)
                    if isinstance(wrapper, dict):
                        if "response" in wrapper:
                            raw_out = wrapper["response"].strip()
                            if "usage" in wrapper and isinstance(wrapper["usage"], dict):
                                input_tokens = wrapper["usage"].get("input_tokens")
                                output_tokens = wrapper["usage"].get("output_tokens")
                            if "duration_seconds" in wrapper:
                                wall_time = float(wrapper["duration_seconds"])
                            if "num_turns" in wrapper:
                                turn_count = int(wrapper["num_turns"])
                        else:
                            parsed_json = wrapper
                except Exception:
                    pass

            if parsed_json is None and raw_out.startswith("{") and raw_out.endswith("}"):
                try:
                    parsed_json = json.loads(raw_out)
                except Exception:
                    pass

            return BackendResult(
                raw_text=raw_out,
                parsed_output=parsed_json,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                latency=elapsed,
                wall_time=wall_time,
                turn_count=turn_count,
            )

        except subprocess.TimeoutExpired:
            elapsed = time.time() - start_time
            return BackendResult(
                error=f"AGY CLI execution timed out after {self.timeout}s",
                latency=elapsed,
                wall_time=elapsed,
                turn_count=1,
            )
        except Exception as e:
            elapsed = time.time() - start_time
            return BackendResult(
                error=f"AGY CLI invocation error: {str(e)}",
                latency=elapsed,
                wall_time=elapsed,
            )
