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


TOKEN_EXHAUSTED_KEYWORDS = (
    "token limit",
    "tokens finished",
    "tokens exhausted",
    "out of tokens",
    "token quota",
    "quota exceeded",
    "insufficient_quota",
    "exceeded your current quota",
    "rate limit",
    "rate_limit_exceeded",
    "429",
    "credit limit",
    "out of credits",
    "billing",
    "maximum context length",
    "context_length_exceeded",
    "usage limit",
    "capacity exhausted",
    "no tokens remaining",
    "exhausted",
)


def is_token_exhausted(msg: str) -> bool:
    """Detects whether an error message indicates model token or quota exhaustion."""
    if not msg:
        return False
    lower = msg.lower()
    return any(kw in lower for kw in TOKEN_EXHAUSTED_KEYWORDS)


class CodexCLIBackend(BaseAIBackend):
    """
    Terminal backend using Codex CLI.
    Supports non-interactive JSONL streaming execution, token extraction,
    and automatic token-exhaustion detection.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(name="codex", config=config)
        self.executable = (
            self.config.get("executable")
            or os.environ.get("CODEX_EXECUTABLE")
            or shutil.which("codex")
            or "/home/hackdac/.local/bin/codex"
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

        cmd = [
            resolved_exe,
            "exec",
            "--skip-git-repo-check",
            "--ephemeral",
            "--json",
            prompt,
        ]
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

            raw_out = res.stdout.strip()
            stderr_out = res.stderr.strip()

            # Parse JSONL events from stdout
            agent_messages: list[str] = []
            input_tokens = None
            output_tokens = None
            event_error = None
            token_exhausted = False

            for line in raw_out.splitlines():
                line = line.strip()
                if not line or not (line.startswith("{") and line.endswith("}")):
                    continue
                try:
                    ev = json.loads(line)
                    ev_type = ev.get("type")
                    if ev_type == "item.completed":
                        item = ev.get("item", {})
                        if item.get("type") == "agent_message" and "text" in item:
                            agent_messages.append(item["text"])
                    elif ev_type == "turn.completed":
                        usage = ev.get("usage", {})
                        input_tokens = usage.get("input_tokens")
                        output_tokens = usage.get("output_tokens")
                    elif ev_type in ("turn.failed", "error"):
                        err_obj = ev.get("error") or ev
                        event_error = str(err_obj)
                        if is_token_exhausted(event_error):
                            token_exhausted = True
                except Exception:
                    pass

            combined_text = "\n".join(agent_messages).strip() if agent_messages else raw_out

            # Check if token exhausted in error, stderr, or stdout
            combined_diag = f"{stderr_out} {event_error or ''} {combined_text}"
            if is_token_exhausted(combined_diag):
                token_exhausted = True

            if res.returncode != 0 or event_error:
                err_msg = event_error or stderr_out or f"Codex CLI returned exit code {res.returncode}"
                return BackendResult(
                    raw_text=combined_text,
                    error=err_msg,
                    input_tokens=input_tokens,
                    output_tokens=output_tokens,
                    latency=elapsed,
                    wall_time=elapsed,
                    turn_count=1,
                    is_token_exhausted=token_exhausted,
                )

            # Try parsing structured JSON
            parsed_json = None
            clean_text = combined_text
            if clean_text.startswith("```"):
                lines = clean_text.splitlines()
                if len(lines) > 2:
                    clean_text = "\n".join(lines[1:-1]).strip()

            if clean_text.startswith("{") and clean_text.endswith("}"):
                try:
                    parsed_json = json.loads(clean_text)
                except Exception:
                    pass

            return BackendResult(
                raw_text=clean_text,
                parsed_output=parsed_json,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                latency=elapsed,
                wall_time=elapsed,
                turn_count=1,
                is_token_exhausted=token_exhausted,
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
            err_str = str(e)
            return BackendResult(
                error=f"Codex CLI invocation error: {err_str}",
                latency=elapsed,
                wall_time=elapsed,
                is_token_exhausted=is_token_exhausted(err_str),
            )

