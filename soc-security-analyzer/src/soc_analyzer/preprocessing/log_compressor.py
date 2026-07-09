import re
import sys
from typing import Protocol, Dict, List, Any
from soc_analyzer.common.schemas import CompressedLog, ErrorWarningDetail

class ToolLogParser(Protocol):
    def parse(self, raw_output: str) -> dict:
        """Parses the raw log output and returns errors, warnings, and summary."""
        ...

class VeribleLogParser:
    def parse(self, raw_output: str) -> dict:
        errors = []
        warnings = []
        
        # Pattern: filename:line:col: message
        # Group 1 captures possible Windows drive letters (e.g. C:/ or C:\) or normal filepaths
        pattern = re.compile(r"^([a-zA-Z]:[\\/][^:]+|[^:]+):(\d+):(\d+):\s*(.*)$")
        
        for line in raw_output.splitlines():
            m = pattern.match(line)
            if m:
                file_path = m.group(1).strip()
                line_num = int(m.group(2))
                col_num = int(m.group(3))
                message = m.group(4).strip()
                
                # Check for syntax errors to elevate to error, otherwise warning
                severity = "error" if "syntax error" in message.lower() or "error" in message.lower() else "warning"
                
                detail: ErrorWarningDetail = {
                    "file": file_path,
                    "line": line_num,
                    "column": col_num,
                    "severity": severity,
                    "message": message
                }
                
                if severity == "error":
                    errors.append(detail)
                else:
                    warnings.append(detail)
                    
        return {
            "errors": errors,
            "warnings": warnings,
            "summary": {
                "error_count": len(errors),
                "warning_count": len(warnings)
            }
        }

class VerilatorLogParser:
    def parse(self, raw_output: str) -> dict:
        errors = []
        warnings = []
        
        # Pattern: %Error: filepath:line:col: message
        # or: %Warning-CODE: filepath:line:col: message
        pattern = re.compile(r"^%(Error|Warning)(?:-([A-Z0-9_]+))?:\s*([a-zA-Z]:[\\/][^:]+|[^:]+):(\d+):(?:(\d+):)?\s*(.*)$")
        
        last_detail = None
        for line in raw_output.splitlines():
            m = pattern.match(line)
            if m:
                severity_type = m.group(1).lower()  # "error" or "warning"
                code = m.group(2)
                file_path = m.group(3).strip()
                line_num = int(m.group(4))
                col_num = int(m.group(5)) if m.group(5) else 0
                message = m.group(6).strip()
                
                if code:
                    message = f"[{code}] {message}"
                    
                detail: ErrorWarningDetail = {
                    "file": file_path,
                    "line": line_num,
                    "column": col_num,
                    "severity": severity_type,
                    "message": message
                }
                
                if severity_type == "error":
                    errors.append(detail)
                    last_detail = errors[-1]
                else:
                    warnings.append(detail)
                    last_detail = warnings[-1]
            else:
                # Append multi-line content (source lines or continuation text)
                if last_detail and (line.startswith(" ") or line.startswith("\t") or line.strip().startswith(":")):
                    last_detail["message"] += "\n" + line.strip()
                    
        return {
            "errors": errors,
            "warnings": warnings,
            "summary": {
                "error_count": len(errors),
                "warning_count": len(warnings)
            }
        }

class IVerilogLogParser:
    def parse(self, raw_output: str) -> dict:
        # TODO: Implement iverilog log parser based on real compiler outputs
        raise NotImplementedError("IVerilogLogParser is not implemented yet")

class YosysLogParser:
    def parse(self, raw_output: str) -> dict:
        # TODO: Implement yosys log parser based on synthesis warnings/errors
        raise NotImplementedError("YosysLogParser is not implemented yet")

# Parser registry
PARSERS: Dict[str, ToolLogParser] = {
    "verible": VeribleLogParser(),
    "verilator": VerilatorLogParser(),
    "iverilog": IVerilogLogParser(),
    "yosys": YosysLogParser()
}

def truncate_raw_output(raw_output: str, limit: int = 2000) -> str:
    """Caps the raw output at ~2000 characters and appends a truncation indicator."""
    if len(raw_output) <= limit:
        return raw_output
    # Safe limit truncation
    return raw_output[:limit - 30] + "\n... [TRUNCATED] ..."

def compress_log(tool_name: str, raw_output: str, exit_code: int = 0) -> CompressedLog:
    """
    Looks up the parser for the given tool, parses raw logs, and outputs structured CompressedLog.
    Handles parse failures and unknown tools gracefully.
    """
    tool_key = tool_name.lower()
    truncated = truncate_raw_output(raw_output)
    
    # Check if tool is registered
    if tool_key not in PARSERS:
        return {
            "tool": tool_name,
            "exit_code": exit_code,
            "errors": [],
            "warnings": [],
            "summary": {
                "error_count": -1,  # sentinel for unknown tool/failed parse
                "warning_count": 0
            },
            "raw_output_truncated": truncated
        }
        
    parser = PARSERS[tool_key]
    try:
        parsed_data = parser.parse(raw_output)
        return {
            "tool": tool_name,
            "exit_code": exit_code,
            "errors": parsed_data["errors"],
            "warnings": parsed_data["warnings"],
            "summary": parsed_data["summary"],
            "raw_output_truncated": truncated
        }
    except Exception as e:
        print(f"Warning: Log compression failed for tool '{tool_name}': {e}", file=sys.stderr)
        return {
            "tool": tool_name,
            "exit_code": exit_code,
            "errors": [],
            "warnings": [],
            "summary": {
                "error_count": -1,  # sentinel for failed parse
                "warning_count": 0
            },
            "raw_output_truncated": truncated
        }
