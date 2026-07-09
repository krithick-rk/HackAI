from typing import TypedDict, List, Optional

class ErrorWarningDetail(TypedDict):
    file: str
    line: int
    column: int
    severity: str  # "error" or "warning"
    message: str

class SummaryDetail(TypedDict):
    error_count: int
    warning_count: int

class CompressedLog(TypedDict):
    tool: str
    exit_code: int
    errors: List[ErrorWarningDetail]
    warnings: List[ErrorWarningDetail]
    summary: SummaryDetail
    raw_output_truncated: str

class ToolInvocationInfo(TypedDict):
    base_command: str
    files: List[str]
    include_paths: List[str]
    required_companions: List[str]
    stubs_required: List[str]
    status: str  # e.g., "UNVALIDATED", "VALIDATED", "PARTIAL", "NEEDS_STUB", "TOOL_UNAVAILABLE", "FAILED"
    validation_output_summary: Optional[str]
    worker_note: str

class PerModuleInvocationMap(TypedDict):
    module: str
    slang: ToolInvocationInfo
    verilator: ToolInvocationInfo
    verible: ToolInvocationInfo
