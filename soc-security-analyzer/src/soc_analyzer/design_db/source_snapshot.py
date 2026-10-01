"""
Source Snapshot and Line Mapping for design_db.
Ensures original source files remain canonical, hashes are recorded,
and line numbers are preserved with high fidelity.
"""

from __future__ import annotations
import os
import hashlib
import bisect
from typing import Dict, List, Optional, Tuple
from .schemas import SourceSnapshot, SourceLocation


class SourceManager:
    """
    Manages source file snapshots, line indices, and hash integrity.
    Never mutates or normalizes the canonical source files.
    """

    def __init__(self):
        self._snapshots: Dict[str, SourceSnapshot] = {}
        self._line_offsets: Dict[str, List[int]] = {}
        self._file_contents: Dict[str, str] = {}

    def capture_file(self, file_path: str) -> SourceSnapshot:
        """Reads file, computes SHA-256 hash, indexes line start offsets, and stores snapshot."""
        abs_path = os.path.abspath(file_path)
        if not os.path.exists(abs_path):
            raise FileNotFoundError(f"Source file not found: {abs_path}")

        with open(abs_path, "rb") as f:
            raw_bytes = f.read()

        sha256 = hashlib.sha256(raw_bytes).hexdigest()
        text = raw_bytes.decode("utf-8", errors="replace")
        lines = text.splitlines(keepends=True)
        line_count = len(lines)
        byte_size = len(raw_bytes)

        # Build line start offsets
        offsets = [0]
        cur = 0
        for line in lines:
            cur += len(line)
            offsets.append(cur)

        snapshot = SourceSnapshot(
            file_path=abs_path,
            source_hash=sha256,
            line_count=line_count,
            byte_size=byte_size,
            is_canonical=True,
        )

        self._snapshots[abs_path] = snapshot
        self._line_offsets[abs_path] = offsets
        self._file_contents[abs_path] = text
        return snapshot

    def get_snapshot(self, file_path: str) -> Optional[SourceSnapshot]:
        abs_path = os.path.abspath(file_path)
        if abs_path not in self._snapshots:
            if os.path.exists(abs_path):
                return self.capture_file(abs_path)
            return None
        return self._snapshots[abs_path]

    def verify_integrity(self, file_path: str) -> bool:
        """Verifies that the file currently on disk matches the captured source hash."""
        abs_path = os.path.abspath(file_path)
        snapshot = self.get_snapshot(file_path)
        if not snapshot or not os.path.exists(abs_path):
            return False

        with open(abs_path, "rb") as f:
            current_hash = hashlib.sha256(f.read()).hexdigest()
        return current_hash == snapshot.source_hash

    def get_lines(self, file_path: str, start_line: int, end_line: Optional[int] = None) -> List[str]:
        """
        Retrieves 1-indexed line range [start_line, end_line] directly from the original source.
        Returns unmodified lines (preserving original comments and indentation).
        """
        abs_path = os.path.abspath(file_path)
        if abs_path not in self._file_contents:
            if not os.path.exists(abs_path):
                return []
            self.capture_file(abs_path)

        text = self._file_contents.get(abs_path, "")
        lines = text.splitlines()
        if not lines:
            return []

        actual_end = end_line if end_line is not None else start_line
        s = max(0, start_line - 1)
        e = min(len(lines), actual_end)
        return lines[s:e]

    def get_line_location_by_char_offset(self, file_path: str, char_offset: int) -> Tuple[int, int]:
        """Maps character offset to 1-indexed (line, column)."""
        abs_path = os.path.abspath(file_path)
        if abs_path not in self._line_offsets:
            self.capture_file(abs_path)
        offsets = self._line_offsets[abs_path]
        line_idx = bisect.bisect_right(offsets, char_offset) - 1
        line_num = line_idx + 1
        col_num = (char_offset - offsets[line_idx]) + 1
        return line_num, col_num

    @property
    def snapshots(self) -> Dict[str, SourceSnapshot]:
        return dict(self._snapshots)
