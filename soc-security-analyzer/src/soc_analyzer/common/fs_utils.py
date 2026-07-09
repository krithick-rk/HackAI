import os
import json
from typing import Any

def write_json_artifact(data: Any, filepath: str) -> None:
    """Helper to write data as JSON, creating directories recursively."""
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)

def read_json_artifact(filepath: str) -> Any:
    """Helper to read data from a JSON file."""
    with open(filepath, 'r', encoding='utf-8') as f:
        return json.load(f)
