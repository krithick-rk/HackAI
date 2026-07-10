import os
import json
from typing import Dict, Any, Tuple

CONFIG_DIR = "workspace/projects"

def get_config_path(project_name: str) -> str:
    os.makedirs(CONFIG_DIR, exist_ok=True)
    return os.path.join(CONFIG_DIR, f"{project_name}_config.json")

def load_project_config(project_name: str) -> Tuple[Dict[str, Any], Dict[str, str]]:
    path = get_config_path(project_name)
    if not os.path.exists(path):
        return {}, {}
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            return data.get("config", {}), data.get("resolved_duplicates", {})
    except Exception:
        return {}, {}

def save_project_config(project_name: str, config: Dict[str, Any], resolved_duplicates: Dict[str, str]):
    path = get_config_path(project_name)
    data = {
        "config": config,
        "resolved_duplicates": resolved_duplicates
    }
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)
