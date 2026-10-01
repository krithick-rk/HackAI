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
        # Fallback to artifacts directory if available
        art_path = f"workspace/{project_name}_artifacts/project_config.json"
        if os.path.exists(art_path):
            path = art_path
        else:
            return {}, {}
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            config = data.get("config", data)
            duplicates = data.get("resolved_duplicates", {})
            return config, duplicates
    except Exception:
        return {}, {}

def save_project_config(project_name: str, config: Dict[str, Any], resolved_duplicates: Dict[str, str] = None):
    if resolved_duplicates is None:
        resolved_duplicates = {}
    path = get_config_path(project_name)
    data = {
        "config": config,
        "resolved_duplicates": resolved_duplicates
    }
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)

    # Also mirror to project_config.json in artifacts directory if output_dir is known or default
    art_dir = config.get("output_dir", f"workspace/{project_name}_artifacts")
    try:
        os.makedirs(art_dir, exist_ok=True)
        art_path = os.path.join(art_dir, "project_config.json")
        with open(art_path, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2)
    except Exception:
        pass

