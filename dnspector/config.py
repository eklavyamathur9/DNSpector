"""JSON config file loading."""

import json
from pathlib import Path
from typing import Any, Dict, Optional


def load_config(path: Optional[str]) -> Dict[str, Any]:
    """Load default option values from a JSON config file, if one is given and exists."""
    if not path:
        return {}
    config_path = Path(path)
    if not config_path.exists():
        return {}
    try:
        with open(config_path) as f:
            return json.load(f)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in config file {path}: {exc}") from exc
