from future import annotations
from typing import Dict, Any
from metadata.schema import REQUIRED_FIELDS

def validate_block_meta(meta: Dict[str, Any]) -> None:
    missing = REQUIRED_FIELDS - set(meta.keys())
    if missing:
        raise ValueError(f"Metadata missing fields: {sorted(missing)}")