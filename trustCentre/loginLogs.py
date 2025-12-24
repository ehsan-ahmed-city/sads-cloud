from __future__ import annotations
import json
from pathlib import Path
from datetime import datetime, timezone

def append_login_log(user_id: str, sha3_pw: str) -> None:
    #local log file for S3/CloudWeatch)
    log_path = Path("trust_centre/login_audit.jsonl")
    event = {
        "event": "login",
        "user_id": user_id,
        "sha3_pw": sha3_pw,
        "ts_utc": datetime.now(timezone.utc).isoformat()
    }
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.open("a", encoding="utf-8").write(json.dumps(event) + "\n")