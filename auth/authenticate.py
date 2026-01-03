from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timezone

from auth.cognito import sign_in
from auth.token_verify import verify_access_token
from trust_centre.loginLogs import writeLoginEvent

import yaml
from pathlib import Path

def load_config():
    return yaml.safe_load(Path("config/config.yaml").read_text(encoding="utf-8"))


@dataclass
class AuthResult:
    user_id: str
    access_token: str
    id_token: str
    login_ts_utc: str


def authenticate_user(email: str, password: str) -> AuthResult:
    cfg = load_config()
    region = cfg["aws"]["region"]
    bucket = cfg["s3"]["raw_bucket"]

    try:
        tokens = sign_in(email, password)#cognito sign in attempt 
    except Exception as e:   #log failed login attempt
        writeLoginEvent(
            bucket=bucket,
            region=region,
            user_id=None,
            success=False,
            reason=str(e),
            extra={"email_hint": (email[:3] + "***") if email else "***"},
        )
        raise


    u = verify_access_token(tokens["access_token"])#get user id from access token for verif
    user_id = u["Username"]
    login_ts = datetime.now(timezone.utc).isoformat()

    
    writeLoginEvent( #log successful login attempt
        bucket=bucket,
        region=region,
        #^our bucket title and region 
        user_id=user_id,
        success=True,
        extra={"client": "cli_or_ui"},
    )

    return AuthResult(
        user_id=user_id,
        access_token=tokens["access_token"],
        id_token=tokens["id_token"],
        login_ts_utc=login_ts,
    )
