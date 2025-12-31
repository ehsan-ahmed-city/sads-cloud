from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timezone

from auth.cognito import sign_in
from auth.token_verify import verify_access_token
from trust_centre.loginLogs import write_login_event


@dataclass
class AuthResult:
    user_id: str
    access_token: str
    id_token: str
    login_ts_utc: str


def authenticate_user(email: str, password: str) -> AuthResult:
    try:
        tokens = sign_in(email, password)#cognito sign in attempt 
    except Exception as e:   #log failed login attempt
        write_login_event(
            bucket="sads-raw-data",
            region="eu-west-2",
            user_id=None,
            success=False,
            reason=str(e),
            extra={"email_hint": email[:3] + "***"},
        )
        raise


    u = verify_access_token(tokens["access_token"])#get user id from access token for verif
    user_id = u["Username"]
    login_ts = datetime.now(timezone.utc).isoformat()

    
    write_login_event( #log successful login attempt
        bucket="sads-raw-data",
        region="eu-west-2",
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
