from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib

from auth.cognito import sign_in

@dataclass
class AuthResult:
    user_id: str
    access_token: str
    id_token: str
    sha3_pw: str
    login_ts_utc: str

def sha3_256_hex(s: str) -> str:
    #sha3 hash for tust centre log
    return hashlib.sha3_256(s.encode("utf-8")).hexdigest()

def authenticate_user(email: str, password: str) -> AuthResult:
    #need real pwd
    tokens = sign_in(email, password)

    #parse from access token? better: call GetUser using access tokem
    from auth.token_verify import verify_access_token
    u = verify_access_token(tokens["access_token"])
    user_id = u["Username"]

    return AuthResult(
        user_id=user_id,
        access_token=tokens["access_token"],
        id_token=tokens["id_token"],
        sha3_pw=sha3_256_hex(password),
        login_ts_utc=datetime.now(timezone.utc).isoformat()
    )
