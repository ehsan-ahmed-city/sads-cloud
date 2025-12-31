from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib

from auth.cognito import sign_in
from auth.token_verify import verify_access_token
from trust_centre.loginLogs import append_login_log

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

    u = verify_access_token(tokens["access_token"])#get user id from access token for verif
    user_id = u["Username"]
    login_ts = datetime.now(timezone.utc).isoformat()
    sha3_pw = sha3_256_hex(email + ":" + password) #better than hashing raw pwd
    #TC log to S3
    append_login_log(
        bucket="sads-raw-data",
        region="eu-west-2",
        #^our bucket title and region 
        user_id=user_id,
        sha3_pw=sha3_pw,
    )

    return AuthResult(
        user_id=user_id,
        access_token=tokens["access_token"],
        id_token=tokens["id_token"],
        sha3_pw=sha3_pw,
        login_ts_utc=login_ts,
    )