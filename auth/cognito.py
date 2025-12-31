import boto3
import yaml
from pathlib import Path
from typing import Dict, Any

from auth.hashing import sha3_256_hex

def load_config() -> Dict[str, Any]:
    with Path("config/config.yaml").open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def cognito_client(region: str):
    return boto3.client("cognito-idp", region_name=region)

def sign_up(email: str, password: str) -> None:
    cfg = load_config()
    region = cfg["aws"]["region"]
    client_id = cfg["cognito"]["client_id"]


    hashed = sha3_256_hex(password)#store SHA3 hash as extra trust centre artifact

    c = cognito_client(region)
    c.sign_up(
        ClientId=client_id,
        Username=email,
        Password=password,
        UserAttributes=[
            {"Name": "email", "Value": email},
        ],
    )

def sign_in(email: str, password: str) -> Dict[str, str]:
    cfg = load_config()
    region = cfg["aws"]["region"]
    client_id = cfg["cognito"]["client_id"]

    c = cognito_client(region)
    resp = c.initiate_auth(
        ClientId=client_id,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": email, "PASSWORD": password},
    )
    res = resp["AuthenticationResult"]
    return {
        "access_token": res["AccessToken"],
        "id_token": res["IdToken"],
        #access token and id from aws coginto
        "refresh_token": res.get("RefreshToken", ""),
    }
