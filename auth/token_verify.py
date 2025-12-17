import boto3
import yaml
from pathlib import Path
from typing import Any, Dict

def load_config() -> Dict[str, Any]:
    # read config file
    with Path("config/config.yaml").open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def verify_access_token(access_token: str) -> Dict[str, Any]:
    """
    check token with Cognito
    invalid token -> exception
    """
    cfg = load_config()
    region = cfg["aws"]["region"]  # aws region
    client = boto3.client("cognito-idp", region_name=region)  # cognito api
    return client.get_user(AccessToken=access_token)  # if ok, token valid