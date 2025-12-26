
from future import annotations
import json
from datetime import datetime, timezone
import boto3
from botocore.exceptions import ClientError


def append_login_log(
    *,
    bucket: str,
    region: str,
    user_id: str,
    sha3_pw: str,
) -> None:
    """
    Append one login event to a JSONL file in S3 trust centre.
    """

    s3 = boto3.client("s3", region_name=region)
    key = "trust-centre/login_audit.jsonl"

    event = {
        "event": "login",
        "user_id": user_id,
        "sha3_pw": sha3_pw,
        "ts_utc": datetime.now(timezone.utc).isoformat(),
    }

    line = (json.dumps(event) + "\n").encode("utf-8")

    #read existing log or strat empty
    try:
        resp = s3.get_object(Bucket=bucket, Key=key)
        existing = resp["Body"].read()
    except ClientError as e:
        if e.response["Error"]["Code"] in ("NoSuchKey", "404"):
            existing = b""
        else:
            raise

    s3.put_object(#append + write back
        Bucket=bucket,
        Key=key,
        Body=existing + line,
        ContentType="application/json",
    )