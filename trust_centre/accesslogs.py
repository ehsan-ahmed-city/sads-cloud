from __future__ import annotations
import json
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError


def append_access_log(
    *,
    bucket: str,
    region: str,
    user_id: str,
    action: str,  # upload, download,decrypt,cluster etc
    ok: bool,
    reason: str | None = None,
    extra: dict | None = None,
) -> None:
    """
    Append one access event to JSONL file in S3 trust centre.
    """

    s3 = boto3.client("s3", region_name=region)
    log_key = "trust-centre/access_audit.jsonl"

    event = {
        "event": "access",
        "action": action,
        "user_id": user_id,
        "s3_key": s3_key,
        "ok": ok,
        "reason": reason,
        "ts_utc": datetime.now(timezone.utc).isoformat(),
    }
    if extra:
        event["extra"] = extra

    line = (json.dumps(event) + "\n").encode("utf-8")

    #read existing log (or sttart empty one)
    try:
        resp = s3.get_object(Bucket=bucket, Key=log_key)
        existing = resp["Body"].read()
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("NoSuchKey", "404"):
            existing = b""
        else:
            raise

    #append n wb
    s3.put_object(
        Bucket=bucket,
        Key=log_key,
        Body=existing + line,
        ContentType="application/json",
    )
