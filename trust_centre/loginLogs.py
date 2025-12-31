from __future__ import annotations
import json
from datetime import datetime, timezone
import boto3
from botocore.exceptions import ClientError
import uuid


def writeLoginEvent(
    *,
    bucket: str,
    region: str,
    user_id: str | None,
    success: bool,
    reason: str | None = None,
    extra: dict | None = None,
) -> str:
    #writing one login event as a single S3 obj

    s3 = boto3.client("s3", region_name=region)

    now = datetime.now(timezone.utc)
    key = f"trust-centre/logins/{now:%Y/%m/%d}/{uuid.uuid4().hex}.json"

    event = {
        "event": "login",
        "ts_utc": now.isoformat(),
        "user_id": user_id,
        "success": success,
        "reason": reason,
    }

    if extra:
        event["extra"] = extra

    s3.put_object(
        Bucket=bucket,
        Key=key,
        Body=json.dumps(event).encode("utf-8"),
        ContentType="application/json",
    )

    return key
