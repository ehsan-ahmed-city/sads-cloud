from __future__ import annotations

import json
from datetime import datetime, timezone, timedelta
import boto3
import uuid
from typing import Any, Dict, List, Optional


#Susp policy from Asad
class SuspiciousPolicy:
    HIGH_ATTEMPT_N = 5
    HIGH_ATTEMPT_WINDOW_SEC = 120  #5 attempts in 2 minutes
    FAIL_THEN_SUCCESS_FAIL_N = 5
    FAIL_THEN_SUCCESS_WINDOW_SEC = 300 # 5minuts

    UNUSUAL_START_HOUR = 23
    UNUSUAL_END_HOUR = 6

    RAPID_SUCCESS_N = 5
    RAPID_SUCCESS_WINDOW_SEC = 600

    FEATURE_WINDOW_10M_SEC = 600


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def parseIso(ts: str) -> datetime:
    #for .z and +00:00
    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def withinTime(dt: datetime, start: datetime, end: datetime) -> bool:
    return start <= dt <= end


def _s3(region: str):
    return boto3.client("s3", region_name=region)


def listKeys(s3, *, bucket: str, prefix: str) -> List[str]:
    keys: List[str] = []
    token: Optional[str] = None
    while True:
        kwargs = {"Bucket": bucket, "Prefix": prefix}
        if token:
            kwargs["ContinuationToken"] = token
        resp = s3.list_objects_v2(**kwargs)
        for obj in resp.get("Contents", []):
            keys.append(obj["Key"])
        token = resp.get("NextContinuationToken")
        if not token:
            break
    return keys


def read_recent_login_events(
    *,
    bucket: str,
    region: str,
    user_id: str,
    lookback_minutes: int = 10,
) -> List[Dict[str, Any]]:
    """
    Reads recent login events by scanning today's and yesterday's login prefixes
    """
    s3 = _s3(region)
    now = utcnow()
    cutoff = now - timedelta(minutes=lookback_minutes)

    #keys are stored by date prefix so it scan today and yesterday
    prefixes = [
        f"trust-centre/logins/{now:%Y/%m/%d}/",
        f"trust-centre/logins/{(now - timedelta(days=1)):%Y/%m/%d}/",
    ]

    events: List[Dict[str, Any]] = []
    for pref in prefixes:
        for key in listKeys(s3, bucket=bucket, prefix=pref):
            try:
                obj = s3.get_object(Bucket=bucket, Key=key)
                e = json.loads(obj["Body"].read().decode("utf-8"))

                # only keep this user's events
                if e.get("user_id") != user_id:
                    continue

                ts = parseIso(e["ts_utc"])
                if ts >= cutoff:
                    events.append(e)
            except Exception:
                continue

    events.sort(key=lambda x: x.get("ts_utc", ""))
    return events


def detect_suspicious_from_history(
    *,
    now: datetime,
    this_success: bool,
    history_events: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    #applies policies using history events
    """

    w2m = now - timedelta(seconds=SuspiciousPolicy.HIGH_ATTEMPT_WINDOW_SEC)
    w5m = now - timedelta(seconds=SuspiciousPolicy.FAIL_THEN_SUCCESS_WINDOW_SEC)

    w10m = now - timedelta(seconds=SuspiciousPolicy.FEATURE_WINDOW_10M_SEC)

    parsed: List[tuple[datetime, bool]] = []
    for e in history_events:
        try:
            dt = parseIso(e["ts_utc"])
            ok = bool(e.get("success", False))
            parsed.append((dt, ok))
        except Exception:
            continue

    attempt2m = sum(1 for (dt, _) in parsed if withinTime(dt, w2m, now))
    attempt10m = sum(1 for (dt, _) in parsed if withinTime(dt, w10m, now))

    failure5m = sum(1 for (dt, ok) in parsed if withinTime(dt, w5m, now) and not ok)
    failure10m = sum(1 for (dt, ok) in parsed if withinTime(dt, w10m, now) and not ok)

    successes10m = sum(1 for (dt, ok) in parsed if withinTime(dt, w10m, now) and ok)

    #last successful login time for timeSinceLastloginsec
    last_success_dt: Optional[datetime] = None
    for dt, ok in sorted(parsed, key=lambda x: x[0], reverse=True):
        if ok:

            last_success_dt = dt
            break

    time_since_last_login_sec: Optional[int] = None
    if last_success_dt is not None:
        time_since_last_login_sec = int((now - last_success_dt).total_seconds())

    features = {
        "hourOfDay": now.hour,
        "dayOfWeek": now.weekday(),
        #^Monday=0,Sunday=6

        "success": 1 if this_success else 0,
        "failuresLast10m": failure10m,
        "attemptsLast10m": attempt10m,
        "timeSinceLastLoginSec": time_since_last_login_sec,

    }

    reasons: List[str] = []

    #Rule 1 for high attempt rate and includes this attempt

    if (attempt2m + 1) >= SuspiciousPolicy.HIGH_ATTEMPT_N:
        reasons.append("HIGH_ATTEMPT_RATE: >=5 attempts in 2m")

    #Rule 2 for login failures then success

    if this_success and failure5m >= SuspiciousPolicy.FAIL_THEN_SUCCESS_FAIL_N:
        reasons.append("FAILURES_THEN_SUCCESS: >=5 failures in 5m before success")
    #Rule 3 for unusual time of day
    h = features["hourOfDay"]
    if h >= SuspiciousPolicy.UNUSUAL_START_HOUR or h <= SuspiciousPolicy.UNUSUAL_END_HOUR:

        reasons.append("UNUSUAL_HOUR: 23:00–06:00")

    # Rule 4 for rapid repeated logins

    if this_success and (successes10m + 1) >= SuspiciousPolicy.RAPID_SUCCESS_N:
        reasons.append("RAPID_SUCCESS_LOGINS: >=5 successes in 10m")

    anomalous = len(reasons) > 0
    return {
        "decision": "SUSPICIOUS" if anomalous else "NORMAL",
        "anomalous": anomalous,
        "reasons": reasons,
        "features": features,

    }


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
    s3 = _s3(region)
    now = utcnow()

    key = f"trust-centre/logins/{now:%Y/%m/%d}/{uuid.uuid4().hex}.json"

    event: Dict[str, Any] = {
        "event": "login",
        "ts_utc": now.isoformat(),
        "user_id": user_id,
        "success": success,
        "reason": reason,
    }

    if extra:
        event["extra"] = extra

    if user_id:    #history-based detection if user ID
        history = read_recent_login_events(bucket=bucket, region=region, user_id=user_id, lookback_minutes=10)
        detection = detect_suspicious_from_history(now=now, this_success=success, history_events=history)
        event.update(detection)
    else:
        event.update({"decision": "UNKNOWN", "anomalous": False, "reasons": [], "features": {}})

    s3.put_object(
        Bucket=bucket,
        Key=key,
        Body=json.dumps(event).encode("utf-8"),
        ContentType="application/json",
    )

    return key