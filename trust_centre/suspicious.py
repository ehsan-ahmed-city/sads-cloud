from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple



#helper functions:
def parse_ts(ts: Any) -> datetime:
    """
    func accepts a datetime object or iso string and
    normalises it into UTC datetime to ensures all comparisons
    are consistent regardless of how timestamps r logged 
    """

     
    if isinstance(ts, datetime):#useed directly
        dt = ts

    
    elif isinstance(ts, str):# If string, parse ISO format
        s = ts.replace("Z", "+00:00")#replace Z fromisoformat
        dt = datetime.fromisoformat(s)


    else:
        raise TypeError(f"Unsupported ts type: {type(ts)}")


    if dt.tzinfo is None:#(default to UTC if missing)
        dt = dt.replace(tzinfo=timezone.utc)

    return dt.astimezone(timezone.utc)


def _within(dt: datetime, start: datetime, end: datetime) -> bool: #function check whether a datetime lies within a time window

    return start <= dt <= end


def _hour(dt: datetime) -> int:
    
    #Extract hour-of-day from timestamp (0–23)
    
    return dt.hour


def _dow(dt: datetime) -> int:#day of week
    return dt.weekday()



#policy boundaries based on rules set

@dataclass(frozen=True)
class SuspiciousPolicy:
    
    #config object holding all anomaly detection thresholds

    
    high_attempts_n: int = 5# High attempt rate eg. 5 logins in 2 mins
    attemptWinSec: int = 120 #attempt window in seconds

    #Failures followed by success (maybe brute force) and triggers if >=5 failures occurred within 5 minutes before a success
    failThenSuccessN: int = 5
    failThenSuccessSec: int = 300  # 5 minutes

    unusual_start_hour: int = 23   #weird login hours (late night/early morning)
    unusual_end_hour: int = 6

    # Rapid repeated successful logins
    rapid_success_n: int = 5
    rapid_success_window_sec: int = 600  # 10 minutes

    # Feature extraction window (for ML / logging)
    feature_window_10m_sec: int = 600  # 10 minutes


# Main detection function


def detect_suspicious_login(
    *,
    user_id: str,
    now_ts: Any,                     # datetime or ISO string
    success: bool,
    history_events: List[Dict[str, Any]],
    policy: SuspiciousPolicy = SuspiciousPolicy(),
) -> Dict[str, Any]:
    """
    Detect whether a login attempt is suspicious according
    to my defined security policys

    Parameters

    user_id: cognito user identifier
    now_ts: Timestamp of current login attempt
    sucess: whether the current login attempt succeeded
    history_events: prior login attempts for this user

    Returns

    Dict for logging and alerts:
    {
        "decision": "SUSPICIOUS" or"NORMAL",
        "anomalous": bool,
        "reasons": [str],
        "features": {}
    }
    """

    #parse current timestamp into UTC datetime
    now_dt = parse_ts(now_ts)

    #filter history to specific user
    user_hist = [e for e in history_events if e.get("user_id") == user_id]

    #parse historical timestamps once
    parsed: List[Tuple[datetime, bool]] = []
    for e in user_hist:
        try:
            dt = parse_ts(e["ts"])
            ok = bool(e.get("success", False))
            parsed.append((dt, ok))
        except Exception:
            #ignores corrupt log entries
            continue

 
    #rolling time windows
    w2m = now_dt - timedelta(seconds=policy.attemptWinSec)
    w5m = now_dt - timedelta(seconds=policy.failThenSuccessSec)
    w10m = now_dt - timedelta(seconds=policy.feature_window_10m_sec)

   
 

    #Total num attempts in last 2 mins
    attempts_2m = sum(
        1 for (dt, _) in parsed if _within(dt, w2m, now_dt)
    )

    #Total num attempts in last 10 mins
    attempts_10m = sum(
        1 for (dt, _) in parsed if _within(dt, w10m, now_dt)
    )

    #failed num attempts in last 5 min
    failures_5m = sum(
        1 for (dt, ok) in parsed if _within(dt, w5m, now_dt) and not ok
    )

    #failed num attempts in last 10 min
    failures_10m = sum(
        1 for (dt, ok) in parsed if _within(dt, w10m, now_dt) and not ok
    )

    #successful attempts in last 10 mins
    successes_10m = sum(
        1 for (dt, ok) in parsed if _within(dt, w10m, now_dt) and ok
    )


    #time since last successful login

    last_success_dt: Optional[datetime] = None
    for dt, ok in sorted(parsed, key=lambda x: x[0], reverse=True):
        if ok:
            last_success_dt = dt
            break

    time_since_last_login_sec: Optional[int] = None
    if last_success_dt is not None:
        time_since_last_login_sec = int(
            (now_dt - last_success_dt).total_seconds()
        )




    features = {    #added vector for logging and ml
        "hourOfDay": _hour(now_dt),
        "dayOfWeek": _dow(now_dt),
        "success": 1 if success else 0,
        "failuresLast10m": failures_10m,
        "attemptsLast10m": attempts_10m,
        "timeSinceLastLoginSec": time_since_last_login_sec,
    }

    reasons: List[str] = []


    #Rule-based detection:#


    #rule 1 if high attempt rate
    if (attempts_2m + 1) >= policy.high_attempts_n:
        reasons.append(
            f"HIGH_ATTEMPT_RATE: >= {policy.high_attempts_n} attempts "
            f"in {policy.attemptWinSec // 60}m"
        )


    #rule 2 is failures followed by success which is brite force
    if success and failures_5m >= policy.failThenSuccessN:
        reasons.append(
            f"FAILURES_THEN_SUCCESS: {failures_5m} failures "
            f"within {policy.failThenSuccessSec // 60}m before success"
        )

    #rule 3 is unusual login time like 11pm to 6am window
    h = features["hourOfDay"]
    if h >= policy.unusual_start_hour or h <= policy.unusual_end_hour:
        reasons.append("UNUSUAL_HOUR: login during 23:00–06:00")

    #Rule 4 is quick repeated successful logins
    if success and (successes_10m + 1) >= policy.rapid_success_n:
        reasons.append(
            f"RAPID_SUCCESS_LOGINS: >= {policy.rapid_success_n} successes "
            f"within {policy.rapid_success_window_sec // 60}m"
        )


    #fnal decision
    anomalous = len(reasons) > 0

    return {
        "decision": "SUSPICIOUS" if anomalous else "NORMAL",
        "anomalous": anomalous,
        "reasons": reasons,
        "features": features,
    }
