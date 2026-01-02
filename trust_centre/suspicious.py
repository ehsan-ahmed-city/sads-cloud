from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple


#p[pp]
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