"""
Timestamp utilities for MediaWiki signature format handling.

Provides functions to parse, format, and convert timestamps between Python
datetime objects and MediaWiki's signature timestamp format.
"""

import re
import time
import calendar
from datetime import datetime, timezone
from typing import Optional


# Regex to find the "Last updated: ..." line produced by ~~~~~ format.
LAST_UPDATED_RE = re.compile(
    r"(?im)^\s*Last\s+updated:\s*(?P<ts>\d{1,2}:\d{2},\s*\d{1,2}\s+[A-Za-z]+\s+\d{4}\s*\(UTC\))\s*$"
)


def parse_mediawiki_sig_timestamp(timestamp_str: str) -> datetime:
    """
    Parse a MediaWiki ~~~~~ timestamp like "19:32, 19 August 2025 (UTC)" into aware UTC datetime.
    """
    timestamp_str = timestamp_str.strip()
    # Example format: "19:32, 19 August 2025 (UTC)"
    datetime_obj = datetime.strptime(timestamp_str, "%H:%M, %d %B %Y (UTC)")
    return datetime_obj.replace(tzinfo=timezone.utc)


def to_mediawiki_sig_timestamp(datetime_obj: datetime) -> str:
    """
    Convert aware UTC datetime -> "HH:MM, D Month YYYY (UTC)"
    """
    if datetime_obj.tzinfo is None:
        datetime_obj = datetime_obj.replace(tzinfo=timezone.utc)
    datetime_obj = datetime_obj.astimezone(timezone.utc)
    day = datetime_obj.day
    # Build without platform-specific %-d
    return datetime_obj.strftime(f"%H:%M, {day} %B %Y (UTC)")


def extract_last_updated(text: str) -> Optional[datetime]:
    """
    Extract the 'Last updated' timestamp from page text.

    Args:
        text: Wiki page text containing a "Last updated: ..." line

    Returns:
        Parsed datetime in UTC, or None if not found
    """
    match = LAST_UPDATED_RE.search(text)
    if not match:
        return None
    return parse_mediawiki_sig_timestamp(match.group("ts"))


def iso8601_from_dt(datetime_obj: datetime) -> str:
    """Return ISO8601 with 'Z'."""
    return datetime_obj.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def to_mediawiki_timestamp(timestamp_value) -> str:
    """
    Convert various timestamp representations to MediaWiki sig timestamp:
      - str in ISO8601 "YYYY-MM-DDTHH:MM:SSZ"
      - time.struct_time (as returned by mwclient logevents)
      - datetime (naive or aware)
    """
    if isinstance(timestamp_value, str):
        datetime_obj = datetime.strptime(timestamp_value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    elif isinstance(timestamp_value, time.struct_time):
        # struct_time is in UTC for MediaWiki API; use calendar.timegm
        datetime_obj = datetime.fromtimestamp(calendar.timegm(timestamp_value), tz=timezone.utc)
    elif isinstance(timestamp_value, datetime):
        datetime_obj = timestamp_value if timestamp_value.tzinfo else timestamp_value.replace(tzinfo=timezone.utc)
    else:
        raise TypeError(f"Unsupported timestamp type: {type(timestamp_value)!r}")
    return to_mediawiki_sig_timestamp(datetime_obj)


__all__ = [
    'LAST_UPDATED_RE',
    'parse_mediawiki_sig_timestamp',
    'to_mediawiki_sig_timestamp',
    'extract_last_updated',
    'iso8601_from_dt',
    'to_mediawiki_timestamp',
]
