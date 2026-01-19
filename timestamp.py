"""
Timestamp and utility functions for MediaWiki bot operations.

Provides functions to parse, format, and convert timestamps between Python
datetime objects and MediaWiki's signature timestamp format, as well as
general text processing utilities.
"""

import re
import time
import calendar
import unicodedata
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


def clean_invisible_unicode(text: str) -> str:
    """Remove invisible Unicode characters that could cause display issues."""
    if not text:
        return text

    # Remove common problematic invisible Unicode characters
    # LTR/RTL marks and other directional formatting characters
    invisible_chars = [
        '\u200E', '\u200F',  # LTR/RTL marks
        '\u202A', '\u202B', '\u202C', '\u202D', '\u202E',  # Directional formatting
        '\u2066', '\u2067', '\u2068', '\u2069',  # Directional isolates
        '\uFEFF',  # Zero Width No-Break Space (BOM)
        '\u200B', '\u200C', '\u200D',  # Zero width characters
    ]

    cleaned = text
    for char in invisible_chars:
        cleaned = cleaned.replace(char, '')

    # Also remove other control characters except newlines, tabs, and carriage returns
    cleaned = ''.join(char for char in cleaned
                     if unicodedata.category(char)[0] != 'C' or char in '\n\t\r')

    return cleaned


def format_expiry(expiry: str) -> str:
    """
    Format a MediaWiki expiry string for human-readable display.

    Args:
        expiry: Expiry in YYYYMMDDHHMMSS format or "infinity"

    Returns:
        Human-readable string like "17:03, 27 February 2026" or "indefinite"
    """
    if not expiry or expiry == "infinity":
        return "indefinite"
    try:
        dt = datetime.strptime(expiry, "%Y%m%d%H%M%S")
        return dt.strftime("%H:%M, ") + str(dt.day) + dt.strftime(" %B %Y")
    except ValueError:
        return expiry  # fallback to raw value


__all__ = [
    'LAST_UPDATED_RE',
    'parse_mediawiki_sig_timestamp',
    'to_mediawiki_sig_timestamp',
    'extract_last_updated',
    'iso8601_from_dt',
    'to_mediawiki_timestamp',
    'clean_invisible_unicode',
    'format_expiry',
]
