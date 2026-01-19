#!/usr/bin/env python3
"""
One-off script to backfill pending changes (stable) log entries from 2025 to present.

This script generates AE protection log entries for pending changes protections
that were missed because the main bot only monitored type=protect events.

Output goes to: User:ClerkBot/T3/pending_changes_2025

Usage:
    ./venv/bin/python backfill_pending_changes.py

Requires .env file with CLERKBOT_USERNAME and CLERKBOT_PASSWORD.
"""

import json
import logging
import os
import re
import sys
import time
import calendar
from datetime import datetime, timezone
from typing import Dict, Iterable, List
from urllib.request import urlopen, Request

import mwclient

# Load .env file
from pathlib import Path
env_path = Path(__file__).parent / ".env"
if env_path.exists():
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, _, value = line.partition("=")
            value = value.strip().strip('"').strip("'")
            os.environ.setdefault(key.strip(), value)

# Configuration
USERNAME = os.environ.get("CLERKBOT_USERNAME")
PASSWORD = os.environ.get("CLERKBOT_PASSWORD")
TARGET_PAGE = "User:ClerkBot/T3/pending_changes_2025"
API_HOST = "en.wikipedia.org"
API_PATH = "/w/"
USER_AGENT = "ClerkBot-Backfill/1.0 (https://en.wikipedia.org/wiki/User:ClerkBot)"

# Backfill range
START_DATE = datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

# Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

# AE trigger phrases (same as main bot)
AE_TRIGGERS = [
    "arbitration", "arbcom", "ctop", "ct/", "contentious topic",
    "blpct", "blpds", "arbpia",
    "wp:ae ", "wikipedia:ae ", "wp:ae|", "wikipedia:ae|", "wp:ae]", "wikipedia:ae]",
]

# Topic detection config URL
CONFIG_URL = "https://en.wikipedia.org/w/index.php?title=User:ClerkBot/T3/config.json&action=raw&ctype=application/json"


class TopicDetector:
    """Detects CTOP topic codes from edit summaries."""

    def __init__(self, codes: List[str], page_to_code: Dict[str, str], override_strings: Dict[str, str]):
        self.codes = sorted([c.lower() for c in codes], key=len, reverse=True)
        def _norm(s: str) -> str:
            return (
                (s or "").lower()
                .replace("\u2013", "-").replace("\u2014", "-")
                .replace("\u2010", "-").replace("\u2212", "-")
            )
        self._norm = _norm
        self.page_to_code = {_norm(page): (code or "").lower() for page, code in page_to_code.items()}
        self._code_res = {
            code: re.compile(r"(?i)(?<![A-Za-z])" + re.escape(code) + r"(?![A-Za-z])")
            for code in self.codes
        }
        self._ctop_shortcut_re = re.compile(r"(?i)(?:wp|wikipedia):ct(?:op)?/([A-Za-z-]+)")
        self.override_strings = override_strings

    def detect(self, comment: str) -> str:
        comment = (comment or "")
        lower = self._norm(comment)

        # Heuristic 1: WP:CT/<code> shortcuts
        match = self._ctop_shortcut_re.search(lower)
        if match:
            code = match.group(1).lower()
            if code in self.codes:
                return code

        # Heuristic 2: specific page string
        for page_norm, code in self.page_to_code.items():
            if page_norm in lower:
                return code

        # Heuristic 3: override strings
        for override, code in self.override_strings.items():
            if override in lower:
                return code

        # Heuristic 4: bare code token
        for code in self.codes:
            if self._code_res[code].search(lower):
                if code not in ("at",):  # temporary fix
                    return code

        return ""


def load_topics() -> TopicDetector:
    """Load topic detection configuration from Wikipedia."""
    log.info("Fetching topics configuration...")
    request = Request(CONFIG_URL, headers={'User-Agent': USER_AGENT})
    with urlopen(request) as response:
        data = json.loads(response.read().decode("utf-8"))
    codes = data.get("codes", [])
    page_to_code = data.get("specific_pages", {})
    override_strings = data.get("override_strings", {})
    if not codes or not page_to_code:
        raise ValueError("Configuration JSON missing required keys")
    return TopicDetector(codes=codes, page_to_code=page_to_code, override_strings=override_strings)


def is_arbitration_enforcement(comment: str) -> bool:
    comment_lower = (comment or "").lower()
    return any(trigger in comment_lower for trigger in AE_TRIGGERS)


def iso8601_from_dt(datetime_obj: datetime) -> str:
    return datetime_obj.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def to_mediawiki_sig_timestamp(datetime_obj: datetime) -> str:
    if datetime_obj.tzinfo is None:
        datetime_obj = datetime_obj.replace(tzinfo=timezone.utc)
    datetime_obj = datetime_obj.astimezone(timezone.utc)
    day = datetime_obj.day
    return datetime_obj.strftime(f"%H:%M, {day} %B %Y (UTC)")


def to_mediawiki_timestamp(timestamp_value) -> str:
    if isinstance(timestamp_value, str):
        datetime_obj = datetime.strptime(timestamp_value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    elif isinstance(timestamp_value, time.struct_time):
        datetime_obj = datetime.fromtimestamp(calendar.timegm(timestamp_value), tz=timezone.utc)
    elif isinstance(timestamp_value, datetime):
        datetime_obj = timestamp_value if timestamp_value.tzinfo else timestamp_value.replace(tzinfo=timezone.utc)
    else:
        raise TypeError(f"Unsupported timestamp type: {type(timestamp_value)!r}")
    return to_mediawiki_sig_timestamp(datetime_obj)


def format_expiry(expiry: str) -> str:
    """Format expiry string for display."""
    if not expiry or expiry == "infinity":
        return "indefinite"
    # Format: YYYYMMDDHHMMSS -> human readable
    try:
        dt = datetime.strptime(expiry, "%Y%m%d%H%M%S")
        return dt.strftime("%H:%M, %d %B %Y")
    except ValueError:
        return expiry  # fallback to raw value


def build_action_string(log_event: dict) -> str:
    action = log_event.get("action", "")
    params = log_event.get("params") or {}
    autoreview = params.get("autoreview") or ""
    expiry = params.get("expiry") or ""

    if action == "config":
        base = "added pending changes protection"
    elif action == "modify":
        base = "changed pending changes level"
    else:
        return action or ""

    # Build details string
    details = []
    if autoreview:
        details.append(f"autoreview={autoreview}")
    if expiry:
        details.append(f"expires {format_expiry(expiry)}")

    if details:
        return f"{base} ({', '.join(details)})"
    return base


def format_entry(log_event: dict, topic_code: str) -> str:
    logid = log_event.get("logid")
    user = log_event.get("user") or ""
    title = log_event.get("title") or ""
    timestamp_value = log_event.get("timestamp")
    comment = log_event.get("comment") or ""

    date_str = to_mediawiki_timestamp(timestamp_value)
    action_str = build_action_string(log_event)

    return (
        "{{User:ClerkBot/AE entry"
        f"|logid={logid}"
        f"|admin={user}"
        f"|page={title}"
        f"|date={date_str}"
        f"|action={action_str}"
        f"|summary={comment}"
        f"|topic={topic_code}"
        "}}"
    )


def get_event_sort_key(log_event: dict) -> float:
    timestamp_value = log_event.get("timestamp")
    if isinstance(timestamp_value, time.struct_time):
        return calendar.timegm(timestamp_value)
    elif isinstance(timestamp_value, str):
        dt = datetime.strptime(timestamp_value, "%Y-%m-%dT%H:%M:%SZ")
        return dt.replace(tzinfo=timezone.utc).timestamp()
    elif isinstance(timestamp_value, datetime):
        return timestamp_value.timestamp()
    return 0.0


def connect_site() -> mwclient.Site:
    site = mwclient.Site(API_HOST, scheme="https", path=API_PATH, clients_useragent=USER_AGENT)
    site.login(USERNAME, PASSWORD)
    return site


def enumerate_stable_logevents(site: mwclient.Site, start_utc: datetime) -> Iterable[dict]:
    """Iterate stable (pending changes) logevents from start_utc to now."""
    start_iso = iso8601_from_dt(start_utc)
    log.info("Fetching stable logevents from %s (dir=newer)", start_iso)

    for log_event in site.logevents(type="stable", start=start_iso, dir="newer"):
        action = log_event.get("action")
        if action in ("reset", "move_stable"):
            continue  # skip removals and page moves
        yield log_event


def main() -> int:
    if not USERNAME or not PASSWORD:
        log.error("Missing CLERKBOT_USERNAME or CLERKBOT_PASSWORD in environment/.env")
        return 2

    # Load topic detector
    try:
        detector = load_topics()
    except Exception as e:
        log.error("Failed to load topic configuration: %s", e)
        return 2

    log.info("Connecting to Wikipedia...")
    site = connect_site()

    log.info("Fetching stable log events from %s to now...", START_DATE.date())

    # Collect all events
    all_events = list(enumerate_stable_logevents(site, START_DATE))
    log.info("Found %d total stable log events", len(all_events))

    # Filter to AE-related only
    ae_events = [e for e in all_events if is_arbitration_enforcement(e.get("comment") or "")]
    log.info("Found %d AE-related stable log events", len(ae_events))

    if not ae_events:
        log.info("No AE-related pending changes events found. Nothing to do.")
        return 0

    # Sort by timestamp
    ae_events.sort(key=get_event_sort_key)

    # Format entries with topic detection
    entries = []
    for e in ae_events:
        comment = e.get("comment") or ""
        topic_code = detector.detect(comment)
        entries.append(format_entry(e, topic_code))

    # Build page content
    now_str = to_mediawiki_sig_timestamp(datetime.now(tz=timezone.utc))
    page_content = f"""Backfill of pending changes (stable) log entries for AE protections.

Generated: {now_str}

Period: 1 January 2025 to present

Total entries: {len(entries)}

{{{{/header}}}}
""" + "\n".join(entries) + "\n{{/footer}}\n"

    # Save to target page
    log.info("Saving %d entries to %s", len(entries), TARGET_PAGE)
    token = site.get_token('csrf')

    res = site.api(
        'edit',
        title=TARGET_PAGE,
        text=page_content,
        summary=f"Backfill of {len(entries)} pending changes AE protection entries (2025-present)",
        bot=True,
        token=token,
    )
    log.info("Edit result: %s", res.get("edit", {}).get("result", "unknown"))

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except mwclient.errors.APIError as e:
        log.error("MediaWiki API error: %s", e)
        sys.exit(1)
    except Exception as e:
        log.exception("Unhandled exception: %s", e)
        sys.exit(1)
