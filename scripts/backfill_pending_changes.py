#!/usr/bin/env python3
"""
One-off script to backfill pending changes (stable) log entries from 2025 to present.

This script generates AE protection log entries for pending changes protections
that were missed because the main bot only monitored type=protect events.

Output goes to: User:ClerkBot/T3/pending_changes_2025

Usage:
    ./venv/bin/python scripts/backfill_pending_changes.py

Requires .env file with CLERKBOT_USERNAME and CLERKBOT_PASSWORD.
"""

import calendar
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

import mwclient

# Load .env file manually (to avoid requiring python-dotenv for this script)
env_path = Path(__file__).parent.parent / ".env"
if env_path.exists():
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, _, value = line.partition("=")
            value = value.strip().strip('"').strip("'")
            os.environ.setdefault(key.strip(), value)

# Import from shared modules
from clerkbot.constants import FOOTER_MARK, HEADER_MARK
from clerkbot.entries import format_entry
from clerkbot.filters import is_arbitration_enforcement
from clerkbot.timestamp import iso8601_from_dt, to_mediawiki_sig_timestamp
from clerkbot.topics import load_topics

# Configuration
USERNAME = os.environ.get("CLERKBOT_USERNAME")
PASSWORD = os.environ.get("CLERKBOT_PASSWORD")
TARGET_PAGE = "User:ClerkBot/T3/pending_changes_2025"
API_HOST = "en.wikipedia.org"
API_PATH = "/w/"
USER_AGENT = "ClerkBot-Backfill/1.0 (https://en.wikipedia.org/wiki/User:ClerkBot)"

# Topics configuration URL
CONFIG_URL = "https://en.wikipedia.org/w/index.php?title=User:ClerkBot/T3/config.json&action=raw&ctype=application/json"

# Backfill range
START_DATE = datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

# Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)


def connect_site() -> mwclient.Site:
    """Connect to MediaWiki site and authenticate."""
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


def get_event_sort_key(log_event: dict) -> float:
    """Extract a sortable timestamp from a log event."""
    timestamp_value = log_event.get("timestamp")
    if isinstance(timestamp_value, time.struct_time):
        return calendar.timegm(timestamp_value)
    elif isinstance(timestamp_value, str):
        dt = datetime.strptime(timestamp_value, "%Y-%m-%dT%H:%M:%SZ")
        return dt.replace(tzinfo=timezone.utc).timestamp()
    elif isinstance(timestamp_value, datetime):
        return timestamp_value.timestamp()
    return 0.0


def main() -> int:
    if not USERNAME or not PASSWORD:
        log.error("Missing CLERKBOT_USERNAME or CLERKBOT_PASSWORD in environment/.env")
        return 2

    # Load topic detector
    try:
        detector = load_topics(CONFIG_URL, USER_AGENT)
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

{HEADER_MARK}
""" + "\n".join(entries) + "\n" + FOOTER_MARK + "\n"

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
