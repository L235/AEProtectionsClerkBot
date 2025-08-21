#!/usr/bin/env python3
"""
ClerkBot — AE protection actions logger

- Uses mwclient (MediaWiki Python client).
- All configuration via environment variables.
- Designed to run via cron.
- Appends new arbitration enforcement protection actions to a target page.

Environment variables (all ASCII):

  CLERKBOT_USERNAME           Required. BotPassword username, e.g. "ClerkBot@AEProtections"
  CLERKBOT_PASSWORD           Required. BotPassword password
  CLERKBOT_TARGET_PAGE        Required. e.g. "User:ClerkBot/AE protection log"
  CLERKBOT_API_HOST           Optional. Host for wiki (default: "en.wikipedia.org")
  CLERKBOT_API_PATH           Optional. Path (default: "/w/")
  CLERKBOT_USER_AGENT         Optional. Shown in requests (default set below)
  CLERKBOT_TOPICS_PATH        Optional. Path to topics JSON (default: "ctop_topics.json" in same dir)
  CLERKBOT_DRY_RUN            Optional. "1" to run without saving edits
  CLERKBOT_UPDATE_TIMESTAMP   Optional. "1" to update the leading "Last updated: ..." line to current UTC

The target page must begin with a line like:
  Last updated: 19:32, 19 August 2025 (UTC)

This script will NOT change anything but appending entries unless CLERKBOT_UPDATE_TIMESTAMP=1.
"""

import json
import logging
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
import time
import calendar
from typing import Dict, Iterable, List, Optional, Tuple

import mwclient
from mwclient.page import Page as MWPage  # correct type for page objects


# --------- Logging ---------
LOG_LEVEL = os.environ.get("CLERKBOT_LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger(__name__)

# --------- Configuration ---------
USERNAME = os.environ.get("CLERKBOT_USERNAME")
PASSWORD = os.environ.get("CLERKBOT_PASSWORD")
TARGET_PAGE = os.environ.get("CLERKBOT_TARGET_PAGE")

API_HOST = os.environ.get("CLERKBOT_API_HOST", "en.wikipedia.org")
API_PATH = os.environ.get("CLERKBOT_API_PATH", "/w/")
USER_AGENT = os.environ.get(
    "CLERKBOT_USER_AGENT",
    "ClerkBot-AEProtections/1.0 (https://en.wikipedia.org/wiki/User:ClerkBot)",
)
TOPICS_PATH = os.environ.get("CLERKBOT_TOPICS_PATH")
DRY_RUN = os.environ.get("CLERKBOT_DRY_RUN", "0") == "1"
UPDATE_TIMESTAMP = os.environ.get("CLERKBOT_UPDATE_TIMESTAMP", "0") == "1"

if not USERNAME or not PASSWORD or not TARGET_PAGE:
    log.error("Missing required environment variables. "
              "Set CLERKBOT_USERNAME, CLERKBOT_PASSWORD, CLERKBOT_TARGET_PAGE.")
    sys.exit(2)

# Where to find the topics JSON by default
if not TOPICS_PATH:
    # Resolve to the directory of this script
    TOPICS_PATH = str(Path(__file__).with_name("ctop_topics.json"))

# --------- Constants ---------

# AE trigger phrases (case-insensitive) to detect arbitration enforcement
AE_TRIGGERS = [
    "arbitration",
    "arbcom",
    "ctop",
    "ct/",
    "30/500",
    "contentious topic",
    "blpct",
    "blpds",
    "arbpia",
]

# Regex to find the "Last updated: ..." line produced by ~~~~~ format.
LAST_UPDATED_RE = re.compile(
    r"(?im)^\s*Last\s+updated:\s*(?P<ts>\d{1,2}:\d{2},\s*\d{1,2}\s+[A-Za-z]+\s+\d{4}\s*\(UTC\))\s*$"
)

# Template entry pattern to find existing logids and avoid duplicates on append
ENTRY_LOGID_RE = re.compile(r"\{\{\/entry\|[^}]*\blogid=(\d+)\b[^}]*\}\}", re.DOTALL)


# --------- Utilities ---------

def parse_mediawiki_sig_timestamp(ts_str: str) -> datetime:
    """
    Parse a MediaWiki ~~~~~ timestamp like "19:32, 19 August 2025 (UTC)" into aware UTC datetime.
    """
    ts_str = ts_str.strip()
    # Example format: "19:32, 19 August 2025 (UTC)"
    dt = datetime.strptime(ts_str, "%H:%M, %d %B %Y (UTC)")
    return dt.replace(tzinfo=timezone.utc)


def to_mediawiki_sig_timestamp(dt: datetime) -> str:
    """
    Convert aware UTC datetime -> "HH:MM, D Month YYYY (UTC)"
    Note: %-d works on Linux; on Windows use %#d. We normalize via manual day int.
    """
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc)
    day = dt.day
    # Build without platform-specific %-d
    return dt.strftime(f"%H:%M, {day} %B %Y (UTC)")


def extract_last_updated(text: str) -> Optional[datetime]:
    m = LAST_UPDATED_RE.search(text)
    if not m:
        return None
    return parse_mediawiki_sig_timestamp(m.group("ts"))


def extract_existing_logids(text: str) -> set:
    return set(int(x) for x in ENTRY_LOGID_RE.findall(text))


def is_arbitration_enforcement(comment: str) -> bool:
    c = (comment or "").lower()
    return any(trigger in c for trigger in AE_TRIGGERS)


def mediawiki_param_nowiki(value: str) -> str:
    """
    Wrap a parameter value in <nowiki> to avoid template-breaking characters (|, }}, [[]], etc.).
    """
    value = value or ""
    return "<nowiki>" + value + "</nowiki>"


def iso8601_from_dt(dt: datetime) -> str:
    """Return ISO8601 with 'Z'."""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------- Topic detection ---------

class TopicDetector:
    """
    Detects CTOP topic codes from edit summaries using the required heuristics, in order:

    (1) If a topic code appears in the comment, not surrounded by letters (case-insensitive), return that code.
    (2) If a WP:CT/$CODE shortcut appears, return $CODE.
    (3) If a CTOP specific page appears, return the corresponding code.
    """

    def __init__(self, codes: List[str], specific_pages: Dict[str, str]):
        self.codes = sorted([c.lower() for c in codes], key=len, reverse=True)
        # Normalize specific pages for case-insensitive match and common dash variants
        def _norm(s: str) -> str:
            return (
                (s or "")
                .lower()
                .replace("\u2013", "-")  # en dash
                .replace("\u2014", "-")  # em dash
                .replace("\u2010", "-")  # hyphen
                .replace("\u2212", "-")  # minus sign
            )
        self._norm = _norm
        self.specific_pages = {code.lower(): _norm(page) for code, page in specific_pages.items()}
        # Precompile regexes for code token matches
        self._code_res = {
            code: re.compile(r"(?i)(?<![A-Za-z])" + re.escape(code) + r"(?![A-Za-z])")
            for code in self.codes
        }
        # Regex to catch WP:CT/<code> with optional spaces around the colon and slash
        self._ctop_shortcut_re = re.compile(r"(?i)wp\s*:\s*ct\s*/\s*([A-Za-z-]+)")

    def detect(self, comment: str) -> str:
        comment = (comment or "")
        lower = self._norm(comment)

        # Heuristic (1): bare code token
        for code in self.codes:
            if self._code_res[code].search(lower):
                return code

        # Heuristic (2): WP:CT/<code>
        m = self._ctop_shortcut_re.search(lower)
        if m:
            code = m.group(1).lower()
            if code in self.codes:
                return code

        # Heuristic (3): specific page string appears anywhere
        for code, page in self.specific_pages.items():
            if page in lower:
                return code

        return ""


def load_topics(path: str) -> TopicDetector:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    codes = data.get("codes", [])
    specific_pages = data.get("specific_pages", {})
    if not codes or not specific_pages:
        raise ValueError("ctop_topics.json missing required keys 'codes' or 'specific_pages'")
    return TopicDetector(codes=codes, specific_pages=specific_pages)


# --------- Core logic ---------

def connect_site() -> mwclient.Site:
    # Use the modern 'scheme' argument to avoid deprecation warnings.
    site = mwclient.Site(
        API_HOST,
        scheme="https",
        path=API_PATH,
        clients_useragent=USER_AGENT,
    )
    site.login(USERNAME, PASSWORD)
    return site


def fetch_target_page(site: mwclient.Site, title: str) -> MWPage:
    return site.pages[title]


def enumerate_protect_logevents(
    site: mwclient.Site,
    start_utc: datetime,
) -> Iterable[dict]:
    """
    Iterate logevents (type=protect) newer than start_utc. Skip 'unprotect' actions.
    mwclient handles API continuation internally.
    """
    start_iso = iso8601_from_dt(start_utc)
    log.info("Fetching logevents from %s (dir=newer)", start_iso)

    # props include user, timestamp, comment, details/params
    # mwclient uses 'dir' (older/newer), 'type', 'start'
    for ev in site.logevents(type="protect", start=start_iso, dir="newer"):
        # ev is a dict-like structure
        action = ev.get("action")
        if action == "unprotect":
            continue  # explicit removals of protection
        yield ev


def build_action_string(ev: dict) -> str:
    """
    ACTION is constructed as:
      - if action == 'protect': "added protection (<description>)"
      - if action == 'modify':  "changed protection level (<description>)"
      - otherwise: use the raw action string.
    Description is ev['params']['description'] when available.
    """
    action = ev.get("action", "")
    desc = ""
    params = ev.get("params") or {}
    desc = params.get("description") or ""
    if action == "protect":
        base = "added protection"
    elif action == "modify":
        base = "changed protection level"
    else:
        return action or ""
    if desc:
        return f"{base} ({desc})"
    return base


def to_mediawiki_timestamp(ts_value) -> str:
    """
    Convert various timestamp representations to MediaWiki sig timestamp:
      - str in ISO8601 "YYYY-MM-DDTHH:MM:SSZ"
      - time.struct_time (as returned by mwclient logevents)
      - datetime (naive or aware)
    """
    if isinstance(ts_value, str):
        dt = datetime.strptime(ts_value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    elif isinstance(ts_value, time.struct_time):
        # struct_time is in UTC for MediaWiki API; use calendar.timegm
        dt = datetime.fromtimestamp(calendar.timegm(ts_value), tz=timezone.utc)
    elif isinstance(ts_value, datetime):
        dt = ts_value if ts_value.tzinfo else ts_value.replace(tzinfo=timezone.utc)
    else:
        raise TypeError(f"Unsupported timestamp type: {type(ts_value)!r}")
    return to_mediawiki_sig_timestamp(dt)


def format_entry(ev: dict, topic_code: str) -> str:
    """
    Render one entry line with nowiki on fields that could contain pipes or template braces.
    """
    logid = ev.get("logid")
    user = ev.get("user") or ""
    title = ev.get("title") or ""
    ts_value = ev.get("timestamp")  # may be struct_time or str
    comment = ev.get("comment") or ""

    date_str = to_mediawiki_timestamp(ts_value)
    action_str = build_action_string(ev)

    # formerly wrap potentially hazardous parameters in <nowiki>...</nowiki>; now omitting
    action_param = action_str
    summary_param = comment

    # topic may be empty string
    topic_part = topic_code

    return (
        "{{/entry"
        f"|logid={logid}"
        f"|admin={user}"
        f"|page={title}"
        f"|date={date_str}"
        f"|action={action_param}"
        f"|summary={summary_param}"
        f"|topic={topic_part}"
        "}}"
    )


def main() -> int:
    # Load topic detection data
    try:
        detector = load_topics(TOPICS_PATH)
    except Exception as e:
        log.error("Failed to load CTOP topics data from %s: %s", TOPICS_PATH, e)
        return 2

    site = connect_site()
    # Removed: mwclient.Site has no public assertuser() method.

    page = fetch_target_page(site, TARGET_PAGE)
    if not page.exists:
        log.error("Target page '%s' does not exist. Create it first with the 'Last updated:' line.", TARGET_PAGE)
        return 2

    text = page.text()
    last_updated_dt = extract_last_updated(text)
    if not last_updated_dt:
        log.error("Could not find 'Last updated: ... (UTC)' line at top of %s", TARGET_PAGE)
        return 2

    existing_logids = extract_existing_logids(text)
    log.info("Parsed last updated: %s", last_updated_dt.isoformat())
    log.info("Found %d existing entries on page (by logid).", len(existing_logids))

    new_entries: List[str] = []
    appended_logids: List[int] = []

    for ev in enumerate_protect_logevents(site, last_updated_dt):
        logid = ev.get("logid")
        if logid is None:
            continue
        if int(logid) in existing_logids:
            # Already logged
            continue

        # Arbitration enforcement filter
        comment = ev.get("comment") or ""
        if not is_arbitration_enforcement(comment):
            continue

        topic_code = detector.detect(comment)
        entry_line = format_entry(ev, topic_code)
        new_entries.append(entry_line)
        appended_logids.append(int(logid))

    if not new_entries:
        log.info("No new AE protection actions to append.")
    else:
        append_text = "\n" + "\n".join(new_entries) + "\n"
        summary = f"Log {len(new_entries)} arbitration enforcement protection action(s)"
        if DRY_RUN:
            log.info("[DRY RUN] Would append:\n%s", append_text)
        else:
            # Append via MediaWiki API with appendtext to avoid fetching/saving whole page.
            log.info("Appending %d entries to %s", len(new_entries), TARGET_PAGE)
            token = site.get_token('csrf')
            res = site.api(
                'edit',
                title=TARGET_PAGE,
                appendtext=append_text,
                summary=summary,
                bot=True,
                token=token,
            )
            log.debug("Edit API response: %r", res)

    # Optional: update the 'Last updated' line to now (UTC), if explicitly requested.
    if UPDATE_TIMESTAMP:
        now_line = "Last updated: " + to_mediawiki_sig_timestamp(datetime.now(tz=timezone.utc))
        new_text, n = LAST_UPDATED_RE.subn(now_line, text, count=1)
        if n == 1:
            if DRY_RUN:
                log.info("[DRY RUN] Would update first line to: %s", now_line)
            else:
                # Prepend replacement and leave appended entries intact if we also appended above
                # We must refetch to avoid stomping the append; safer: prependtext is not suitable.
                # Do a full save merging the original text (with replaced timestamp) plus any new entries we appended above.
                # If we appended earlier, page.text() includes the old version; to avoid edit conflict, refetch current.
                current = page.text()
                current_updated, n2 = LAST_UPDATED_RE.subn(now_line, current, count=1)
                if n2 == 1:
                    page.save(current_updated, summary="Update last updated timestamp", bot=True)
        else:
            log.warning("Did not find 'Last updated' line to update.")

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
