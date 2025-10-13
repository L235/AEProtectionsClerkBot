#!/usr/bin/env python3
"""
ClerkBot - AE protection actions logger

This system monitors Wikipedia's protection log for arbitration enforcement (AE) actions
and automatically appends them to a designated tracking page. It serves as an automated
logging mechanism for Wikipedia administrators to maintain a centralized record of
protection actions taken under arbitration enforcement authority.

System Architecture:
- Monitors MediaWiki's protection log via the API using mwclient library
- Filters log entries to identify arbitration enforcement actions using keyword detection
- Categorizes actions by contentious topic (CTOP) codes using configurable heuristics
- Appends new entries to a target page while maintaining proper template structure
- Ensures {{/header}} appears before entries and {{/footer}} after all entries
- Updates the page's "Last updated" timestamp

Key Features:
- Duplicate detection using log IDs to prevent re-logging existing entries
- Topic code detection using multiple heuristics (bare codes, WP:CT/ shortcuts, specific pages)
- Atomic editing: performs all updates in a single edit to minimize page history
- Comprehensive error handling and logging
- Unicode normalization to prevent display issues

Operational Design:
- Configured entirely through environment variables for deployment flexibility
- Designed for automated execution via cron or similar scheduling systems
- Uses MediaWiki bot authentication for automated editing privileges
- Implements rate limiting and error recovery through mwclient's built-in mechanisms

Environment variables (all ASCII):

  CLERKBOT_USERNAME           Required. BotPassword username, e.g. "ClerkBot@AEProtections"
  CLERKBOT_PASSWORD           Required. BotPassword password
  CLERKBOT_TARGET_PAGE        Required. e.g. "User:ClerkBot/AE protection log"
  CLERKBOT_API_HOST           Optional. Host for wiki (default: "en.wikipedia.org")
  CLERKBOT_API_PATH           Optional. Path (default: "/w/")
  CLERKBOT_USER_AGENT         Optional. Shown in requests (default set below)
  CLERKBOT_CONFIG_URL         Optional. URL to fetch topics JSON (default: Wikipedia ClerkBot configuration URL)
  CLERKBOT_NOTIFY_ADMINS      Optional. Controls the notify-admin module. One of:
                              "false", "debug", or "true". Defaults to "debug" if unset/invalid.

The target page must begin with a line like:
  Last updated: 19:32, 19 August 2025 (UTC)
"""

import json
import logging
import os
import re
import sys
import unicodedata
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
import time
import calendar
from typing import Dict, Iterable, List, Optional, Tuple, Set
from urllib.request import urlopen, Request

from typing import Match
import mwclient
from mwclient.page import Page as MWPage


# --------- Enums ---------
class NotifyMode(str, Enum):
    """Notification mode for the notify-admin module."""
    DISABLED = "false"
    DEBUG = "debug"
    ENABLED = "true"


# --------- Logging ---------
LOG_LEVEL = os.environ.get("CLERKBOT_LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger(__name__)

# --------- Configuration ---------

# Required authentication and target page
USERNAME = os.environ.get("CLERKBOT_USERNAME")
PASSWORD = os.environ.get("CLERKBOT_PASSWORD")
TARGET_PAGE = os.environ.get("CLERKBOT_TARGET_PAGE")

# Optional API and user agent configuration
API_HOST = os.environ.get("CLERKBOT_API_HOST", "en.wikipedia.org")
API_PATH = os.environ.get("CLERKBOT_API_PATH", "/w/")
USER_AGENT = os.environ.get(
    "CLERKBOT_USER_AGENT",
    "ClerkBot-AEProtections/1.0 (https://en.wikipedia.org/wiki/User:ClerkBot)",
)

# Topic detection configuration
CONFIG_URL = os.environ.get(
    "CLERKBOT_CONFIG_URL",
    "https://en.wikipedia.org/w/index.php?title=User:ClerkBot/T3/config.json&action=raw&ctype=application/json"
)

# Notify-admin module configuration
# Validate the environment variable and default to DEBUG mode for safety
# This prevents accidental production notifications during development/testing
notify_raw = (os.environ.get("CLERKBOT_NOTIFY_ADMINS") or "").strip().lower()
if notify_raw not in (NotifyMode.DISABLED.value, NotifyMode.DEBUG.value, NotifyMode.ENABLED.value):
    notify_raw = NotifyMode.DEBUG.value
NOTIFY_MODE = NotifyMode(notify_raw)

DRYRUN_PAGE = os.environ.get("CLERKBOT_NOTIFICATIONS_DRYRUN_PAGE", f"{TARGET_PAGE}/notifications_dryrun")

# Validate required configuration
if not USERNAME or not PASSWORD or not TARGET_PAGE:
    log.error("Missing required environment variables. "
              "Set CLERKBOT_USERNAME, CLERKBOT_PASSWORD, CLERKBOT_TARGET_PAGE.")
    sys.exit(2)

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
ENTRY_LOGID_RE = re.compile(
    r"\{\{\s*User:ClerkBot/AE[ _]entry\s*\|[^}]*\blogid\s*=\s*(\d+)\b[^}]*\}\}",
    re.DOTALL | re.IGNORECASE,
)
# Lightweight presence checks for header/footer markers
HEADER_MARK = "{{/header}}"
FOOTER_MARK = "{{/footer}}"


# --------- Utilities ---------

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
    match = LAST_UPDATED_RE.search(text)
    if not match:
        return None
    return parse_mediawiki_sig_timestamp(match.group("ts"))


def extract_existing_logids(text: str) -> set:
    return set(int(x) for x in ENTRY_LOGID_RE.findall(text))


def is_arbitration_enforcement(comment: str) -> bool:
    comment_lower = (comment or "").lower()
    return any(trigger in comment_lower for trigger in AE_TRIGGERS)


def mediawiki_param_nowiki(value: str) -> str:
    """
    Wrap a parameter value in <nowiki> to avoid template-breaking characters (|, }}, [[]], etc.).
    """
    value = value or ""
    return "<nowiki>" + value + "</nowiki>"


def iso8601_from_dt(datetime_obj: datetime) -> str:
    """Return ISO8601 with 'Z'."""
    return datetime_obj.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


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


# --------- Topic detection ---------

class TopicDetector:
    """
    Detects CTOP topic codes from edit summaries using the required heuristics, in order:

    (1) If a topic code appears in the comment, not surrounded by letters (case-insensitive), return that code.
    (2) If a WP:CT/$CODE shortcut appears, return $CODE.
    (3) If a CTOP specific page appears, return the corresponding code.
    (4) If an override string appears, return the corresponding code.

    Args:
        codes: List of valid topic codes (e.g., ["ap", "blp", "cc"]). These are searched
               as bare tokens in edit summaries.
        page_to_code: Dictionary mapping full page names to topic codes (e.g.,
                      "Wikipedia:Contentious topics/American politics" -> "ap").
                      Used to detect topic codes from page references in edit summaries.
        override_strings: Dictionary mapping special/legacy strings to topic codes (e.g.,
                          "arbind" -> "sa"). Handles non-standard references that don't
                          match standard patterns.
    """

    def __init__(self, codes: List[str], page_to_code: Dict[str, str], override_strings: Dict[str, str]):
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
        # Input mapping is now page -> code; store normalized page text -> code
        self.page_to_code = { _norm(page): (code or "").lower() for page, code in page_to_code.items() }
        # Precompile regexes for code token matches
        self._code_res = {
            code: re.compile(r"(?i)(?<![A-Za-z])" + re.escape(code) + r"(?![A-Za-z])")
            for code in self.codes
        }
        # Regex to catch WP:CT/<code> with optional spaces around the colon and slash
        self._ctop_shortcut_re = re.compile(r"(?i)wp\s*:\s*ct\s*/\s*([A-Za-z-]+)")
        self.override_strings = override_strings

    def detect(self, comment: str) -> str:
        comment = (comment or "")
        lower = self._norm(comment)

        # Heuristic (1): bare code token (e.g., "CTOP:AP" or "restricted to AP")
        # Matches topic codes when they appear as standalone words, not embedded in longer words
        for code in self.codes:
            if self._code_res[code].search(lower):
                return code

        # Heuristic (2): WP:CT/<code> shortcuts (e.g., "WP:CT/AP" or "WP: CT / AP")
        # These are Wikipedia shortcuts commonly used in edit summaries
        match = self._ctop_shortcut_re.search(lower)
        if match:
            code = match.group(1).lower()
            if code in self.codes:
                return code

        # Heuristic (3): specific page string appears anywhere in comment
        # Detects full page names like "Wikipedia:Contentious topics/American politics"
        # These may appear as links or plain text in edit summaries
        for page_norm, code in self.page_to_code.items():
            if page_norm in lower:
                return code

        # Heuristic (4): override strings for special cases and legacy abbreviations
        # Handles historical or non-standard references (e.g., "arbind" -> "sa")
        for override, code in self.override_strings.items():
            if override in lower:
                return code

        # No topic detected - return empty string
        return ""


def load_topics(url: str) -> TopicDetector:
    """
    Load topic detection configuration from a URL.
    Args:
        url: URL to fetch the JSON configuration from
    Returns:
        TopicDetector instance configured with the fetched data
    """
    log.info("Fetching topics configuration from %s", url)
    request = Request(url, headers={'User-Agent': USER_AGENT})
    with urlopen(request) as response:
        data = json.loads(response.read().decode("utf-8"))
    codes = data.get("codes", [])
    # JSON now provides mapping: page -> code
    page_to_code = data.get("specific_pages", {})
    override_strings = data.get("override_strings", {})
    if not codes or not page_to_code:
        raise ValueError("Configuration JSON missing required keys 'codes' or 'specific_pages'")
    return TopicDetector(codes=codes, page_to_code=page_to_code, override_strings=override_strings)
  

# --------- Core logic ---------

def connect_site() -> mwclient.Site:
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
    Iterate logevents (type=protect) newer than start_utc. Skip 'unprotect' and 'move_prot' actions.
    mwclient handles API continuation internally.
    """
    start_iso = iso8601_from_dt(start_utc)
    log.info("Fetching logevents from %s (dir=newer)", start_iso)

    # props include user, timestamp, comment, details/params
    # mwclient uses 'dir' (older/newer), 'type', 'start'
    for log_event in site.logevents(type="protect", start=start_iso, dir="newer"):
        action = log_event.get("action")
        if action in ("unprotect", "move_prot"):
            continue  # skip protection removals and move protection actions
        yield log_event


def build_action_string(log_event: dict) -> str:
    """
    Build a human-readable action string from a protection log event.

    ACTION is constructed as:
      - if action == 'protect': "added protection (<description>)"
      - if action == 'modify':  "changed protection level (<description>)"
      - otherwise: use the raw action string.

    Args:
        log_event: A protection log event dict from the MediaWiki API

    Returns:
        A formatted action string describing what protection was applied
    """
    action = log_event.get("action", "")
    desc = ""
    params = log_event.get("params") or {}
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


def format_entry(log_event: dict, topic_code: str) -> str:
    """
    Render a protection log event as a template invocation string.

    Generates wikitext in the format:
    {{User:ClerkBot/AE entry|logid=...|admin=...|page=...|date=...|action=...|summary=...|topic=...}}

    Args:
        log_event: A protection log event dict from the MediaWiki API
        topic_code: The detected CTOP topic code, or empty string if none detected

    Returns:
        A formatted template invocation string ready to append to the target page
    """
    logid = log_event.get("logid")
    user = log_event.get("user") or ""
    title = log_event.get("title") or ""
    timestamp_value = log_event.get("timestamp")
    comment = log_event.get("comment") or ""

    date_str = to_mediawiki_timestamp(timestamp_value)
    action_str = build_action_string(log_event)

    # Parameters are used directly in template format without nowiki wrapping
    action_param = action_str
    summary_param = comment

    # topic may be empty string
    topic_part = topic_code

    return (
        "{{User:ClerkBot/AE entry"
        f"|logid={logid}"
        f"|admin={user}"
        f"|page={title}"
        f"|date={date_str}"
        f"|action={action_param}"
        f"|summary={summary_param}"
        f"|topic={topic_part}"
        "}}"
    )


# --------- Notify admin module ---------
def _build_notification_text(admin: str, items: List[Tuple[int, str, str]]) -> str:
    """
    Build a wikitext notification message for an admin about unclassified protection actions.

    Generates a message using the User:ClerkBot/AE notification template with a bulleted
    list of protection actions that could not be automatically categorized by topic.

    Args:
        admin: The username of the admin to notify
        items: List of (logid, utc_date_sig, protection_page_title) tuples for each
               unclassified action performed by this admin

    Returns:
        A formatted wikitext notification ready to post to the admin's talk page
    """
    bullets = "\n".join(
        f"* [[Special:Redirect/logid/{logid}|{date_sig}]] ([[{title}]])"
        for (logid, date_sig, title) in items
    )

    message = ("{{subst:User:ClerkBot/AE notification template"
        f"|admin={admin}|actions={bullets}|target_page={TARGET_PAGE}"
        "}}"
    )
    return message


def fetch_bot_usernames(site: mwclient.Site) -> Set[str]:
    """
    Retrieve the set of usernames that have the 'bot' user right.
    Uses the MediaWiki API list=allusers with augroup=bot and handles continuation.
    """
    bot_usernames: Set[str] = set()
    cont: Dict[str, str] = {"continue": ""}
    while True:
        try:
            resp = site.api(
                "query",
                list="allusers",
                augroup="bot",
                aulimit="max",
                **cont,
            )
        except mwclient.errors.APIError as api_error:
            log.error("Failed to fetch bot usernames: %s", api_error)
            break

        users = ((resp or {}).get("query") or {}).get("allusers") or []
        for user in users:
            name = user.get("name")
            if name:
                bot_usernames.add(name)

        new_cont = (resp or {}).get("continue")
        if not new_cont:
            break
        cont = new_cont

    log.info("Loaded %d bot usernames for notification filtering.", len(bot_usernames))
    return bot_usernames

def _notify_admins(
    site: mwclient.Site,
    unclassified_by_admin: Dict[str, List[Tuple[int, str, str]]],
    token: str,
    bot_usernames: Set[str],
) -> None:
    """
    Notify admins about protection actions that could not be automatically categorized.

    For each admin who performed unclassified protection actions, posts a notification
    to their talk page (or to a debug page) asking them to review the categorization.
    Bot accounts are automatically excluded from notifications.

    Behavior depends on NOTIFY_MODE:
      - DISABLED: No notifications sent, returns immediately
      - DEBUG: All notifications appended to DRYRUN_PAGE for testing
      - ENABLED: Notifications posted to individual admin talk pages

    Args:
        site: The mwclient Site connection
        unclassified_by_admin: Map of admin username -> list of (logid, date_sig, title)
                               for actions that were newly logged but lack a topic code
        token: CSRF token for API edits
        bot_usernames: Set of usernames with bot rights (excluded from notifications)

    Returns:
        None
    """
    if NOTIFY_MODE == NotifyMode.DISABLED:
        log.info("Notify-admin module disabled (CLERKBOT_NOTIFY_ADMINS=false).")
        return
    if not unclassified_by_admin:
        log.info("Notify-admin module: no unclassified actions to notify.")
        return

    for admin, items in unclassified_by_admin.items():
        if not items:
            continue
        if admin in bot_usernames:
            log.debug("Notify-admin: skipping bot account %s", admin)
            continue
        text = _build_notification_text(admin, items)
        if NOTIFY_MODE == NotifyMode.DEBUG:
            dest_title = DRYRUN_PAGE
            summary = f"DEBUG: AE protection categorization notice for {admin}"
        else:
            dest_title = f"User talk:{admin}"
            summary = "adding AE protection categorization notice ([[User:ClerkBot#t3|task 3]], [[Wikipedia:Bots/Requests for approval/ClerkBot|BRFA in trial]])"
        try:
            log.info("Posting notification (%d item(s)) to %s", len(items), dest_title)
            site.api(
                "edit",
                title=dest_title,
                appendtext="\n" + text + "\n",
                summary=summary + " (bot)",
                bot=True,
                token=token,
            )
        except mwclient.errors.APIError as api_error:
            log.error("Failed to notify %s at %s: %s", admin, dest_title, api_error)


def _process_new_log_entries(
    site: mwclient.Site,
    detector: TopicDetector,
    last_updated_dt: datetime,
    existing_logids: set,
) -> Tuple[List[str], Dict[str, List[Tuple[int, str, str]]]]:
    """
    Process new protection log events and generate entry strings.

    Args:
        site: The mwclient Site connection
        detector: TopicDetector instance for categorizing actions
        last_updated_dt: Only process events after this timestamp
        existing_logids: Set of log IDs already present on the page

    Returns:
        Tuple of (new_entries, unclassified_by_admin) where:
          - new_entries: List of formatted template strings to append
          - unclassified_by_admin: Map of admin -> list of unclassified actions
    """
    new_entries: List[str] = []
    unclassified_by_admin: Dict[str, List[Tuple[int, str, str]]] = {}

    for log_event in enumerate_protect_logevents(site, last_updated_dt):
        logid = log_event.get("logid")
        if logid is None:
            continue
        if int(logid) in existing_logids:
            # Already logged
            continue

        # Arbitration enforcement filter
        comment = log_event.get("comment") or ""
        if not is_arbitration_enforcement(comment):
            continue

        topic_code = detector.detect(comment)
        entry_line = format_entry(log_event, topic_code)
        new_entries.append(entry_line)

        # Track unclassified actions (no topic determined) for admin notifications
        if not topic_code or not topic_code.strip():
            admin = (log_event.get("user") or "").strip()
            if admin:
                timestamp_value = log_event.get("timestamp")
                date_sig = to_mediawiki_timestamp(timestamp_value)
                title = log_event.get("title") or ""
                unclassified_by_admin.setdefault(admin, []).append((int(logid), date_sig, title))

    return new_entries, unclassified_by_admin


def _build_updated_page_text(text: str, new_entries: List[str]) -> str:
    """
    Build updated page content with new entries and updated timestamp.

    Args:
        text: Current page text
        new_entries: List of new entry template strings to append

    Returns:
        Updated page text with new entries, updated timestamp, and footer repositioned
    """
    # Build the new page content in-memory so we can do one edit that:
    # - appends new entries
    # - updates the timestamp
    # This atomic approach minimizes page history entries and prevents race conditions
    new_text = text

    # Update the "Last updated" timestamp to current time
    now_line = "Last updated: " + to_mediawiki_sig_timestamp(datetime.now(tz=timezone.utc))
    new_text, num_replacements = LAST_UPDATED_RE.subn(now_line, new_text, count=1)
    if num_replacements != 1:
        log.warning("Did not find 'Last updated' line to update.")

    # Temporarily remove the footer marker so we can append new entries at the true end
    # The footer must appear after ALL entries to maintain proper page structure
    new_text = new_text.replace(FOOTER_MARK, "")

    # Append new entries (if any) after the last existing entry
    if new_entries:
        append_block = "\n".join(new_entries) + "\n"
        new_text = new_text + append_block
    else:
        log.info("No new AE protection actions to append.")

    # Re-add the footer marker at the very end, after all entries
    # This ensures the page structure remains: header -> entries -> footer
    new_text = new_text + FOOTER_MARK + "\n"

    # Clean invisible unicode characters that could cause display issues
    new_text = clean_invisible_unicode(new_text)

    return new_text


def _save_page_update(site: mwclient.Site, new_text: str, new_entries: List[str]) -> None:
    """
    Save the updated page text to Wikipedia.

    Args:
        site: The mwclient Site connection
        new_text: The complete new page text to save
        new_entries: List of new entries (used for edit summary)

    Returns:
        None
    """
    edit_summary = (
        f"updating AE protection log"
        f"{f' ({len(new_entries)} new entries)' if new_entries else ''}"
        " ([[User:ClerkBot#t3|task 3]], [[Wikipedia:Bots/Requests for approval/ClerkBot|BRFA in trial]])"
    )

    token = site.get_token('csrf')
    log.info("Saving single edit to %s (%s)", TARGET_PAGE, edit_summary)
    res = site.api(
        'edit',
        title=TARGET_PAGE,
        text=new_text,
        summary=edit_summary,
        bot=True,
        token=token,
    )
    log.debug("Edit API response: %r", res)


def main() -> int:
    """
    Main entry point for the ClerkBot AE protection log updater.

    Returns:
        0 on success, 2 on configuration/setup error, 1 on API error
    """
    # Load topic detection data
    try:
        detector = load_topics(CONFIG_URL)
    except Exception as error:
        log.error("Failed to load CTOP topics configuration from '%s': %s", CONFIG_URL, error)
        return 2

    # Connect to Wikipedia and load the target page
    site = connect_site()
    bot_usernames = fetch_bot_usernames(site)
    page = fetch_target_page(site, TARGET_PAGE)
    if not page.exists:
        log.error("Target page '%s' does not exist. Create it first with the 'Last updated:' line.", TARGET_PAGE)
        return 2

    # Parse existing page content
    text = page.text()
    last_updated_dt = extract_last_updated(text)
    if not last_updated_dt:
        log.error("Could not find 'Last updated: ... (UTC)' line at top of '%s'", TARGET_PAGE)
        return 2

    existing_logids = extract_existing_logids(text)
    log.info("Parsed last updated: %s", last_updated_dt.isoformat())
    log.info("Found %d existing entries on page (by logid).", len(existing_logids))

    # Process new log entries
    new_entries, unclassified_by_admin = _process_new_log_entries(
        site, detector, last_updated_dt, existing_logids
    )

    # Build updated page text
    new_text = _build_updated_page_text(text, new_entries)

    # If nothing changed at all, bail out
    if new_text == text:
        log.info("Nothing to do: no new entries and no timestamp update.")
        return 0

    # Save the updated page
    _save_page_update(site, new_text, new_entries)

    # Run notify-admin module after attempting the main page save
    # Only notify for actions that were newly appended in this run
    if new_entries and unclassified_by_admin:
        token = site.get_token('csrf')
        _notify_admins(site, unclassified_by_admin, token, bot_usernames)
    else:
        log.info("Notify-admin module: nothing to notify.")

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except mwclient.errors.APIError as api_error:
        log.error("MediaWiki API error: %s", api_error)
        sys.exit(1)
    except Exception as error:
        log.exception("Unhandled exception: %s", error)
        sys.exit(1)
