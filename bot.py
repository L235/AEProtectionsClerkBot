#!/usr/bin/env python3
"""
ClerkBot - AE protection actions logger

This system monitors Wikipedia's protection log for arbitration enforcement (AE) actions
and automatically appends them to a designated tracking page. It serves as an automated
logging mechanism for Wikipedia administrators to maintain a centralized record of
protection actions taken under arbitration enforcement authority.

System Architecture:
- Monitors MediaWiki's protection log (type=protect) and pending changes log (type=stable) via the API
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

# Standard library imports
import calendar
import logging
import sys
import time
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Set, Tuple

# Third-party imports
import mwclient
from mwclient.page import Page as MWPage

# Local imports
from config import BotConfig, NotifyMode
from constants import ENTRY_LOGID_RE, FOOTER_MARK
from entries import build_action_string, format_entry
from filters import is_arbitration_enforcement
from timestamp import (
    LAST_UPDATED_RE,
    clean_invisible_unicode,
    extract_last_updated,
    iso8601_from_dt,
    to_mediawiki_sig_timestamp,
    to_mediawiki_timestamp,
)
from topics import TopicDetector, load_topics

# Load environment variables from .env file for local development
# This is optional and only needed for local development with .env files
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    # python-dotenv not installed, skip loading .env file
    pass

# Load configuration from environment
config = BotConfig.from_environment()

# --------- Logging ---------
logging.basicConfig(
    level=config.log_level,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger(__name__)

# --------- Utilities ---------

def extract_existing_logids(text: str) -> set:
    return set(int(x) for x in ENTRY_LOGID_RE.findall(text))


# --------- Core logic ---------

def connect_site(config: BotConfig) -> mwclient.Site:
    """
    Connect to MediaWiki site and authenticate.

    Args:
        config: Bot configuration

    Returns:
        Authenticated mwclient Site instance
    """
    site = mwclient.Site(
        config.api_host,
        scheme="https",
        path=config.api_path,
        clients_useragent=config.user_agent,
    )
    site.login(config.username, config.password)
    return site


def fetch_target_page(site: mwclient.Site, title: str) -> Tuple[MWPage, int]:
    """
    Fetch target page and its current revision ID.

    Args:
        site: The mwclient Site connection
        title: Page title to fetch

    Returns:
        Tuple of (page, base_revid) where base_revid is the current revision ID
    """
    page = site.pages[title]
    # Get the current revision ID to use as baserevid in edit
    revisions = list(page.revisions(limit=1))
    base_revid = revisions[0]['revid'] if revisions else 0
    return page, base_revid


def enumerate_protect_logevents(
    site: mwclient.Site,
    start_utc: datetime,
) -> Iterable[dict]:
    """
    Iterate logevents (type=protect) newer than start_utc. Skip 'unprotect' and 'move_prot' actions.
    mwclient handles API continuation internally.

    See also: enumerate_stable_logevents() for pending changes protections.
    """
    start_iso = iso8601_from_dt(start_utc)
    log.info("Fetching protect logevents from %s (dir=newer)", start_iso)

    # props include user, timestamp, comment, details/params
    # mwclient uses 'dir' (older/newer), 'type', 'start'
    for log_event in site.logevents(type="protect", start=start_iso, dir="newer"):
        action = log_event.get("action")
        if action in ("unprotect", "move_prot"):
            continue  # skip protection removals and move protection actions
        yield log_event


def enumerate_stable_logevents(
    site: mwclient.Site,
    start_utc: datetime,
) -> Iterable[dict]:
    """
    Iterate logevents (type=stable) newer than start_utc for pending changes protections.
    Skip 'reset' (removal) and 'move_stable' (page move) actions.
    mwclient handles API continuation internally.

    See also: enumerate_protect_logevents() for regular protections.
    """
    start_iso = iso8601_from_dt(start_utc)
    log.info("Fetching stable (pending changes) logevents from %s (dir=newer)", start_iso)

    for log_event in site.logevents(type="stable", start=start_iso, dir="newer"):
        action = log_event.get("action")
        if action in ("reset", "move_stable"):
            continue  # skip removals and page move actions
        yield log_event


# --------- Notify admin module ---------
def _build_notification_text(admin: str, items: List[Tuple[int, str, str]], target_page: str) -> str:
    """
    Build a wikitext notification message for an admin about unclassified protection actions.

    Generates a message using the User:ClerkBot/AE notification template with a bulleted
    list of protection actions that could not be automatically categorized by topic.

    Args:
        admin: The username of the admin to notify
        items: List of (logid, utc_date_sig, protection_page_title) tuples for each
               unclassified action performed by this admin
        target_page: The target page URL to include in notification

    Returns:
        A formatted wikitext notification ready to post to the admin's talk page
    """
    bullets = "\n".join(
        f"* [[Special:Redirect/logid/{logid}|{date_sig}]] ([[{title}]])"
        for (logid, date_sig, title) in items
    )

    message = ("{{subst:User:ClerkBot/AE notification template"
        f"|admin={admin}|actions={bullets}|target_page={target_page}"
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
    config: BotConfig,
) -> None:
    """
    Notify admins about protection actions that could not be automatically categorized.

    For each admin who performed unclassified protection actions, posts a notification
    to their talk page (or to a debug page) asking them to review the categorization.
    Bot accounts are automatically excluded from notifications.

    Behavior depends on config.notify_mode:
      - DISABLED: No notifications sent, returns immediately
      - DEBUG: All notifications appended to config.dryrun_page for testing
      - ENABLED: Notifications posted to individual admin talk pages

    Args:
        site: The mwclient Site connection
        unclassified_by_admin: Map of admin username -> list of (logid, date_sig, title)
                               for actions that were newly logged but lack a topic code
        token: CSRF token for API edits
        bot_usernames: Set of usernames with bot rights (excluded from notifications)
        config: Bot configuration

    Returns:
        None
    """
    if config.notify_mode == NotifyMode.DISABLED:
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
        text = _build_notification_text(admin, items, config.target_page)
        if config.notify_mode == NotifyMode.DEBUG:
            dest_title = config.dryrun_page
            summary = f"DEBUG: AE protection categorization notice for {admin}"
        else:
            dest_title = f"User talk:{admin}"
            summary = "adding AE protection categorization notice ([[User:ClerkBot#t3|bot task 3]])"
        try:
            log.info("Posting notification (%d item(s)) to %s", len(items), dest_title)
            site.api(
                "edit",
                title=dest_title,
                appendtext="\n" + text + "\n",
                summary=summary,
                bot=True,
                token=token,
            )
        except mwclient.errors.APIError as api_error:
            log.error("Failed to notify %s at %s: %s", admin, dest_title, api_error)


def _process_single_log_event(
    log_event: dict,
    detector: TopicDetector,
    existing_logids: set,
    new_entries: List[str],
    unclassified_by_admin: Dict[str, List[Tuple[int, str, str]]],
) -> None:
    """
    Process a single log event and append to new_entries if it's an AE action.

    Args:
        log_event: A log event dict from the MediaWiki API
        detector: TopicDetector instance for categorizing actions
        existing_logids: Set of log IDs already present on the page
        new_entries: List to append new entry strings to (modified in place)
        unclassified_by_admin: Map to track unclassified actions (modified in place)
    """
    logid = log_event.get("logid")
    if logid is None:
        return
    if int(logid) in existing_logids:
        # Already logged
        return

    # Arbitration enforcement filter
    comment = log_event.get("comment") or ""
    if not is_arbitration_enforcement(comment):
        return

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


def _get_event_sort_key(log_event: dict) -> float:
    """
    Extract a sortable timestamp from a log event.
    Returns seconds since epoch for consistent sorting across event types.
    """
    timestamp_value = log_event.get("timestamp")
    if isinstance(timestamp_value, time.struct_time):
        return calendar.timegm(timestamp_value)
    elif isinstance(timestamp_value, str):
        dt = datetime.strptime(timestamp_value, "%Y-%m-%dT%H:%M:%SZ")
        return dt.replace(tzinfo=timezone.utc).timestamp()
    elif isinstance(timestamp_value, datetime):
        return timestamp_value.timestamp()
    return 0.0


def _process_new_log_entries(
    site: mwclient.Site,
    detector: TopicDetector,
    last_updated_dt: datetime,
    existing_logids: set,
) -> Tuple[List[str], Dict[str, List[Tuple[int, str, str]]]]:
    """
    Process new protection log events (both regular and pending changes) and generate entry strings.
    Events are merged and sorted chronologically before processing.

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

    # Collect all events from both log types
    all_events: List[dict] = []
    all_events.extend(enumerate_protect_logevents(site, last_updated_dt))
    all_events.extend(enumerate_stable_logevents(site, last_updated_dt))

    # Sort by timestamp to maintain chronological order
    all_events.sort(key=_get_event_sort_key)

    # Process events in chronological order
    for log_event in all_events:
        _process_single_log_event(
            log_event, detector, existing_logids, new_entries, unclassified_by_admin
        )

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


def _save_page_update(site: mwclient.Site, target_page: str, new_text: str, new_entries: List[str], base_revid: int) -> None:
    """
    Save the updated page text to Wikipedia with edit conflict detection.

    Args:
        site: The mwclient Site connection
        target_page: Title of the page to save
        new_text: The complete new page text to save
        new_entries: List of new entries (used for edit summary)
        base_revid: The revision ID that the edit is based on (for conflict detection)

    Returns:
        None

    Raises:
        mwclient.errors.EditError: If an edit conflict occurs or other API error
    """
    edit_summary = (
        f"updating AE protection log"
        f"{f' ({len(new_entries)} new entries)' if new_entries else ''}"
        " ([[User:ClerkBot#t3|bot task 3]])"
    )

    token = site.get_token('csrf')
    log.info("Saving single edit to %s (%s) [baserevid=%d]", target_page, edit_summary, base_revid)

    try:
        res = site.api(
            'edit',
            title=target_page,
            text=new_text,
            summary=edit_summary,
            bot=True,
            token=token,
            baserevid=base_revid,
        )
        log.debug("Edit API response: %r", res)
    except mwclient.errors.EditError as edit_error:
        log.error("Edit conflict or error: %s", edit_error)
        raise


def main() -> int:
    """
    Main entry point for the ClerkBot AE protection log updater.

    Returns:
        0 on success, 2 on configuration/setup error, 1 on API error
    """
    # Load topic detection data
    try:
        detector = load_topics(config.config_url, config.user_agent)
    except Exception as error:
        log.error("Failed to load CTOP topics configuration from '%s': %s", config.config_url, error)
        return 2

    # Connect to Wikipedia and load the target page
    site = connect_site(config)
    bot_usernames = fetch_bot_usernames(site)
    page, base_revid = fetch_target_page(site, config.target_page)
    if not page.exists:
        log.error("Target page '%s' does not exist. Create it first with the 'Last updated:' line.", config.target_page)
        return 2

    # Parse existing page content
    text = page.text()
    last_updated_dt = extract_last_updated(text)
    if not last_updated_dt:
        log.error("Could not find 'Last updated: ... (UTC)' line at top of '%s'", config.target_page)
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
    try:
        _save_page_update(site, config.target_page, new_text, new_entries, base_revid)
    except mwclient.errors.EditError as e:
        log.error("Failed to save page due to edit conflict or error: %s", e)
        log.error("Another user may have edited the page. Please re-run the bot.")
        return 1

    # Run notify-admin module after attempting the main page save
    # Only notify for actions that were newly appended in this run
    if new_entries and unclassified_by_admin:
        token = site.get_token('csrf')
        _notify_admins(site, unclassified_by_admin, token, bot_usernames, config)
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
