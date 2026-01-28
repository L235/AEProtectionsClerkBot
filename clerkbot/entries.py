"""
Entry formatting for AE protection log entries.

Provides functions to format protection log events as wikitext template invocations.
"""

from clerkbot.constants import AE_ENTRY_TEMPLATE
from clerkbot.timestamp import format_expiry, to_mediawiki_timestamp


def build_action_string(log_event: dict) -> str:
    """
    Build a human-readable action string from a protection log event.

    ACTION is constructed as:
      - if type == 'stable' and action == 'config': "added pending changes protection (<details>)"
      - if type == 'stable' and action == 'modify': "changed pending changes level (<details>)"
      - if action == 'protect': "added protection (<description>)"
      - if action == 'modify':  "changed protection level (<description>)"
      - otherwise: use the raw action string.

    Args:
        log_event: A protection log event dict from the MediaWiki API

    Returns:
        A formatted action string describing what protection was applied
    """
    action = log_event.get("action", "")
    log_type = log_event.get("type", "")
    params = log_event.get("params") or {}

    # Handle pending changes (stable) log events
    if log_type == "stable" and action in ("config", "modify"):
        autoreview = params.get("autoreview") or ""
        expiry = params.get("expiry") or ""
        base = "added pending changes protection" if action == "config" else "changed pending changes level"

        details = []
        if autoreview:
            details.append(f"autoreview={autoreview}")
        if expiry:
            details.append(f"expires {format_expiry(expiry)}")

        if details:
            return f"{base} ({', '.join(details)})"
        return base

    # Handle regular protection log events
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
        "{{" + AE_ENTRY_TEMPLATE
        + f"|logid={logid}"
        f"|admin={user}"
        f"|page={title}"
        f"|date={date_str}"
        f"|action={action_param}"
        f"|summary={summary_param}"
        f"|topic={topic_part}"
        "}}"
    )


__all__ = [
    'build_action_string',
    'format_entry',
]
