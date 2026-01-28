"""
ClerkBot - AE protection actions logger package.

This package provides modules for monitoring Wikipedia's protection log for
arbitration enforcement (AE) actions and automatically appending them to a
designated tracking page.
"""

from clerkbot.config import BotConfig, NotifyMode
from clerkbot.constants import AE_ENTRY_TEMPLATE, ENTRY_LOGID_RE, FOOTER_MARK, HEADER_MARK
from clerkbot.entries import build_action_string, format_entry
from clerkbot.filters import AE_TRIGGERS, is_arbitration_enforcement
from clerkbot.timestamp import (
    LAST_UPDATED_RE,
    clean_invisible_unicode,
    extract_last_updated,
    format_expiry,
    iso8601_from_dt,
    parse_mediawiki_sig_timestamp,
    to_mediawiki_sig_timestamp,
    to_mediawiki_timestamp,
)
from clerkbot.topics import TopicDetector, load_topics

__all__ = [
    # config
    'BotConfig',
    'NotifyMode',
    # constants
    'AE_ENTRY_TEMPLATE',
    'ENTRY_LOGID_RE',
    'FOOTER_MARK',
    'HEADER_MARK',
    # entries
    'build_action_string',
    'format_entry',
    # filters
    'AE_TRIGGERS',
    'is_arbitration_enforcement',
    # timestamp
    'LAST_UPDATED_RE',
    'clean_invisible_unicode',
    'extract_last_updated',
    'format_expiry',
    'iso8601_from_dt',
    'parse_mediawiki_sig_timestamp',
    'to_mediawiki_sig_timestamp',
    'to_mediawiki_timestamp',
    # topics
    'TopicDetector',
    'load_topics',
]
