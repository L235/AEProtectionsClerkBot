"""
Constants used throughout the ClerkBot codebase.

Centralizes magic strings and compiled regex patterns to ensure consistency
and make future updates easier.
"""

import re

# Template name for AE protection log entries
AE_ENTRY_TEMPLATE = "User:ClerkBot/AE entry"

# Template entry pattern to find existing logids and avoid duplicates on append
ENTRY_LOGID_RE = re.compile(
    r"\{\{\s*User:ClerkBot/AE[ _]entry\s*\|[^}]*\blogid\s*=\s*(\d+)\b[^}]*\}\}",
    re.DOTALL | re.IGNORECASE,
)

# Lightweight presence checks for header/footer markers
HEADER_MARK = "{{/header}}"
FOOTER_MARK = "{{/footer}}"


__all__ = [
    'AE_ENTRY_TEMPLATE',
    'ENTRY_LOGID_RE',
    'HEADER_MARK',
    'FOOTER_MARK',
]
