"""
Topic detection for CTOP (Contentious Topic) codes.

Provides TopicDetector class that detects topic codes from edit summaries
using multiple heuristics in priority order.
"""

import json
import logging
import re
from typing import Dict, List
from urllib.request import Request, urlopen


log = logging.getLogger(__name__)


class TopicDetector:
    """
    Detects CTOP topic codes from edit summaries using the required heuristics, in order:

    (1) If a WP:CT/$CODE shortcut appears, return $CODE.
    (2) If a CTOP specific page appears, return the corresponding code.
    (3) If an override string appears, return the corresponding code.
    (4) If a bare topic code appears in the comment, not surrounded by letters (case-insensitive), return that code.

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
        # Regex to catch WP:CT/<code>, WP:CTOP/<code>, Wikipedia:CT/<code>, Wikipedia:CTOP/<code>
        self._ctop_shortcut_re = re.compile(r"(?i)(?:wp|wikipedia):ct(?:op)?/([A-Za-z-]+)")
        self.override_strings = override_strings

    def detect(self, comment: str) -> str:
        comment = (comment or "")
        lower = self._norm(comment)

        # Heuristic (1): WP:CT/<code> (or WP:CTOP/<code>) shortcuts (e.g., "WP:CT/AP", "WP:CTOP/AP", "Wikipedia:CTOP/AP")
        # These are Wikipedia shortcuts commonly used in edit summaries
        match = self._ctop_shortcut_re.search(lower)
        if match:
            code = match.group(1).lower()
            if code in self.codes:
                return code

        # Heuristic (2): specific page string appears anywhere in comment
        # Detects full page names like "Wikipedia:Contentious topics/American politics"
        # These may appear as links or plain text in edit summaries
        for page_norm, code in self.page_to_code.items():
            if page_norm in lower:
                return code

        # Heuristic (3): override strings for special cases and legacy abbreviations
        # Handles historical or non-standard references (e.g., "arbind" -> "sa")
        for override, code in self.override_strings.items():
            if override in lower:
                return code

        # Heuristic (4): bare code token (e.g., "AE action: BLP")
        # Matches topic codes when they appear as standalone words, not embedded in longer words
        for code in self.codes:
            if self._code_res[code].search(lower):
                if code not in ("at", ): # temporary fix for "at"
                    return code

        # No topic detected - return empty string
        return ""


def load_topics(url: str, user_agent: str) -> TopicDetector:
    """
    Load topic detection configuration from a URL.

    Args:
        url: URL to fetch the JSON configuration from
        user_agent: User-Agent header for the request

    Returns:
        TopicDetector instance configured with the fetched data

    Raises:
        ValueError: If the configuration JSON is missing required keys
    """
    log.info("Fetching topics configuration from %s", url)
    request = Request(url, headers={'User-Agent': user_agent})
    with urlopen(request) as response:
        data = json.loads(response.read().decode("utf-8"))
    codes = data.get("codes", [])
    # JSON now provides mapping: page -> code
    page_to_code = data.get("specific_pages", {})
    override_strings = data.get("override_strings", {})
    if not codes or not page_to_code:
        raise ValueError("Configuration JSON missing required keys 'codes' or 'specific_pages'")
    return TopicDetector(codes=codes, page_to_code=page_to_code, override_strings=override_strings)


__all__ = [
    'TopicDetector',
    'load_topics',
]
