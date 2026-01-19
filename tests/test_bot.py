"""Tests for bot.py pure functions."""

import time
import calendar
from datetime import datetime, timezone

import pytest

# Import the functions we want to test
from bot import (
    build_action_string,
    extract_existing_logids,
    _get_event_sort_key,
    TopicDetector,
)
from filters import (
    is_arbitration_enforcement,
)
from timestamp import (
    parse_mediawiki_sig_timestamp,
    to_mediawiki_sig_timestamp,
    extract_last_updated,
    format_expiry,
)


class TestIsArbitrationEnforcement:
    """Tests for AE trigger detection."""

    def test_ctop_trigger(self):
        assert is_arbitration_enforcement("Protected per WP:CTOP/BLP")
        assert is_arbitration_enforcement("ctop blp")

    def test_ct_slash_trigger(self):
        assert is_arbitration_enforcement("WP:CT/AP")
        assert is_arbitration_enforcement("per ct/blp")

    def test_arbitration_trigger(self):
        assert is_arbitration_enforcement("Per arbitration enforcement")
        assert is_arbitration_enforcement("ARBITRATION decision")

    def test_ae_trigger_with_space(self):
        # "wp:ae " should match (with trailing space to avoid "WP:AELECT")
        assert is_arbitration_enforcement("per WP:AE action")
        assert is_arbitration_enforcement("Wikipedia:AE request")

    def test_ae_trigger_with_brackets(self):
        assert is_arbitration_enforcement("[[WP:AE]]")
        assert is_arbitration_enforcement("[[WP:AE|link]]")

    def test_blpct_trigger(self):
        assert is_arbitration_enforcement("BLPCT protection")

    def test_no_match(self):
        assert not is_arbitration_enforcement("Regular vandalism protection")
        assert not is_arbitration_enforcement("Requested at RFPP")
        assert not is_arbitration_enforcement("")
        assert not is_arbitration_enforcement(None)

    def test_aelect_should_not_match(self):
        # This is the "bodge" case - WP:AELECT should not trigger
        assert not is_arbitration_enforcement("See WP:AELECT for more")


class TestBuildActionString:
    """Tests for action string formatting."""

    def test_protect_action_with_description(self):
        event = {
            "type": "protect",
            "action": "protect",
            "params": {"description": "edit=autoconfirmed"}
        }
        assert build_action_string(event) == "added protection (edit=autoconfirmed)"

    def test_protect_action_without_description(self):
        event = {
            "type": "protect",
            "action": "protect",
            "params": {}
        }
        assert build_action_string(event) == "added protection"

    def test_modify_action(self):
        event = {
            "type": "protect",
            "action": "modify",
            "params": {"description": "edit=sysop"}
        }
        assert build_action_string(event) == "changed protection level (edit=sysop)"

    def test_stable_config_action(self):
        event = {
            "type": "stable",
            "action": "config",
            "params": {"autoreview": "autoconfirmed"}
        }
        assert build_action_string(event) == "added pending changes protection (autoreview=autoconfirmed)"

    def test_stable_config_action_with_expiry(self):
        event = {
            "type": "stable",
            "action": "config",
            "params": {"autoreview": "autoconfirmed", "expiry": "20260227170300"}
        }
        assert build_action_string(event) == "added pending changes protection (autoreview=autoconfirmed, expires 17:03, 27 February 2026)"

    def test_stable_config_action_with_indefinite_expiry(self):
        event = {
            "type": "stable",
            "action": "config",
            "params": {"autoreview": "autoconfirmed", "expiry": "infinity"}
        }
        assert build_action_string(event) == "added pending changes protection (autoreview=autoconfirmed, expires indefinite)"

    def test_stable_config_without_autoreview(self):
        event = {
            "type": "stable",
            "action": "config",
            "params": {}
        }
        assert build_action_string(event) == "added pending changes protection"

    def test_stable_modify_action(self):
        event = {
            "type": "stable",
            "action": "modify",
            "params": {"autoreview": "autoconfirmed"}
        }
        assert build_action_string(event) == "changed pending changes level (autoreview=autoconfirmed)"

    def test_unknown_action_returns_raw(self):
        event = {
            "type": "protect",
            "action": "something_else",
            "params": {}
        }
        assert build_action_string(event) == "something_else"


class TestTimestampParsing:
    """Tests for MediaWiki timestamp parsing and formatting."""

    def test_parse_timestamp(self):
        result = parse_mediawiki_sig_timestamp("19:32, 19 August 2025 (UTC)")
        assert result.year == 2025
        assert result.month == 8
        assert result.day == 19
        assert result.hour == 19
        assert result.minute == 32
        assert result.tzinfo == timezone.utc

    def test_format_timestamp(self):
        dt = datetime(2025, 8, 19, 19, 32, tzinfo=timezone.utc)
        result = to_mediawiki_sig_timestamp(dt)
        assert result == "19:32, 19 August 2025 (UTC)"

    def test_parse_format_roundtrip(self):
        original = "07:15, 3 January 2026 (UTC)"
        dt = parse_mediawiki_sig_timestamp(original)
        result = to_mediawiki_sig_timestamp(dt)
        assert result == original


class TestExtractLastUpdated:
    """Tests for extracting Last updated timestamp from page text."""

    def test_extract_from_page(self):
        text = """Last updated: 19:32, 19 August 2025 (UTC)
{{/header}}
Some content here
{{/footer}}"""
        result = extract_last_updated(text)
        assert result is not None
        assert result.year == 2025
        assert result.month == 8

    def test_no_timestamp_returns_none(self):
        text = "Some page without a timestamp"
        assert extract_last_updated(text) is None


class TestExtractExistingLogids:
    """Tests for extracting logids from existing entries."""

    def test_extract_single_logid(self):
        text = "{{User:ClerkBot/AE entry|logid=12345|admin=Someone}}"
        result = extract_existing_logids(text)
        assert result == {12345}

    def test_extract_multiple_logids(self):
        text = """{{User:ClerkBot/AE entry|logid=111|admin=A}}
{{User:ClerkBot/AE entry|logid=222|admin=B}}
{{User:ClerkBot/AE entry|logid=333|admin=C}}"""
        result = extract_existing_logids(text)
        assert result == {111, 222, 333}

    def test_empty_page(self):
        result = extract_existing_logids("")
        assert result == set()


class TestGetEventSortKey:
    """Tests for event timestamp sorting."""

    def test_struct_time(self):
        # mwclient returns struct_time
        ts = time.strptime("2025-08-19T19:32:00Z", "%Y-%m-%dT%H:%M:%SZ")
        event = {"timestamp": ts}
        result = _get_event_sort_key(event)
        assert result == calendar.timegm(ts)

    def test_iso_string(self):
        event = {"timestamp": "2025-08-19T19:32:00Z"}
        result = _get_event_sort_key(event)
        expected = datetime(2025, 8, 19, 19, 32, tzinfo=timezone.utc).timestamp()
        assert result == expected

    def test_datetime_object(self):
        dt = datetime(2025, 8, 19, 19, 32, tzinfo=timezone.utc)
        event = {"timestamp": dt}
        result = _get_event_sort_key(event)
        assert result == dt.timestamp()

    def test_missing_timestamp(self):
        event = {}
        result = _get_event_sort_key(event)
        assert result == 0.0

    def test_none_timestamp(self):
        event = {"timestamp": None}
        result = _get_event_sort_key(event)
        assert result == 0.0

    def test_sorting_order(self):
        """Verify events sort correctly by timestamp."""
        events = [
            {"timestamp": "2025-08-19T20:00:00Z", "id": "later"},
            {"timestamp": "2025-08-19T19:00:00Z", "id": "earlier"},
            {"timestamp": "2025-08-19T19:30:00Z", "id": "middle"},
        ]
        sorted_events = sorted(events, key=_get_event_sort_key)
        assert [e["id"] for e in sorted_events] == ["earlier", "middle", "later"]


class TestFormatExpiry:
    """Tests for format_expiry function."""

    def test_infinity_returns_indefinite(self):
        assert format_expiry("infinity") == "indefinite"

    def test_empty_string_returns_indefinite(self):
        assert format_expiry("") == "indefinite"

    def test_none_returns_indefinite(self):
        assert format_expiry(None) == "indefinite"

    def test_valid_expiry_format(self):
        # YYYYMMDDHHMMSS format
        assert format_expiry("20260227170300") == "17:03, 27 February 2026"

    def test_expiry_single_digit_day(self):
        assert format_expiry("20260103091500") == "09:15, 3 January 2026"

    def test_malformed_expiry_returns_raw(self):
        # Invalid format should return the raw value as fallback
        assert format_expiry("not-a-date") == "not-a-date"


class TestTopicDetector:
    """Tests for TopicDetector heuristics."""

    @pytest.fixture
    def detector(self):
        """Create a TopicDetector with sample configuration."""
        codes = ["ap", "blp", "cc", "ipa", "sa", "at"]
        page_to_code = {
            "Wikipedia:Contentious topics/American politics": "ap",
            "Wikipedia:Contentious topics/Biographies of living persons": "blp",
            "Wikipedia:Contentious topics/Climate change": "cc",
            "Wikipedia:Contentious topics/India, Pakistan, and Afghanistan": "ipa",
            "Wikipedia:Contentious topics/South Asia": "sa",
        }
        override_strings = {
            "arbind": "sa",
            "arbpia": "ipa",
        }
        return TopicDetector(codes=codes, page_to_code=page_to_code, override_strings=override_strings)

    def test_wp_ct_shortcut(self, detector):
        """Test WP:CT/<code> shortcuts."""
        assert detector.detect("Protected per WP:CT/AP") == "ap"
        assert detector.detect("wp:ct/blp protection") == "blp"
        assert detector.detect("WP:CTOP/CC applied") == "cc"
        assert detector.detect("Wikipedia:CT/IPA") == "ipa"
        assert detector.detect("Wikipedia:CTOP/SA") == "sa"

    def test_wp_ct_shortcut_case_insensitive(self, detector):
        """Test that shortcuts are case-insensitive."""
        assert detector.detect("WP:CT/ap") == "ap"
        assert detector.detect("wp:ct/AP") == "ap"
        assert detector.detect("WP:CT/Ap") == "ap"

    def test_specific_page_detection(self, detector):
        """Test detection by specific page name."""
        assert detector.detect("Protected via Wikipedia:Contentious topics/American politics") == "ap"
        assert detector.detect("See Wikipedia:Contentious topics/Biographies of living persons") == "blp"
        assert detector.detect("Wikipedia:Contentious topics/Climate change applies") == "cc"

    def test_specific_page_case_insensitive(self, detector):
        """Test that page detection is case-insensitive."""
        assert detector.detect("wikipedia:contentious topics/american politics") == "ap"
        assert detector.detect("WIKIPEDIA:CONTENTIOUS TOPICS/CLIMATE CHANGE") == "cc"

    def test_override_strings(self, detector):
        """Test override strings for special cases."""
        assert detector.detect("arbind applies") == "sa"
        assert detector.detect("ARBIND protection") == "sa"
        assert detector.detect("arbpia applies") == "ipa"

    def test_bare_code_token(self, detector):
        """Test bare code detection as standalone tokens."""
        assert detector.detect("AE action: AP") == "ap"
        assert detector.detect("BLP protection applied") == "blp"
        assert detector.detect("Protected CC") == "cc"

    def test_bare_code_not_in_word(self, detector):
        """Test that codes don't match when embedded in words."""
        # "ap" shouldn't match in "apply"
        assert detector.detect("apply protection") == ""
        # "at" should be excluded per the code (temporary fix for "at")
        assert detector.detect("at the request") == ""

    def test_bare_code_case_insensitive(self, detector):
        """Test that bare code detection is case-insensitive."""
        assert detector.detect("ap protection") == "ap"
        assert detector.detect("AP protection") == "ap"
        assert detector.detect("Ap protection") == "ap"

    def test_priority_order_shortcut_over_page(self, detector):
        """Test that WP:CT/ shortcuts have priority over specific pages."""
        # If both appear, shortcut should win (appears first in heuristics)
        comment = "WP:CT/BLP and also Wikipedia:Contentious topics/American politics"
        assert detector.detect(comment) == "blp"

    def test_priority_order_page_over_override(self, detector):
        """Test that specific pages have priority over override strings."""
        comment = "arbind and Wikipedia:Contentious topics/American politics"
        assert detector.detect(comment) == "ap"

    def test_priority_order_override_over_bare(self, detector):
        """Test that override strings have priority over bare codes."""
        comment = "arbind SA"
        assert detector.detect(comment) == "sa"

    def test_no_detection_empty_comment(self, detector):
        """Test that empty comments return empty string."""
        assert detector.detect("") == ""
        assert detector.detect(None) == ""

    def test_no_detection_no_matches(self, detector):
        """Test that unmatched comments return empty string."""
        assert detector.detect("Regular protection, no AE topic") == ""
        assert detector.detect("Vandalism protection") == ""

    def test_longest_code_first(self, detector):
        """Test that longer codes are matched before shorter ones."""
        # Create detector with codes that could overlap
        codes = ["a", "ab", "abc"]
        page_to_code = {}
        override_strings = {}
        det = TopicDetector(codes=codes, page_to_code=page_to_code, override_strings=override_strings)

        # "abc" should match, not "ab" or "a"
        assert det.detect("abc protection") == "abc"
        assert det.detect("ab protection") == "ab"
        assert det.detect("a protection") == "a"

    def test_multiple_codes_first_wins(self, detector):
        """Test that when multiple codes match, priority order determines result."""
        # Shortcut should win
        comment = "WP:CT/AP also mentions BLP"
        assert detector.detect(comment) == "ap"
