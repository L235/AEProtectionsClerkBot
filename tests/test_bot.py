"""Tests for bot.py pure functions."""

import time
import calendar
from datetime import datetime, timezone

import pytest

# Import the functions we want to test
from bot import (
    is_arbitration_enforcement,
    build_action_string,
    parse_mediawiki_sig_timestamp,
    to_mediawiki_sig_timestamp,
    extract_last_updated,
    extract_existing_logids,
    _get_event_sort_key,
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

    def test_roundtrip(self):
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

    def test_sorting_order(self):
        """Verify events sort correctly by timestamp."""
        events = [
            {"timestamp": "2025-08-19T20:00:00Z", "id": "later"},
            {"timestamp": "2025-08-19T19:00:00Z", "id": "earlier"},
            {"timestamp": "2025-08-19T19:30:00Z", "id": "middle"},
        ]
        sorted_events = sorted(events, key=_get_event_sort_key)
        assert [e["id"] for e in sorted_events] == ["earlier", "middle", "later"]
