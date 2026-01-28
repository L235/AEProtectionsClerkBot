"""Tests for bot.py pure functions."""

import time
import calendar
from datetime import datetime, timezone

import pytest

# Import the functions we want to test
from bot import (
    extract_existing_logids,
    _get_event_sort_key,
)
from clerkbot.entries import build_action_string
from clerkbot.filters import is_arbitration_enforcement
from clerkbot.timestamp import (
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


class TestFormatEntry:
    """Tests for log entry formatting."""

    def test_basic_entry_format(self):
        from clerkbot.entries import format_entry
        log_event = {
            "logid": 12345,
            "user": "Admin",
            "title": "Test Page",
            "timestamp": "2025-08-19T19:32:00Z",
            "comment": "Test protection",
            "type": "protect",
            "action": "protect",
            "params": {"description": "edit=autoconfirmed"}
        }
        result = format_entry(log_event, "ap")
        assert "{{User:ClerkBot/AE entry" in result
        assert "|logid=12345" in result
        assert "|admin=Admin" in result
        assert "|page=Test Page" in result
        assert "|topic=ap" in result
        assert "}}" in result

    def test_entry_with_empty_topic(self):
        from clerkbot.entries import format_entry
        log_event = {
            "logid": 12345,
            "user": "Admin",
            "title": "Test Page",
            "timestamp": "2025-08-19T19:32:00Z",
            "comment": "Test protection",
            "type": "protect",
            "action": "protect",
            "params": {"description": "edit=autoconfirmed"}
        }
        result = format_entry(log_event, "")
        assert "|topic=" in result
        # Should have empty topic parameter

    def test_entry_with_pending_changes(self):
        from clerkbot.entries import format_entry
        log_event = {
            "logid": 67890,
            "user": "AdminTwo",
            "title": "Another Page",
            "timestamp": "2025-08-20T10:00:00Z",
            "comment": "PC protection",
            "type": "stable",
            "action": "config",
            "params": {"autoreview": "autoconfirmed"}
        }
        result = format_entry(log_event, "blp")
        assert "|logid=67890" in result
        assert "|admin=AdminTwo" in result
        assert "|topic=blp" in result


class TestBuildNotificationText:
    """Tests for admin notification message building."""

    def test_single_item_notification(self):
        from bot import _build_notification_text
        items = [(12345, "19:32, 19 August 2025", "Test Page")]
        result = _build_notification_text("Admin", items, "User:ClerkBot/Test")
        assert "{{subst:User:ClerkBot/AE notification template" in result
        assert "|admin=Admin" in result
        assert "|target_page=User:ClerkBot/Test" in result
        assert "[[Special:Redirect/logid/12345|19:32, 19 August 2025]]" in result
        assert "([[Test Page]])" in result
        assert "}}" in result

    def test_multiple_items_notification(self):
        from bot import _build_notification_text
        items = [
            (12345, "19:32, 19 August 2025", "Page One"),
            (67890, "20:15, 20 August 2025", "Page Two"),
        ]
        result = _build_notification_text("AdminUser", items, "User:ClerkBot/Log")
        assert "[[Special:Redirect/logid/12345" in result
        assert "[[Special:Redirect/logid/67890" in result
        assert "([[Page One]])" in result
        assert "([[Page Two]])" in result
        # Should have multiple bullet points
        assert result.count("* [[Special:Redirect/logid/") == 2


class TestEditConflictHandling:
    """Tests for edit conflict detection and handling."""

    def test_save_page_update_includes_baserevid(self):
        """Test that _save_page_update passes baserevid to prevent edit conflicts."""
        from unittest.mock import Mock, patch
        from bot import _save_page_update

        # Create mock site
        mock_site = Mock()
        mock_site.get_token.return_value = "fake_token"
        mock_site.api.return_value = {"edit": {"result": "Success"}}

        # Call function
        _save_page_update(
            site=mock_site,
            target_page="Test:Page",
            new_text="New content",
            new_entries=["entry1"],
            base_revid=12345
        )

        # Verify API was called with baserevid
        mock_site.api.assert_called_once()
        call_args = mock_site.api.call_args
        assert call_args[1]["baserevid"] == 12345
        assert call_args[1]["title"] == "Test:Page"
        assert call_args[1]["text"] == "New content"

    def test_save_page_update_raises_on_edit_error(self):
        """Test that _save_page_update raises EditError on conflict."""
        from unittest.mock import Mock
        from bot import _save_page_update
        import mwclient.errors

        # Create mock site that raises EditError
        mock_site = Mock()
        mock_site.get_token.return_value = "fake_token"
        mock_site.api.side_effect = mwclient.errors.EditError(
            "editconflict",
            "Edit conflict detected"
        )

        # Verify EditError is raised
        with pytest.raises(mwclient.errors.EditError):
            _save_page_update(
                site=mock_site,
                target_page="Test:Page",
                new_text="New content",
                new_entries=["entry1"],
                base_revid=12345
            )
