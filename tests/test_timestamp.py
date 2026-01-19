"""Tests for timestamp.py utility functions."""

from datetime import datetime, timezone

import pytest

from timestamp import (
    clean_invisible_unicode,
    format_expiry,
    parse_mediawiki_sig_timestamp,
    to_mediawiki_sig_timestamp,
    extract_last_updated,
)


class TestCleanInvisibleUnicode:
    """Tests for Unicode cleaning utility."""

    def test_removes_ltr_rtl_marks(self):
        text = "Hello\u200EWorld\u200F"
        assert clean_invisible_unicode(text) == "HelloWorld"

    def test_removes_directional_formatting(self):
        text = "Text\u202A\u202B\u202C\u202D\u202Ehere"
        assert clean_invisible_unicode(text) == "Texthere"

    def test_removes_directional_isolates(self):
        text = "Test\u2066\u2067\u2068\u2069text"
        assert clean_invisible_unicode(text) == "Testtext"

    def test_removes_zero_width_characters(self):
        text = "Zero\u200B\u200C\u200Dwidth"
        assert clean_invisible_unicode(text) == "Zerowidth"

    def test_removes_bom(self):
        text = "\uFEFFContent"
        assert clean_invisible_unicode(text) == "Content"

    def test_preserves_normal_text(self):
        text = "Normal text with spaces"
        assert clean_invisible_unicode(text) == "Normal text with spaces"

    def test_preserves_newlines_and_tabs(self):
        text = "Line 1\nLine 2\tTabbed"
        assert clean_invisible_unicode(text) == "Line 1\nLine 2\tTabbed"

    def test_handles_empty_string(self):
        assert clean_invisible_unicode("") == ""

    def test_handles_none(self):
        assert clean_invisible_unicode(None) is None

    def test_removes_control_characters(self):
        # Test that other control characters (except \n, \t, \r) are removed
        text = "Text\x00\x01\x02\x03here"
        result = clean_invisible_unicode(text)
        assert "\x00" not in result
        assert "\x01" not in result
        assert "Texthere" == result

    def test_complex_mixed_unicode(self):
        # Mix of visible text and invisible characters
        text = "User:\u200EJohn\u200F\u202ASmith\u202C\u200B"
        assert clean_invisible_unicode(text) == "User:JohnSmith"


class TestFormatExpiry:
    """Tests for expiry formatting."""

    def test_infinity(self):
        assert format_expiry("infinity") == "indefinite"

    def test_empty_string(self):
        assert format_expiry("") == "indefinite"

    def test_none(self):
        assert format_expiry(None) == "indefinite"

    def test_valid_datetime(self):
        assert format_expiry("20260227170300") == "17:03, 27 February 2026"

    def test_single_digit_day(self):
        assert format_expiry("20260103091500") == "09:15, 3 January 2026"

    def test_double_digit_day(self):
        assert format_expiry("20261215143000") == "14:30, 15 December 2026"

    def test_malformed_returns_raw(self):
        assert format_expiry("not-a-date") == "not-a-date"
        assert format_expiry("20260231000000") == "20260231000000"  # Invalid date


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

    def test_format_handles_naive_datetime(self):
        # Should add UTC timezone if missing
        dt = datetime(2025, 8, 19, 19, 32)
        result = to_mediawiki_sig_timestamp(dt)
        assert result == "19:32, 19 August 2025 (UTC)"


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

    def test_case_insensitive(self):
        text = "LAST UPDATED: 19:32, 19 August 2025 (UTC)"
        result = extract_last_updated(text)
        assert result is not None
        assert result.year == 2025

    def test_extra_whitespace(self):
        text = "   Last  updated:   19:32, 19 August 2025 (UTC)  "
        result = extract_last_updated(text)
        assert result is not None
