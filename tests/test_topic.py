"""Tests for TopicDetector class and topic detection logic."""

import pytest

from clerkbot.topics import TopicDetector


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
