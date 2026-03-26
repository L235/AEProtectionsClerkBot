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


class TestGSTopicDetector:
    """Tests for GS-specific TopicDetector."""

    @pytest.fixture
    def gs_detector(self):
        """Create a TopicDetector with GS configuration."""
        codes = ["kurd", "aa", "acas", "rusukr", "crypto", "pw", "mj", "scw&isil"]
        page_to_code = {
            "Wikipedia:General sanctions/Kurds and Kurdistan": "kurd",
            "Wikipedia:General sanctions/Armenia and Azerbaijan": "aa",
            "Wikipedia:General sanctions/Assyrian, Chaldean, Aramean and Syriac topics": "acas",
            "Wikipedia:General sanctions/Russo-Ukrainian war": "rusukr",
            "Wikipedia:General sanctions/Blockchain and cryptocurrencies": "crypto",
            "Wikipedia:General sanctions/Professional wrestling": "pw",
            "Wikipedia:General sanctions/Michael Jackson": "mj",
        }
        override_strings = {
            "gs/kurd": "kurd",
            "gs/aa": "aa",
            "gs/acas": "acas",
            "gs/rusukr": "rusukr",
            "gs/crypto": "crypto",
            "gs/pw": "pw",
            "gs/mj": "mj",
            "gs/scw": "scw&isil",
            "gs/isil": "scw&isil",
        }
        return TopicDetector(codes=codes, page_to_code=page_to_code, override_strings=override_strings)

    def test_gs_override_string(self, gs_detector):
        """WP:GS/ shortcuts detected via override strings."""
        assert gs_detector.detect("Per [[WP:GS/KURD]]") == "kurd"
        assert gs_detector.detect("[[WP:GS/AA]]") == "aa"
        assert gs_detector.detect("gs/acas") == "acas"

    def test_gs_specific_page(self, gs_detector):
        """Full GS page names detected via specific pages."""
        assert gs_detector.detect("[[Wikipedia:General sanctions/Kurds and Kurdistan]]") == "kurd"
        assert gs_detector.detect("Wikipedia:General sanctions/Armenia and Azerbaijan") == "aa"
        assert gs_detector.detect("Per [[Wikipedia:General sanctions/Russo-Ukrainian war]]") == "rusukr"

    def test_gs_bare_code(self, gs_detector):
        """Bare GS codes detected as tokens."""
        assert gs_detector.detect("kurd protection") == "kurd"
        assert gs_detector.detect("RUSUKR enforcement") == "rusukr"

    def test_gs_no_match(self, gs_detector):
        assert gs_detector.detect("regular protection") == ""
        assert gs_detector.detect("") == ""

    def test_gs_priority_page_over_override(self, gs_detector):
        """Specific page match takes priority over override string."""
        comment = "gs/aa and Wikipedia:General sanctions/Kurds and Kurdistan"
        assert gs_detector.detect(comment) == "kurd"

    def test_dual_authority_comment(self, gs_detector):
        """GS detector extracts GS code from dual-authority comment."""
        assert gs_detector.detect("[[WP:CT/KURD]]/[[WP:GS/KURD]]") == "kurd"
        assert gs_detector.detect("Arbitration enforcement - [[WP:CT/AA]]/[[WP:GS/AA]]") == "aa"


class TestLoadTopicsGS:
    """Tests for load_topics returning both AE and GS detectors."""

    def test_load_topics_returns_tuple(self):
        """load_topics should return (ae_detector, gs_detector) tuple."""
        import json
        from unittest.mock import patch, MagicMock
        from clerkbot.topics import load_topics

        config_data = {
            "codes": ["ap", "blp"],
            "specific_pages": {
                "Wikipedia:Contentious topics/American politics": "ap",
            },
            "override_strings": {"arbind": "sa"},
            "gs_codes": ["kurd", "aa"],
            "gs_specific_pages": {
                "Wikipedia:General sanctions/Kurds and Kurdistan": "kurd",
            },
            "gs_override_strings": {"gs/kurd": "kurd"},
        }

        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps(config_data).encode("utf-8")
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch("clerkbot.topics.urlopen", return_value=mock_response):
            ae_detector, gs_detector = load_topics("http://example.com/config.json", "TestAgent/1.0")

        assert ae_detector.detect("WP:CT/AP") == "ap"
        assert gs_detector.detect("gs/kurd") == "kurd"
        # AE detector should NOT know GS codes
        assert ae_detector.detect("gs/kurd") == ""
        # GS detector should NOT know AE codes
        assert gs_detector.detect("WP:CT/AP") == ""

    def test_load_topics_missing_gs_keys_returns_empty_detector(self):
        """When gs_* keys are absent, GS detector matches nothing."""
        import json
        from unittest.mock import patch, MagicMock
        from clerkbot.topics import load_topics

        config_data = {
            "codes": ["ap"],
            "specific_pages": {"Wikipedia:Contentious topics/American politics": "ap"},
            "override_strings": {},
        }

        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps(config_data).encode("utf-8")
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch("clerkbot.topics.urlopen", return_value=mock_response):
            ae_detector, gs_detector = load_topics("http://example.com/config.json", "TestAgent/1.0")

        assert ae_detector.detect("WP:CT/AP") == "ap"
        assert gs_detector.detect("gs/kurd") == ""
        assert gs_detector.detect("anything") == ""
