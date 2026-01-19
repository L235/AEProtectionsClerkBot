"""Tests for filters.py arbitration enforcement detection."""

import pytest

from filters import AE_TRIGGERS, is_arbitration_enforcement


class TestAETriggers:
    """Tests for AE_TRIGGERS constant."""

    def test_triggers_list_not_empty(self):
        assert len(AE_TRIGGERS) > 0

    def test_triggers_are_lowercase(self):
        """All triggers should be lowercase for case-insensitive matching."""
        for trigger in AE_TRIGGERS:
            assert trigger == trigger.lower(), f"Trigger '{trigger}' is not lowercase"

    def test_triggers_are_strings(self):
        """All triggers should be strings."""
        for trigger in AE_TRIGGERS:
            assert isinstance(trigger, str)

    def test_expected_triggers_present(self):
        """Verify key triggers are present."""
        expected = ["arbitration", "arbcom", "ctop", "ct/", "contentious topic", "blpct"]
        for trigger in expected:
            assert trigger in AE_TRIGGERS, f"Expected trigger '{trigger}' not found"


class TestIsArbitrationEnforcement:
    """Tests for AE detection function."""

    def test_ctop_trigger(self):
        assert is_arbitration_enforcement("Protected per WP:CTOP/BLP")
        assert is_arbitration_enforcement("ctop blp")

    def test_ct_slash_trigger(self):
        assert is_arbitration_enforcement("WP:CT/AP")
        assert is_arbitration_enforcement("per ct/blp")

    def test_arbitration_trigger(self):
        assert is_arbitration_enforcement("Per arbitration enforcement")
        assert is_arbitration_enforcement("ARBITRATION decision")

    def test_arbcom_trigger(self):
        assert is_arbitration_enforcement("Per ArbCom decision")
        assert is_arbitration_enforcement("arbcom ruling")

    def test_contentious_topic_trigger(self):
        assert is_arbitration_enforcement("contentious topic protection")
        assert is_arbitration_enforcement("CONTENTIOUS TOPIC applies")

    def test_ae_trigger_with_space(self):
        # "wp:ae " should match (with trailing space to avoid "WP:AELECT")
        assert is_arbitration_enforcement("per WP:AE action")
        assert is_arbitration_enforcement("Wikipedia:AE request")

    def test_ae_trigger_with_brackets(self):
        assert is_arbitration_enforcement("[[WP:AE]]")
        assert is_arbitration_enforcement("[[WP:AE|link]]")

    def test_ae_trigger_with_pipe(self):
        assert is_arbitration_enforcement("[[WP:AE|arbitration enforcement]]")
        assert is_arbitration_enforcement("link: wp:ae|text")

    def test_blpct_trigger(self):
        assert is_arbitration_enforcement("BLPCT protection")
        assert is_arbitration_enforcement("per blpct")

    def test_blpds_trigger(self):
        assert is_arbitration_enforcement("BLPDS applies")
        assert is_arbitration_enforcement("blpds protection")

    def test_arbpia_trigger(self):
        assert is_arbitration_enforcement("arbpia restriction")
        assert is_arbitration_enforcement("ARBPIA applies")

    def test_case_insensitive(self):
        """Test that detection is case-insensitive."""
        assert is_arbitration_enforcement("CTOP")
        assert is_arbitration_enforcement("Ctop")
        assert is_arbitration_enforcement("ctop")
        assert is_arbitration_enforcement("ArBiTrAtIoN")

    def test_no_match(self):
        assert not is_arbitration_enforcement("Regular vandalism protection")
        assert not is_arbitration_enforcement("Requested at RFPP")
        assert not is_arbitration_enforcement("")
        assert not is_arbitration_enforcement(None)

    def test_aelect_should_not_match(self):
        # This is the "bodge" case - WP:AELECT should not trigger
        # because the trigger is "wp:ae " (with trailing space)
        assert not is_arbitration_enforcement("See WP:AELECT for more")
        assert not is_arbitration_enforcement("wikipedia:aelection")

    def test_partial_word_no_match(self):
        """Test that triggers don't match as part of other words."""
        # "arbitration" shouldn't match in "arbitrary"
        assert not is_arbitration_enforcement("arbitrary decision")
        # But "arbitration" should match
        assert is_arbitration_enforcement("arbitration decision")

    def test_multiple_triggers(self):
        """Test comments with multiple triggers."""
        comment = "Per arbitration and ctop/ap"
        assert is_arbitration_enforcement(comment)

    def test_trigger_in_middle_of_comment(self):
        """Test triggers anywhere in comment."""
        assert is_arbitration_enforcement("This is a ctop protection")
        assert is_arbitration_enforcement("Protection applied (arbitration)")
        assert is_arbitration_enforcement("Start arbitration end")

    def test_empty_and_none_inputs(self):
        """Test edge cases with empty/None inputs."""
        assert not is_arbitration_enforcement("")
        assert not is_arbitration_enforcement(None)
        assert not is_arbitration_enforcement("   ")  # Whitespace only

    def test_special_characters_in_comment(self):
        """Test comments with special characters."""
        assert is_arbitration_enforcement("[[WP:CTOP/AP|contentious topic]]")
        assert is_arbitration_enforcement("Protection: [[arbitration]]")
        assert is_arbitration_enforcement("See {{ct/blp}} for details")
