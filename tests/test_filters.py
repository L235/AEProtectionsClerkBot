"""Tests for filters.py arbitration enforcement detection."""

import pytest

from clerkbot.filters import AE_TRIGGERS, is_arbitration_enforcement
from clerkbot.filters import GS_TRIGGERS, is_community_sanction


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


class TestGSTriggers:
    """Tests for GS_TRIGGERS constant."""

    def test_triggers_list_not_empty(self):
        assert len(GS_TRIGGERS) > 0

    def test_triggers_are_lowercase(self):
        for trigger in GS_TRIGGERS:
            assert trigger == trigger.lower(), f"Trigger '{trigger}' is not lowercase"

    def test_triggers_are_strings(self):
        for trigger in GS_TRIGGERS:
            assert isinstance(trigger, str)

    def test_expected_triggers_present(self):
        expected = ["general sanction", "wp:gs/", "wikipedia:general sanctions/"]
        for trigger in expected:
            assert trigger in GS_TRIGGERS, f"Expected trigger '{trigger}' not found"


class TestIsCommunityGS:
    """Tests for community sanction detection."""

    def test_wp_gs_slash_trigger(self):
        assert is_community_sanction("Per [[WP:GS/KURD]]")
        assert is_community_sanction("[[WP:GS/AA]]")
        assert is_community_sanction("wp:gs/acas")

    def test_wikipedia_gs_slash_trigger(self):
        assert is_community_sanction("[[Wikipedia:GS/KURD]]")

    def test_wp_gs_bracket_trigger(self):
        assert is_community_sanction("[[WP:GS]]")
        assert is_community_sanction("[[WP:GS|community sanctions]]")

    def test_full_page_name_trigger(self):
        assert is_community_sanction("[[Wikipedia:General sanctions/Kurds and Kurdistan]]")
        assert is_community_sanction("Wikipedia:General sanctions/Armenia and Azerbaijan")

    def test_general_sanction_phrase(self):
        assert is_community_sanction("Per general sanctions")
        assert is_community_sanction("GENERAL SANCTION applies")

    def test_community_sanction_phrase(self):
        assert is_community_sanction("community sanction enforcement")
        assert is_community_sanction("Community Sanction")

    def test_community_designated_phrase(self):
        assert is_community_sanction("community-designated contentious topic")

    def test_wp_gs_bare_with_space(self):
        assert is_community_sanction("Per WP:GS enforcement")
        assert is_community_sanction("WP:GS applies here")

    def test_case_insensitive(self):
        assert is_community_sanction("WP:GS/KURD")
        assert is_community_sanction("wp:gs/kurd")
        assert is_community_sanction("Wp:Gs/Kurd")

    def test_no_match(self):
        assert not is_community_sanction("Regular vandalism protection")
        assert not is_community_sanction("Requested at RFPP")
        assert not is_community_sanction("")
        assert not is_community_sanction(None)
        assert not is_community_sanction("   ")

    def test_no_false_positive_from_substrings(self):
        """Ensure common words containing trigger substrings don't match."""
        assert not is_community_sanction("Repeatedly recreated")
        assert not is_community_sanction("persistent disruption")

    def test_ae_only_comment_does_not_match(self):
        """AE-only comments should not match the GS filter."""
        assert not is_community_sanction("Per arbitration enforcement WP:CT/BLP")
        assert not is_community_sanction("CTOP protection")

    def test_dual_authority_comment_matches(self):
        """Comments citing both AE and GS should match GS filter."""
        assert is_community_sanction("[[WP:CT/KURD]]/[[WP:GS/KURD]]")
        assert is_community_sanction("Arbitration enforcement - [[WP:CT/AA]]/[[WP:GS/AA]]")

    def test_real_world_comments(self):
        """Test against real edit summaries observed in the wild."""
        assert is_community_sanction("Per [[WP:GS/KURD]]")
        assert is_community_sanction("[[Wikipedia:General sanctions/Armenia and Azerbaijan]]")
        assert is_community_sanction("[[WP:GS#Community sanctions|Community sanctions enforcement]]: WP:GS/KURD")
        assert is_community_sanction("Enforcement for [[WP:GS/PW]]")
        assert is_community_sanction("Persistent disruptive editing - [[WP:GS/MJ]]; requested at [[WP:RfPP]]")
        assert is_community_sanction("[[WP:GS/RUSUKR]]")

    def test_special_characters_in_comment(self):
        assert is_community_sanction("[[WP:GS/KURD|community sanctions]]")
        assert is_community_sanction("Protection: [[Wikipedia:General sanctions/Weather events]]")


class TestRealWorldComments:
    """
    Tests against real edit summaries from Wikipedia protection logs.
    Source: 5000 recent protect log events queried 2026-03-26.
    """

    # --- AE-only comments: match AE, NOT GS ---

    @pytest.mark.parametrize("comment", [
        "Violations of the [[WP:BLP|biographies of living persons policy]] - [[WP:CT/BLP]]; requested at [[WP:RfPP]]",
        "Persistent [[WP:Disruptive editing|disruptive editing]] - arbitration enforcment: [[WP:CT/GG]]; requested at [[WP:RfPP]]",
        "[[WP:30/500|Arbitration enforcement]] - [[WP:CT/IMH]]",
        "Persistent [[WP:Disruptive editing|disruptive editing]] - arbitration enforcement: [[WP:CT/SA]]; requested at [[WP:RfPP]]",
        "[[WP:CTOP|Contentious topic]] restriction: [[WP:BLPCT]]",
        "[[WP:30/500|Arbitration enforcement]] [[WP:CT/IMH]]",
        "[[WP:30/500|Arbitration enforcement]], [[WP:CT/SA]], edit warring and other disruptive editing from TAs and autoconfirmed",
    ])
    def test_ae_only_matches_ae(self, comment):
        assert is_arbitration_enforcement(comment)

    @pytest.mark.parametrize("comment", [
        "Violations of the [[WP:BLP|biographies of living persons policy]] - [[WP:CT/BLP]]; requested at [[WP:RfPP]]",
        "Persistent [[WP:Disruptive editing|disruptive editing]] - arbitration enforcment: [[WP:CT/GG]]; requested at [[WP:RfPP]]",
        "[[WP:30/500|Arbitration enforcement]] - [[WP:CT/IMH]]",
        "Persistent [[WP:Disruptive editing|disruptive editing]] - arbitration enforcement: [[WP:CT/SA]]; requested at [[WP:RfPP]]",
        "[[WP:CTOP|Contentious topic]] restriction: [[WP:BLPCT]]",
        "[[WP:30/500|Arbitration enforcement]] [[WP:CT/IMH]]",
    ])
    def test_ae_only_does_not_match_gs(self, comment):
        assert not is_community_sanction(comment)

    # --- GS-only comments: match GS, NOT AE ---

    @pytest.mark.parametrize("comment", [
        "Per [[WP:GS/KURD]]",
        "[[Wikipedia:General sanctions/Armenia and Azerbaijan]]",
        "[[WP:GS#Community sanctions|Community sanctions enforcement]]: WP:GS/KURD",
        "[[WP:GS#Community sanctions|Community sanctions enforcement]]: per RFPP and [[WP:GS/PAGEANT]]",
        "Enforcement for [[WP:GS/PW]]",
        "Persistent [[WP:Disruptive editing|disruptive editing]] - [[WP:GS/MJ]]; requested at [[WP:RfPP]]",
        "[[WP:GS/RUSUKR]]",
        "Per [[Wikipedia:General sanctions/Russo-Ukrainian war]]",
        "Per [[Wikipedia:General sanctions/Kurds and Kurdistan]]",
        "[[WP:GS#Community sanctions|Community sanctions enforcement]]: per [[WP:GS/ACAS]]",
    ])
    def test_gs_only_matches_gs(self, comment):
        assert is_community_sanction(comment)

    @pytest.mark.parametrize("comment", [
        "Per [[WP:GS/KURD]]",
        "[[Wikipedia:General sanctions/Armenia and Azerbaijan]]",
        "Enforcement for [[WP:GS/PW]]",
        "Persistent [[WP:Disruptive editing|disruptive editing]] - [[WP:GS/MJ]]; requested at [[WP:RfPP]]",
        "[[WP:GS/RUSUKR]]",
        "Per [[Wikipedia:General sanctions/Russo-Ukrainian war]]",
    ])
    def test_gs_only_does_not_match_ae(self, comment):
        assert not is_arbitration_enforcement(comment)

    # --- Dual-authority comments: match BOTH ---

    @pytest.mark.parametrize("comment", [
        "[[WP:30/500|Arbitration enforcement]] - [[WP:CT/KURD]]/[[WP:GS/KURD]]",
        "[[WP:30/500|Arbitration enforcement]] - [[WP:CT/KURD]]/[[WP:GS/KURD]]; requested at [[WP:RfPP]]",
        "[[WP:30/500|Arbitration enforcement]] - [[WP:CT/AA]]/[[WP:GS/AA]]; requested at [[WP:RfPP]]",
        "Persistent [[WP:Vandalism|vandalism]] - [[WP:CT/KURD]]/[[WP:GS/KURD]]; requested at [[WP:RfPP]]",
        "[[WP:CT/A-I]], [[WP:GS/KURD]]",
    ])
    def test_dual_matches_both_ae(self, comment):
        assert is_arbitration_enforcement(comment)

    @pytest.mark.parametrize("comment", [
        "[[WP:30/500|Arbitration enforcement]] - [[WP:CT/KURD]]/[[WP:GS/KURD]]",
        "[[WP:30/500|Arbitration enforcement]] - [[WP:CT/KURD]]/[[WP:GS/KURD]]; requested at [[WP:RfPP]]",
        "[[WP:30/500|Arbitration enforcement]] - [[WP:CT/AA]]/[[WP:GS/AA]]; requested at [[WP:RfPP]]",
        "Persistent [[WP:Vandalism|vandalism]] - [[WP:CT/KURD]]/[[WP:GS/KURD]]; requested at [[WP:RfPP]]",
        "[[WP:CT/A-I]], [[WP:GS/KURD]]",
    ])
    def test_dual_matches_both_gs(self, comment):
        assert is_community_sanction(comment)

    # --- Neither: should match nothing ---

    @pytest.mark.parametrize("comment", [
        "[[WP:SALT|Repeatedly recreated]] by socks",
        "[[WP:SALT|Repeatedly recreated]]",
        "Persistent [[WP:Disruptive editing|disruptive editing]]; requested at [[WP:RfPP]]",
        "Restoring protection by [[User:Pathoschild|Pathoschild]]",
        "",
    ])
    def test_neither_matches_ae(self, comment):
        assert not is_arbitration_enforcement(comment)

    @pytest.mark.parametrize("comment", [
        "[[WP:SALT|Repeatedly recreated]] by socks",
        "[[WP:SALT|Repeatedly recreated]]",
        "Persistent [[WP:Disruptive editing|disruptive editing]]; requested at [[WP:RfPP]]",
        "Restoring protection by [[User:Pathoschild|Pathoschild]]",
        "",
    ])
    def test_neither_matches_gs(self, comment):
        assert not is_community_sanction(comment)
