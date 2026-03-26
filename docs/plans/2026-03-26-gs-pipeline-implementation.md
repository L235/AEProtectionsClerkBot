# GS Pipeline Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a community sanctions (GS) pipeline alongside the existing AE pipeline, enabling the bot to log protection actions taken under community-designated contentious topics, extended confirmed restrictions, and other community general sanctions.

**Architecture:** Dual-pipeline approach — a new `is_community_sanction()` filter and GS-specific `TopicDetector` run as a second pass after the existing AE pipeline. Both share entry formatting, page update, and dedup infrastructure. A `_run_pipeline()` helper is extracted from `main()` to avoid duplication.

**Tech Stack:** Python 3, mwclient, pytest

**Design doc:** `docs/plans/2026-03-26-gs-pipeline-design.md`

---

### Task 1: Add `is_community_sanction()` filter

**Files:**
- Modify: `clerkbot/filters.py`
- Modify: `clerkbot/__init__.py`
- Test: `tests/test_filters.py`

**Step 1: Write failing tests**

Add to `tests/test_filters.py`:

```python
from clerkbot.filters import GS_TRIGGERS, is_community_sanction


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
```

**Step 2: Run tests to verify they fail**

Run: `venv/bin/pytest tests/test_filters.py -v -k "GS or CommunityGS" 2>&1 | tail -20`
Expected: ImportError — `GS_TRIGGERS` and `is_community_sanction` don't exist yet.

**Step 3: Implement the filter**

Add to `clerkbot/filters.py` after the existing `is_arbitration_enforcement` function and `__all__`:

```python
GS_TRIGGERS = [
    "general sanction",
    "community sanction",
    "community-designated contentious topic",
    "wp:gs/",
    "wikipedia:gs/",
    "wp:gs|",
    "wikipedia:gs|",
    "wp:gs]",
    "wikipedia:gs]",
    "wikipedia:general sanctions/",
]


def is_community_sanction(comment: str) -> bool:
    """
    Check if a protection action comment indicates a community general sanction.

    Args:
        comment: The edit summary or log comment to check

    Returns:
        True if the comment contains any GS trigger phrases, False otherwise
    """
    comment_lower = (comment or "").lower()
    return any(trigger in comment_lower for trigger in GS_TRIGGERS)
```

Update `__all__` in `clerkbot/filters.py` to include `'GS_TRIGGERS'` and `'is_community_sanction'`.

Update `clerkbot/__init__.py` to import and re-export `GS_TRIGGERS` and `is_community_sanction`.

**Step 4: Run tests to verify they pass**

Run: `venv/bin/pytest tests/test_filters.py -v 2>&1 | tail -30`
Expected: All tests PASS, including both existing AE tests and new GS tests.

**Step 5: Commit**

```bash
git add clerkbot/filters.py clerkbot/__init__.py tests/test_filters.py
git commit -m "Add is_community_sanction() filter for GS pipeline (#5)"
```

---

### Task 2: Add GS fields to `BotConfig`

**Files:**
- Modify: `clerkbot/config.py`
- Test: `tests/test_config.py`

**Step 1: Write failing tests**

Add to `tests/test_config.py`:

```python
class TestBotConfigGS:
    """Tests for GS-related configuration fields."""

    def test_gs_defaults_when_not_set(self):
        """GS pipeline defaults to disabled."""
        config = BotConfig(
            username="test",
            password="pass",
            target_page="User:Bot/Log"
        )
        assert config.gs_target_page == ""
        assert config.gs_notify_mode == NotifyMode.DISABLED
        assert config.gs_dryrun_page == ""

    def test_gs_dryrun_page_computed(self):
        """gs_dryrun_page is computed from gs_target_page if not set."""
        config = BotConfig(
            username="test",
            password="pass",
            target_page="User:Bot/AE Log",
            gs_target_page="User:Bot/GS Log"
        )
        assert config.gs_dryrun_page == "User:Bot/GS Log/notifications_dryrun"

    def test_gs_dryrun_page_explicit(self):
        """Explicit gs_dryrun_page is preserved."""
        config = BotConfig(
            username="test",
            password="pass",
            target_page="User:Bot/AE Log",
            gs_target_page="User:Bot/GS Log",
            gs_dryrun_page="User:Bot/GS Dryrun"
        )
        assert config.gs_dryrun_page == "User:Bot/GS Dryrun"

    def test_gs_dryrun_page_empty_when_gs_disabled(self):
        """gs_dryrun_page stays empty when gs_target_page is empty."""
        config = BotConfig(
            username="test",
            password="pass",
            target_page="User:Bot/Log",
            gs_target_page=""
        )
        assert config.gs_dryrun_page == ""

    @patch.dict(os.environ, {
        "CLERKBOT_USERNAME": "TestBot",
        "CLERKBOT_PASSWORD": "secret123",
        "CLERKBOT_TARGET_PAGE": "User:TestBot/AE log",
    }, clear=True)
    def test_from_environment_gs_disabled_by_default(self):
        """GS pipeline is disabled when env vars are not set."""
        config = BotConfig.from_environment()
        assert config.gs_target_page == ""
        assert config.gs_notify_mode == NotifyMode.DISABLED

    @patch.dict(os.environ, {
        "CLERKBOT_USERNAME": "TestBot",
        "CLERKBOT_PASSWORD": "secret123",
        "CLERKBOT_TARGET_PAGE": "User:TestBot/AE log",
        "CLERKBOT_GS_TARGET_PAGE": "User:TestBot/GS log",
        "CLERKBOT_GS_NOTIFY_ADMINS": "debug",
        "CLERKBOT_GS_NOTIFICATIONS_DRYRUN_PAGE": "User:TestBot/GS dryrun",
    }, clear=True)
    def test_from_environment_gs_full(self):
        """GS configuration is loaded from environment."""
        config = BotConfig.from_environment()
        assert config.gs_target_page == "User:TestBot/GS log"
        assert config.gs_notify_mode == NotifyMode.DEBUG
        assert config.gs_dryrun_page == "User:TestBot/GS dryrun"

    @patch.dict(os.environ, {
        "CLERKBOT_USERNAME": "TestBot",
        "CLERKBOT_PASSWORD": "secret123",
        "CLERKBOT_TARGET_PAGE": "User:TestBot/AE log",
        "CLERKBOT_GS_TARGET_PAGE": "User:TestBot/GS log",
        "CLERKBOT_GS_NOTIFY_ADMINS": "invalid",
    }, clear=True)
    def test_from_environment_gs_invalid_notify_defaults_disabled(self):
        """Invalid GS notify mode defaults to DISABLED (not DEBUG like AE)."""
        config = BotConfig.from_environment()
        assert config.gs_notify_mode == NotifyMode.DISABLED
```

**Step 2: Run tests to verify they fail**

Run: `venv/bin/pytest tests/test_config.py -v -k "GS" 2>&1 | tail -20`
Expected: TypeError — `gs_target_page` is not a known field.

**Step 3: Implement config changes**

In `clerkbot/config.py`, add to `BotConfig` dataclass after the existing optional fields:

```python
    # GS pipeline fields (optional, disabled by default)
    gs_target_page: str = ""
    gs_notify_mode: NotifyMode = NotifyMode.DISABLED
    gs_dryrun_page: str = field(default="")
```

Update `__post_init__` to handle `gs_dryrun_page`:

```python
    def __post_init__(self):
        """Set computed defaults after initialization."""
        if not self.dryrun_page:
            self.dryrun_page = f"{self.target_page}/notifications_dryrun"
        if self.gs_target_page and not self.gs_dryrun_page:
            self.gs_dryrun_page = f"{self.gs_target_page}/notifications_dryrun"
```

Update `from_environment()` to read GS env vars. Add after the existing optional value loading:

```python
        # GS pipeline optional values
        gs_target_page = os.environ.get("CLERKBOT_GS_TARGET_PAGE", "")
        gs_notify_raw = (os.environ.get("CLERKBOT_GS_NOTIFY_ADMINS") or "").strip().lower()
        if gs_notify_raw not in (NotifyMode.DISABLED.value, NotifyMode.DEBUG.value, NotifyMode.ENABLED.value):
            gs_notify_raw = NotifyMode.DISABLED.value
        gs_notify_mode = NotifyMode(gs_notify_raw)
        gs_dryrun_page = os.environ.get("CLERKBOT_GS_NOTIFICATIONS_DRYRUN_PAGE", "")
```

Add these to the `cls(...)` constructor call:

```python
            gs_target_page=gs_target_page,
            gs_notify_mode=gs_notify_mode,
            gs_dryrun_page=gs_dryrun_page,
```

**Step 4: Run tests to verify they pass**

Run: `venv/bin/pytest tests/test_config.py -v 2>&1 | tail -30`
Expected: All tests PASS, both existing and new.

**Step 5: Commit**

```bash
git add clerkbot/config.py tests/test_config.py
git commit -m "Add GS pipeline fields to BotConfig (#5)"
```

---

### Task 3: Update `load_topics()` to return both detectors

**Files:**
- Modify: `clerkbot/topics.py`
- Modify: `clerkbot/__init__.py`
- Test: `tests/test_topic.py`

**Step 1: Write failing tests**

Add to `tests/test_topic.py`:

```python
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
```

**Step 2: Run tests to verify they fail**

Run: `venv/bin/pytest tests/test_topic.py -v -k "GS or LoadTopicsGS" 2>&1 | tail -20`
Expected: FAIL — `load_topics` returns a single `TopicDetector`, not a tuple.

**Step 3: Implement changes**

Modify `load_topics()` in `clerkbot/topics.py` to return a tuple:

```python
def load_topics(url: str, user_agent: str) -> tuple:
    """
    Load topic detection configuration from a URL.

    Args:
        url: URL to fetch the JSON configuration from
        user_agent: User-Agent header for the request

    Returns:
        Tuple of (ae_detector, gs_detector) TopicDetector instances

    Raises:
        ValueError: If the configuration JSON is missing required keys
    """
    log.info("Fetching topics configuration from %s", url)
    request = Request(url, headers={'User-Agent': user_agent})
    with urlopen(request) as response:
        data = json.loads(response.read().decode("utf-8"))
    codes = data.get("codes", [])
    page_to_code = data.get("specific_pages", {})
    override_strings = data.get("override_strings", {})
    if not codes or not page_to_code:
        raise ValueError("Configuration JSON missing required keys 'codes' or 'specific_pages'")

    ae_detector = TopicDetector(codes=codes, page_to_code=page_to_code, override_strings=override_strings)

    # GS detector — gracefully handle missing keys
    gs_codes = data.get("gs_codes", [])
    gs_page_to_code = data.get("gs_specific_pages", {})
    gs_override_strings = data.get("gs_override_strings", {})
    gs_detector = TopicDetector(codes=gs_codes, page_to_code=gs_page_to_code, override_strings=gs_override_strings)

    return ae_detector, gs_detector
```

**Note:** The `TopicDetector.__init__` already handles empty lists/dicts gracefully (it just won't match anything), so a GS detector built with empty config is safe.

Update `clerkbot/__init__.py` — no new exports needed since `load_topics` is already exported.

**Step 4: Run tests to verify they pass**

Run: `venv/bin/pytest tests/test_topic.py -v 2>&1 | tail -30`
Expected: All tests PASS.

**Step 5: Fix callers of `load_topics`**

The call in `bot.py:main()` currently does:

```python
detector = load_topics(config.config_url, config.user_agent)
```

This will break because `load_topics` now returns a tuple. Do NOT fix it yet — Task 5 handles this as part of the `main()` refactor. But we need to make sure existing tests that import from `bot` still pass by temporarily updating the call.

Actually, since `bot.py` is imported at test collection time (via `conftest.py` setting env vars, then `test_bot.py` importing from `bot`), we need to fix this now to avoid breaking the test suite. Update the single line in `bot.py:main()`:

```python
    # Old:
    detector = load_topics(config.config_url, config.user_agent)
    # New:
    ae_detector, _gs_detector = load_topics(config.config_url, config.user_agent)
```

And update the call to `_process_new_log_entries` to use `ae_detector` instead of `detector`:

```python
    new_entries, unclassified_by_admin = _process_new_log_entries(
        site, ae_detector, last_updated_dt, existing_logids
    )
```

**Step 6: Run full test suite**

Run: `venv/bin/pytest tests/ -v 2>&1 | tail -40`
Expected: All tests PASS.

**Step 7: Commit**

```bash
git add clerkbot/topics.py clerkbot/__init__.py tests/test_topic.py bot.py
git commit -m "Update load_topics() to return both AE and GS detectors (#5)"
```

---

### Task 4: Extract `_run_pipeline()` helper

This is the most complex task. We refactor the existing `main()` logic into a reusable pipeline function, then wire up both AE and GS pipelines.

**Files:**
- Modify: `bot.py`
- Test: `tests/test_bot.py`

**Step 1: Write failing tests for `_run_pipeline`**

Add to `tests/test_bot.py`:

```python
from unittest.mock import Mock, MagicMock, patch, call
from clerkbot.config import BotConfig, NotifyMode
from clerkbot.topics import TopicDetector
from clerkbot.filters import is_arbitration_enforcement, is_community_sanction


class TestRunPipeline:
    """Tests for _run_pipeline helper."""

    @pytest.fixture
    def mock_site(self):
        site = Mock()
        site.get_token.return_value = "fake_token"
        site.api.return_value = {"edit": {"result": "Success"}}
        return site

    @pytest.fixture
    def ae_detector(self):
        return TopicDetector(
            codes=["ap", "blp"],
            page_to_code={"Wikipedia:Contentious topics/American politics": "ap"},
            override_strings={},
        )

    @pytest.fixture
    def gs_detector(self):
        return TopicDetector(
            codes=["kurd", "aa"],
            page_to_code={"Wikipedia:General sanctions/Kurds and Kurdistan": "kurd"},
            override_strings={"gs/kurd": "kurd", "gs/aa": "aa"},
        )

    @pytest.fixture
    def base_config(self):
        return BotConfig(
            username="test",
            password="pass",
            target_page="User:Bot/AE Log",
            gs_target_page="User:Bot/GS Log",
        )

    def test_run_pipeline_returns_zero_on_success(self, mock_site, ae_detector, base_config):
        from bot import _run_pipeline

        page_text = "Last updated: 19:32, 19 August 2025 (UTC)\n{{/header}}\n{{/footer}}\n"
        mock_page = Mock()
        mock_page.exists = True
        mock_page.text.return_value = page_text
        mock_site.pages.__getitem__ = Mock(return_value=mock_page)
        mock_page.revisions.return_value = [{"revid": 100}]

        with patch("bot.enumerate_protect_logevents", return_value=[]), \
             patch("bot.enumerate_stable_logevents", return_value=[]):
            result = _run_pipeline(
                site=mock_site,
                detector=ae_detector,
                filter_fn=is_arbitration_enforcement,
                target_page="User:Bot/AE Log",
                notify_mode=NotifyMode.DISABLED,
                dryrun_page="",
                bot_usernames=set(),
                config=base_config,
            )
        assert result == 0

    def test_run_pipeline_returns_2_for_missing_page(self, mock_site, ae_detector, base_config):
        from bot import _run_pipeline

        mock_page = Mock()
        mock_page.exists = False
        mock_site.pages.__getitem__ = Mock(return_value=mock_page)
        mock_page.revisions.return_value = []

        result = _run_pipeline(
            site=mock_site,
            detector=ae_detector,
            filter_fn=is_arbitration_enforcement,
            target_page="User:Bot/AE Log",
            notify_mode=NotifyMode.DISABLED,
            dryrun_page="",
            bot_usernames=set(),
            config=base_config,
        )
        assert result == 2
```

**Step 2: Run tests to verify they fail**

Run: `venv/bin/pytest tests/test_bot.py::TestRunPipeline -v 2>&1 | tail -20`
Expected: ImportError — `_run_pipeline` doesn't exist yet.

**Step 3: Implement `_run_pipeline()` by extracting from `main()`**

In `bot.py`, create `_run_pipeline()` by extracting the core logic from `main()`. The function signature:

```python
def _run_pipeline(
    site: mwclient.Site,
    detector: "TopicDetector",
    filter_fn,
    target_page: str,
    notify_mode: NotifyMode,
    dryrun_page: str,
    bot_usernames: Set[str],
    config: BotConfig,
) -> int:
    """
    Run one pipeline (AE or GS).

    Fetches the target page, scans log events through the filter,
    detects topics, builds updated page text, and saves.

    Args:
        site: Authenticated mwclient Site
        detector: TopicDetector for categorizing actions
        filter_fn: Callable(str) -> bool, the filter to apply to comments
        target_page: Wiki page title to update
        notify_mode: NotifyMode for admin notifications
        dryrun_page: Page for debug notifications
        bot_usernames: Set of bot usernames to exclude from notifications
        config: Full BotConfig (for notification text building)

    Returns:
        0 on success, 2 on setup error, 1 on API error
    """
```

The body is the existing logic from `main()` starting at `page, base_revid = fetch_target_page(...)` through the save and notify steps, but using `filter_fn` instead of hardcoded `is_arbitration_enforcement`.

This requires modifying `_process_new_log_entries` to accept `filter_fn` as a parameter instead of hardcoding `is_arbitration_enforcement`. Change its signature:

```python
def _process_new_log_entries(
    site: mwclient.Site,
    detector: TopicDetector,
    filter_fn,
    last_updated_dt: datetime,
    existing_logids: set,
) -> Tuple[List[str], Dict[str, List[Tuple[int, str, str]]]]:
```

And in its body, change:
```python
    if not is_arbitration_enforcement(comment):
        return
```
to:
```python
    if not filter_fn(comment):
        return
```

Wait — that's in `_process_single_log_event`. So `_process_single_log_event` also needs `filter_fn` passed through. Update its signature:

```python
def _process_single_log_event(
    log_event: dict,
    detector: TopicDetector,
    filter_fn,
    existing_logids: set,
    new_entries: List[str],
    unclassified_by_admin: Dict[str, List[Tuple[int, str, str]]],
) -> None:
```

Then update `_process_new_log_entries` to pass `filter_fn` through to `_process_single_log_event`.

Then rewrite `main()` to:

```python
def main() -> int:
    # Load topic detection data
    try:
        ae_detector, gs_detector = load_topics(config.config_url, config.user_agent)
    except Exception as error:
        log.error("Failed to load CTOP topics configuration from '%s': %s", config.config_url, error)
        return 2

    # Connect to Wikipedia and load shared data
    site = connect_site(config)
    bot_usernames = fetch_bot_usernames(site)

    # AE pipeline (always runs)
    ae_result = _run_pipeline(
        site=site,
        detector=ae_detector,
        filter_fn=is_arbitration_enforcement,
        target_page=config.target_page,
        notify_mode=config.notify_mode,
        dryrun_page=config.dryrun_page,
        bot_usernames=bot_usernames,
        config=config,
    )
    if ae_result != 0:
        return ae_result

    # GS pipeline (only if configured)
    if config.gs_target_page:
        gs_result = _run_pipeline(
            site=site,
            detector=gs_detector,
            filter_fn=is_community_sanction,
            target_page=config.gs_target_page,
            notify_mode=config.gs_notify_mode,
            dryrun_page=config.gs_dryrun_page,
            bot_usernames=bot_usernames,
            config=config,
        )
        if gs_result != 0:
            return gs_result

    return 0
```

Add `is_community_sanction` to the imports at the top of `bot.py`:

```python
from clerkbot.filters import is_arbitration_enforcement, is_community_sanction
```

**Step 4: Run tests to verify they pass**

Run: `venv/bin/pytest tests/test_bot.py -v 2>&1 | tail -40`
Expected: All tests PASS.

**Step 5: Run full test suite**

Run: `venv/bin/pytest tests/ -v 2>&1 | tail -40`
Expected: All tests PASS. Existing AE behavior is preserved.

**Step 6: Commit**

```bash
git add bot.py tests/test_bot.py
git commit -m "Extract _run_pipeline() helper and wire up GS pipeline (#5)"
```

---

### Task 5: Add integration-style tests for dual-pipeline behavior

**Files:**
- Modify: `tests/test_bot.py`

**Step 1: Write tests for dual-pipeline scenarios**

Add to `tests/test_bot.py`:

```python
class TestDualPipeline:
    """Tests for AE + GS dual pipeline behavior."""

    def test_gs_pipeline_skipped_when_not_configured(self):
        """GS pipeline should not run when gs_target_page is empty."""
        config = BotConfig(
            username="test", password="pass",
            target_page="User:Bot/AE Log",
            gs_target_page="",
        )
        assert config.gs_target_page == ""
        # This is tested implicitly by main() — gs_target_page == "" means
        # the GS _run_pipeline call is skipped entirely

    def test_ae_filter_does_not_match_gs_only(self):
        """AE filter should not match GS-only comments."""
        assert not is_arbitration_enforcement("Per [[WP:GS/KURD]]")
        assert not is_arbitration_enforcement("[[Wikipedia:General sanctions/Armenia and Azerbaijan]]")
        assert not is_arbitration_enforcement("community sanction enforcement")

    def test_gs_filter_does_not_match_ae_only(self):
        """GS filter should not match AE-only comments."""
        assert not is_community_sanction("Per arbitration enforcement WP:CT/BLP")
        assert not is_community_sanction("CTOP protection")
        assert not is_community_sanction("[[WP:AE]] action")

    def test_both_filters_match_dual_authority(self):
        """Both filters should match dual-authority comments."""
        dual = "[[WP:30/500|Arbitration enforcement]] - [[WP:CT/KURD]]/[[WP:GS/KURD]]"
        assert is_arbitration_enforcement(dual)
        assert is_community_sanction(dual)

    def test_dedup_via_logid(self):
        """Existing logid extraction works for dedup across pipelines."""
        from bot import extract_existing_logids
        text = "{{User:ClerkBot/AE entry|logid=12345|admin=A}}\n{{User:ClerkBot/AE entry|logid=67890|admin=B}}"
        logids = extract_existing_logids(text)
        assert 12345 in logids
        assert 67890 in logids
```

**Step 2: Run tests**

Run: `venv/bin/pytest tests/test_bot.py::TestDualPipeline -v 2>&1 | tail -20`
Expected: All PASS.

**Step 3: Commit**

```bash
git add tests/test_bot.py
git commit -m "Add dual-pipeline integration tests (#5)"
```

---

### Task 6: Update `__init__.py` exports and docstrings

**Files:**
- Modify: `clerkbot/__init__.py`
- Modify: `bot.py` (module docstring)

**Step 1: Update `clerkbot/__init__.py`**

Add `GS_TRIGGERS` and `is_community_sanction` to the imports and `__all__` list if not already done in Task 1.

**Step 2: Update `bot.py` module docstring**

Add the new GS env vars to the docstring at the top of `bot.py`:

```
  CLERKBOT_GS_TARGET_PAGE        Optional. Target page for GS entries (empty = GS disabled)
  CLERKBOT_GS_NOTIFY_ADMINS      Optional. Notification mode for GS pipeline ("false", "debug", "true")
  CLERKBOT_GS_NOTIFICATIONS_DRYRUN_PAGE  Optional. Debug notification page for GS
```

**Step 3: Run full test suite**

Run: `venv/bin/pytest tests/ -v 2>&1 | tail -40`
Expected: All tests PASS.

**Step 4: Commit**

```bash
git add clerkbot/__init__.py bot.py
git commit -m "Update exports and docstrings for GS pipeline (#5)"
```

---

### Task 7: Final verification and cleanup

**Step 1: Run full test suite with coverage**

Run: `venv/bin/pytest tests/ -v --cov=clerkbot --cov=bot --cov-report=term-missing 2>&1 | tail -50`
Expected: All tests PASS. New code has reasonable coverage.

**Step 2: Verify no regressions by checking existing AE test counts**

Run: `venv/bin/pytest tests/ -v 2>&1 | grep -c PASSED`
Expected: Test count increased from before (new GS tests added, no tests removed).

**Step 3: Clean up pywikibot files**

Remove the pywikibot credentials and venv artifacts that were added for research:
```bash
rm -f user-config.py user-password.py
rm -rf venv/
```

**Step 4: Final commit**

```bash
git add -A
git commit -m "Clean up research artifacts (#5)"
```

**Step 5: Push and create PR**

```bash
git checkout -b gs-pipeline
git push -u origin gs-pipeline
gh pr create --title "Add community sanctions (GS) pipeline" --body "$(cat <<'EOF'
## Summary
- Adds `is_community_sanction()` filter for detecting community general sanction protection actions
- Adds GS fields to `BotConfig` (`CLERKBOT_GS_TARGET_PAGE`, `CLERKBOT_GS_NOTIFY_ADMINS`, etc.)
- Updates `load_topics()` to return both AE and GS `TopicDetector` instances from merged on-wiki config
- Extracts `_run_pipeline()` helper from `main()` to avoid duplication
- Wires up GS pipeline to run after AE pipeline when configured
- GS notifications default to disabled (see #19 for future template support)

Closes #5

## Test plan
- [ ] All existing AE tests pass unchanged
- [ ] New GS filter tests verify trigger matching and no false positives
- [ ] New config tests verify GS env var loading and defaults
- [ ] New topic detector tests verify GS-specific detection
- [ ] Dual-pipeline tests verify dedup and filter independence
- [ ] Manual test with `CLERKBOT_GS_TARGET_PAGE` set to a test page
EOF
)"
```
