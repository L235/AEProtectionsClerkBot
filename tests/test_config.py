"""Tests for config.py configuration management."""

import os
import pytest
from unittest.mock import patch

from clerkbot.config import BotConfig, NotifyMode


class TestNotifyMode:
    """Tests for NotifyMode enum."""

    def test_enum_values(self):
        assert NotifyMode.DISABLED.value == "false"
        assert NotifyMode.DEBUG.value == "debug"
        assert NotifyMode.ENABLED.value == "true"


class TestBotConfig:
    """Tests for BotConfig dataclass and environment loading."""

    def test_post_init_sets_dryrun_page(self):
        """Test that dryrun_page is computed from target_page if not set."""
        config = BotConfig(
            username="test",
            password="pass",
            target_page="User:Bot/Log"
        )
        assert config.dryrun_page == "User:Bot/Log/notifications_dryrun"

    def test_post_init_preserves_explicit_dryrun_page(self):
        """Test that explicit dryrun_page is preserved."""
        config = BotConfig(
            username="test",
            password="pass",
            target_page="User:Bot/Log",
            dryrun_page="User:Bot/CustomDryrun"
        )
        assert config.dryrun_page == "User:Bot/CustomDryrun"

    def test_default_values(self):
        """Test that optional fields have correct defaults."""
        config = BotConfig(
            username="test",
            password="pass",
            target_page="User:Bot/Log"
        )
        assert config.api_host == "en.wikipedia.org"
        assert config.api_path == "/w/"
        assert config.user_agent == "ClerkBot-AEProtections/1.0 (https://en.wikipedia.org/wiki/User:ClerkBot)"
        assert config.notify_mode == NotifyMode.DEBUG
        assert config.log_level == "INFO"

    @patch.dict(os.environ, {
        "CLERKBOT_USERNAME": "TestBot",
        "CLERKBOT_PASSWORD": "secret123",
        "CLERKBOT_TARGET_PAGE": "User:TestBot/AE log"
    }, clear=True)
    def test_from_environment_minimal(self):
        """Test loading minimal required configuration from environment."""
        config = BotConfig.from_environment()
        assert config.username == "TestBot"
        assert config.password == "secret123"
        assert config.target_page == "User:TestBot/AE log"
        assert config.api_host == "en.wikipedia.org"
        assert config.notify_mode == NotifyMode.DEBUG

    @patch.dict(os.environ, {
        "CLERKBOT_USERNAME": "TestBot",
        "CLERKBOT_PASSWORD": "secret123",
        "CLERKBOT_TARGET_PAGE": "User:TestBot/AE log",
        "CLERKBOT_API_HOST": "test.wikipedia.org",
        "CLERKBOT_API_PATH": "/api/",
        "CLERKBOT_USER_AGENT": "CustomBot/2.0",
        "CLERKBOT_CONFIG_URL": "https://example.com/config.json",
        "CLERKBOT_NOTIFY_ADMINS": "true",
        "CLERKBOT_NOTIFICATIONS_DRYRUN_PAGE": "User:TestBot/Dryrun",
        "CLERKBOT_LOG_LEVEL": "DEBUG"
    }, clear=True)
    def test_from_environment_full(self):
        """Test loading full configuration from environment."""
        config = BotConfig.from_environment()
        assert config.username == "TestBot"
        assert config.password == "secret123"
        assert config.target_page == "User:TestBot/AE log"
        assert config.api_host == "test.wikipedia.org"
        assert config.api_path == "/api/"
        assert config.user_agent == "CustomBot/2.0"
        assert config.config_url == "https://example.com/config.json"
        assert config.notify_mode == NotifyMode.ENABLED
        assert config.dryrun_page == "User:TestBot/Dryrun"
        assert config.log_level == "DEBUG"

    @patch.dict(os.environ, {
        "CLERKBOT_USERNAME": "TestBot",
        "CLERKBOT_PASSWORD": "secret123",
        "CLERKBOT_TARGET_PAGE": "User:TestBot/AE log",
        "CLERKBOT_NOTIFY_ADMINS": "false"
    }, clear=True)
    def test_from_environment_notify_disabled(self):
        """Test notify mode can be disabled."""
        config = BotConfig.from_environment()
        assert config.notify_mode == NotifyMode.DISABLED

    @patch.dict(os.environ, {
        "CLERKBOT_USERNAME": "TestBot",
        "CLERKBOT_PASSWORD": "secret123",
        "CLERKBOT_TARGET_PAGE": "User:TestBot/AE log",
        "CLERKBOT_NOTIFY_ADMINS": "invalid"
    }, clear=True)
    def test_from_environment_invalid_notify_defaults_debug(self):
        """Test that invalid notify mode defaults to DEBUG."""
        config = BotConfig.from_environment()
        assert config.notify_mode == NotifyMode.DEBUG

    @patch.dict(os.environ, {
        "CLERKBOT_USERNAME": "TestBot",
        "CLERKBOT_PASSWORD": "secret123",
        "CLERKBOT_TARGET_PAGE": "User:TestBot/AE log",
        "CLERKBOT_NOTIFY_ADMINS": "  DEBUG  "  # With whitespace
    }, clear=True)
    def test_from_environment_notify_strips_whitespace(self):
        """Test that notify mode value is stripped of whitespace."""
        config = BotConfig.from_environment()
        assert config.notify_mode == NotifyMode.DEBUG

    @patch.dict(os.environ, {}, clear=True)
    def test_from_environment_missing_username_exits(self):
        """Test that missing username causes SystemExit."""
        with pytest.raises(SystemExit) as exc_info:
            BotConfig.from_environment()
        assert exc_info.value.code == 2

    @patch.dict(os.environ, {
        "CLERKBOT_USERNAME": "TestBot"
    }, clear=True)
    def test_from_environment_missing_password_exits(self):
        """Test that missing password causes SystemExit."""
        with pytest.raises(SystemExit) as exc_info:
            BotConfig.from_environment()
        assert exc_info.value.code == 2

    @patch.dict(os.environ, {
        "CLERKBOT_USERNAME": "TestBot",
        "CLERKBOT_PASSWORD": "secret123"
    }, clear=True)
    def test_from_environment_missing_target_page_exits(self):
        """Test that missing target page causes SystemExit."""
        with pytest.raises(SystemExit) as exc_info:
            BotConfig.from_environment()
        assert exc_info.value.code == 2

    @patch.dict(os.environ, {
        "CLERKBOT_USERNAME": "TestBot",
        "CLERKBOT_PASSWORD": "secret123",
        "CLERKBOT_TARGET_PAGE": "User:TestBot/AE log",
        "CLERKBOT_LOG_LEVEL": "warning"  # lowercase
    }, clear=True)
    def test_from_environment_log_level_uppercased(self):
        """Test that log level is converted to uppercase."""
        config = BotConfig.from_environment()
        assert config.log_level == "WARNING"
