"""
Configuration management for ClerkBot.

Provides BotConfig dataclass for managing all bot configuration from
environment variables.
"""

import os
import sys
from dataclasses import dataclass, field
from enum import Enum


class NotifyMode(str, Enum):
    """Notification mode for the notify-admin module."""
    DISABLED = "false"
    DEBUG = "debug"
    ENABLED = "true"


@dataclass
class BotConfig:
    """
    Bot configuration loaded from environment variables.

    All settings are loaded via from_environment() classmethod.
    Required fields (username, password, target_page) must be set.
    Optional fields have sensible defaults.

    Attributes:
        username: BotPassword username (CLERKBOT_USERNAME)
        password: BotPassword password (CLERKBOT_PASSWORD)
        target_page: Target wiki page to update (CLERKBOT_TARGET_PAGE)
        api_host: Wiki API host (default: "en.wikipedia.org")
        api_path: Wiki API path (default: "/w/")
        user_agent: HTTP User-Agent string
        config_url: URL for topic detection JSON config
        notify_mode: Admin notification mode (DISABLED/DEBUG/ENABLED)
        dryrun_page: Page for debug notifications
        log_level: Logging level (default: "INFO")
    """
    # Required fields
    username: str
    password: str
    target_page: str

    # Optional fields with defaults
    api_host: str = "en.wikipedia.org"
    api_path: str = "/w/"
    user_agent: str = "ClerkBot-AEProtections/1.0 (https://en.wikipedia.org/wiki/User:ClerkBot)"
    config_url: str = "https://en.wikipedia.org/w/index.php?title=User:ClerkBot/T3/config.json&action=raw&ctype=application/json"
    notify_mode: NotifyMode = NotifyMode.DEBUG
    dryrun_page: str = field(default="")  # Computed from target_page if not set
    log_level: str = "INFO"

    def __post_init__(self):
        """Set computed defaults after initialization."""
        if not self.dryrun_page:
            self.dryrun_page = f"{self.target_page}/notifications_dryrun"

    @classmethod
    def from_environment(cls) -> "BotConfig":
        """
        Load configuration from environment variables.

        Environment variables:
            CLERKBOT_USERNAME (required)
            CLERKBOT_PASSWORD (required)
            CLERKBOT_TARGET_PAGE (required)
            CLERKBOT_API_HOST (optional, default: "en.wikipedia.org")
            CLERKBOT_API_PATH (optional, default: "/w/")
            CLERKBOT_USER_AGENT (optional)
            CLERKBOT_CONFIG_URL (optional)
            CLERKBOT_NOTIFY_ADMINS (optional: "false", "debug", "true")
            CLERKBOT_NOTIFICATIONS_DRYRUN_PAGE (optional)
            CLERKBOT_LOG_LEVEL (optional, default: "INFO")

        Returns:
            BotConfig instance

        Raises:
            SystemExit: If required environment variables are missing
        """
        username = os.environ.get("CLERKBOT_USERNAME")
        password = os.environ.get("CLERKBOT_PASSWORD")
        target_page = os.environ.get("CLERKBOT_TARGET_PAGE")

        # Validate required fields before creating config
        if not username or not password or not target_page:
            # Print to stderr since logging may not be configured yet
            print(
                "ERROR: Missing required environment variables. "
                "Set CLERKBOT_USERNAME, CLERKBOT_PASSWORD, CLERKBOT_TARGET_PAGE.",
                file=sys.stderr
            )
            sys.exit(2)

        # Parse notify mode with validation
        notify_raw = (os.environ.get("CLERKBOT_NOTIFY_ADMINS") or "").strip().lower()
        if notify_raw not in (NotifyMode.DISABLED.value, NotifyMode.DEBUG.value, NotifyMode.ENABLED.value):
            notify_raw = NotifyMode.DEBUG.value
        notify_mode = NotifyMode(notify_raw)

        # Get optional values with defaults
        api_host = os.environ.get("CLERKBOT_API_HOST", "en.wikipedia.org")
        api_path = os.environ.get("CLERKBOT_API_PATH", "/w/")
        user_agent = os.environ.get(
            "CLERKBOT_USER_AGENT",
            "ClerkBot-AEProtections/1.0 (https://en.wikipedia.org/wiki/User:ClerkBot)"
        )
        config_url = os.environ.get(
            "CLERKBOT_CONFIG_URL",
            "https://en.wikipedia.org/w/index.php?title=User:ClerkBot/T3/config.json&action=raw&ctype=application/json"
        )
        dryrun_page = os.environ.get(
            "CLERKBOT_NOTIFICATIONS_DRYRUN_PAGE",
            f"{target_page}/notifications_dryrun"
        )
        log_level = os.environ.get("CLERKBOT_LOG_LEVEL", "INFO").upper()

        return cls(
            username=username,
            password=password,
            target_page=target_page,
            api_host=api_host,
            api_path=api_path,
            user_agent=user_agent,
            config_url=config_url,
            notify_mode=notify_mode,
            dryrun_page=dryrun_page,
            log_level=log_level,
        )


__all__ = ['NotifyMode', 'BotConfig']
