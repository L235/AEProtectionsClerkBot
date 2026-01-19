"""Pytest configuration - runs before tests are collected."""

import os

# Set required environment variables before bot.py is imported
# These are dummy values just to pass validation - tests don't actually connect
os.environ.setdefault("CLERKBOT_USERNAME", "TestBot@Test")
os.environ.setdefault("CLERKBOT_PASSWORD", "test_password")
os.environ.setdefault("CLERKBOT_TARGET_PAGE", "User:TestBot/Test")
