"""
Filtering logic for arbitration enforcement and community sanctions detection.

Provides functions to detect whether a protection action is related to
arbitration enforcement or community general sanctions based on edit summary keywords.
"""

# AE trigger phrases (case-insensitive) to detect arbitration enforcement
AE_TRIGGERS = [
    "arbitration",
    "arbcom",
    "ctop",
    "ct/",
    "contentious topic",
    "blpct",
    "blpds",
    "arbpia",
    "wp:ae ",  # Trailing space to avoid matching "WP:AELECT"
    "wikipedia:ae ",
    "wp:ae|",
    "wikipedia:ae|",
    "wp:ae]",
    "wikipedia:ae]",
]


def is_arbitration_enforcement(comment: str) -> bool:
    """
    Check if a protection action comment indicates arbitration enforcement.

    Args:
        comment: The edit summary or log comment to check

    Returns:
        True if the comment contains any AE trigger phrases, False otherwise
    """
    comment_lower = (comment or "").lower()
    return any(trigger in comment_lower for trigger in AE_TRIGGERS)


GS_TRIGGERS = [
    "general sanction",
    "community sanction",
    "community-designated contentious topic",
    "wp:gs/",
    "wp:gs ",
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


__all__ = [
    'AE_TRIGGERS',
    'is_arbitration_enforcement',
    'GS_TRIGGERS',
    'is_community_sanction',
]
