"""
Filtering logic for arbitration enforcement detection.

Provides functions to detect whether a protection action is related to
arbitration enforcement based on edit summary keywords.
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
    "wp:ae ",  # bodge to remove "WP:AELECT"
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


__all__ = [
    'AE_TRIGGERS',
    'is_arbitration_enforcement',
]
