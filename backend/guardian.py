"""Compatibility wrapper for the active Guardian decision engine.

The live application entry point and decision logic are implemented in app.py.
This module keeps older imports working without maintaining a second, divergent
policy engine.
"""

from app import check_guardian


def guardian_check(query: str, tool: str = "external_api"):
    """Delegate to the active Guardian engine.

    The optional ``tool`` argument is retained for compatibility with older
    callers; the active demo uses the controlled execution logic in app.py.
    """
    return check_guardian(query)
