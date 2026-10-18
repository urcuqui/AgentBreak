"""Named control profiles for the workshop's "introduce a regression" step.

The CLI workshop weakens the policy with
``workshop/patches/broaden-incident-agent-access.patch`` (``git apply``). The
web lab must never edit source files, so this module reproduces the *same
logical posture* in memory instead, and only for the duration of one call:

* ``baseline``                  -- the repository's policy, untouched.
* ``broadened-incident-access`` -- ``get_asset_credentials`` is added to the
  ``grid_incident_response`` allowlist and is no longer treated as high-impact
  (so the human-approval gate stops covering it). Exactly the two edits the
  patch makes to ``policy.py`` and ``tools.py``.

Profiles are a fixed, closed set. There is no way to pass an arbitrary change.
"""

from __future__ import annotations

import threading
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Final

from . import policy, tools

BASELINE: Final = "baseline"
BROADENED: Final = "broadened-incident-access"

PROFILES: Final[dict[str, str]] = {
    BASELINE: "Repository default: the incident agent may only search the knowledge base.",
    BROADENED: (
        "Workshop regression (same as broaden-incident-agent-access.patch): "
        "get_asset_credentials is allowed for grid_incident_response and no "
        "longer requires human approval."
    ),
}

_TASK = "grid_incident_response"
# Module globals are process-wide, so concurrent requests must not interleave.
_LOCK = threading.Lock()


@contextmanager
def control_profile(name: str) -> Iterator[None]:
    """Apply profile ``name`` for the body of the ``with`` block, then restore."""

    if name not in PROFILES:
        raise ValueError(f"unknown control profile '{name}'")
    with _LOCK:
        if name == BASELINE:
            yield
            return
        saved_allow = policy.ALLOWED_TOOLS_BY_TASK[_TASK]
        saved_policy_hi = policy.HIGH_IMPACT_TOOLS
        saved_tools_hi = tools.HIGH_IMPACT_TOOLS
        weakened_hi = saved_tools_hi - {"get_asset_credentials"}
        policy.ALLOWED_TOOLS_BY_TASK[_TASK] = saved_allow | {"get_asset_credentials"}
        policy.HIGH_IMPACT_TOOLS = weakened_hi
        tools.HIGH_IMPACT_TOOLS = weakened_hi
        try:
            yield
        finally:
            policy.ALLOWED_TOOLS_BY_TASK[_TASK] = saved_allow
            policy.HIGH_IMPACT_TOOLS = saved_policy_hi
            tools.HIGH_IMPACT_TOOLS = saved_tools_hi
