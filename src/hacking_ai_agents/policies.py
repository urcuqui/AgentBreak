"""Authorization policies for the agent.

The hard rule of this project: *the model may propose an action, but Python
decides whether that action is allowed*. Policies are pure data so they can be
audited, diffed, and unit-tested without involving the model.
"""

from __future__ import annotations

from typing import Final

# Allowlist of tools per logical task.
# Anything not listed is denied by default.
ALLOWED_TOOLS_BY_TASK: Final[dict[str, frozenset[str]]] = {
    "refund_policy": frozenset({"search_knowledge_base"}),
    "shipping_policy": frozenset({"search_knowledge_base"}),
    "warranty_policy": frozenset({"search_knowledge_base"}),
    "customer_support": frozenset(
        {"search_knowledge_base", "create_support_ticket"}
    ),
}


# Fields whose presence inside tool arguments is forbidden, regardless of task.
SENSITIVE_ARGUMENT_KEYS: Final[frozenset[str]] = frozenset(
    {
        "api_key",
        "apikey",
        "password",
        "passwd",
        "token",
        "access_token",
        "refresh_token",
        "private_key",
        "secret",
        "client_secret",
        "credential",
        "credentials",
        "authorization",
    }
)


# Tools that must never receive sensitive data, even if the task allows them.
EGRESS_TOOLS: Final[frozenset[str]] = frozenset({"send_report"})


def is_tool_allowed(task: str, tool_name: str) -> bool:
    """Return ``True`` if ``tool_name`` is allowed for ``task``.

    Unknown tasks return ``False`` (deny by default).
    """

    allowed = ALLOWED_TOOLS_BY_TASK.get(task)
    if allowed is None:
        return False
    return tool_name in allowed
