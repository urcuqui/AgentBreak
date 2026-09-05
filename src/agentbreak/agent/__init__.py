"""The flagship indirect-prompt-injection scenario: retrieval -> agent -> policy -> tool.

This subpackage demonstrates the central AgentBreak trust failure: retrieved
content is treated as trusted instructions by the agent. It exists alongside
(not instead of) the broader OWASP Top 10 for LLM lab in the parent
``agentbreak`` package.
"""

from __future__ import annotations
