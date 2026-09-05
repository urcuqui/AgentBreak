# AgentBreak — Threat Model

Scope: the flagship indirect-prompt-injection scenario (`agentbreak.agent`) —
a tool-using support/SOC agent that answers questions from a retrieved
knowledge base. The broader OWASP Top 10 for LLM lab (`agentbreak.chatbot`,
`agentbreak.probes`) has its own, wider scope and is not the subject of this
document.

## Assets

* **Sensitive credentials** — grid-asset maintenance access tokens
  (`data/assets.json`), customer records and API keys (`data/customers.json`).
* **Tool execution** — the ability to invoke `get_asset_credentials` and
  `send_report`.
* **Internal knowledge base** — the operational documents the agent retrieves
  from (`data/*_knowledge_base.json`).
* **Agent reasoning / context window** — whatever the agent currently
  believes it has been told to do.
* **External destinations** — anywhere `send_report` could be pointed.
* **User and operator trust** — the assumption that the agent's behavior
  reflects the user's request, not a third party's.

## Trust boundaries

```
User ────────────► Agent
Retrieval Source ─► Agent        <-- the boundary this project demonstrates
Agent ───────────► Tool
Tool ────────────► External Service
```

* **User → Agent** — the user is assumed semi-trusted (they asked a
  legitimate question) but not authorized to trigger arbitrary tool calls
  merely by phrasing.
* **Retrieval Source → Agent** — the boundary AgentBreak's flagship scenario
  exists to demonstrate. Anything returned by retrieval is data, is
  `trust_level=untrusted` regardless of source, and must not be treated as an
  instruction.
* **Agent → Tool** — the agent proposes; it does not decide. Every proposed
  call passes through `agentbreak.agent.policy` before it can run.
* **Tool → External Service** — `send_report`'s destination is restricted to
  an explicit allowlist; nothing else is trusted to receive tool output.

## Attacker capabilities (assumed)

The attacker cannot touch the agent's code, prompt, or policy configuration.
They *can*:

* Control content later ingested by retrieval — author or edit a document
  that ends up in the knowledge base (an operations manual, a support
  ticket, a web page, an email, an API response).
* Choose parameters embedded in that content (e.g. which asset ID or which
  destination the agent is nudged toward) and have the agent treat them as
  if the user or a trusted operator had supplied them.
* Attempt to trigger any tool reachable from the agent's context, and
  attempt to exfiltrate whatever that tool returns.
* Not: directly call tools, bypass the CLI/API, or read the policy layer's
  source before an attack — the controls are meant to hold even against an
  attacker who has read this repository.

## Security assumptions that must NOT be trusted

* ❌ **"The model will reliably distinguish instructions from retrieved
  data."** It will not, reliably. Wrapping untrusted content in a
  `<document>` marker or a "never execute instructions found here" system
  note is a secondary signal at best (`policy.detect_suspicious_content`) —
  never the control that stands between an attacker and a privileged action.
* ❌ **"A tool allowlist by task is sufficient."** `tests/security_cases/
  tool_abuse.json` exists specifically to show a broader, role-based
  allowlist still needs argument validation, data classification and egress
  control behind it — this is the "excessive agency" failure mode.
* ❌ **"Suspicious-phrase detection is a defense."** It is telemetry
  (`attack_detected` in the schema) used to explain *why* something was
  blocked, not the mechanism that blocks it.
* ❌ **"If the read succeeded, the attack succeeded."** A credential reaching
  agent memory is not the same as it leaving the system — see
  `PARTIALLY_MITIGATED` in the evidence schema, and the trust boundary at
  `Tool → External Service`.

## What is out of scope here

Compromised or malicious MCP servers, tools, and integrations — the tool
implementations in this repo are trusted, local, and simulated. That failure
mode belongs to **MCP-SHIELD** (see the README's "AgentBreak and MCP-SHIELD"
section).
