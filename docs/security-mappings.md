# Security Mappings

AgentBreak scenario IDs are internal to this repository. OWASP and MITRE ATLAS
identifiers are external standards, kept in their own columns so the three
never get conflated with each other.

## Flagship scenario: `indirect-injection`

| AgentBreak scenario ID | OWASP Top 10 for LLM Applications v1.1 | OWASP Agentic-application concept | MITRE ATLAS |
|---|---|---|---|
| `indirect-injection` | **LLM01 — Prompt Injection** (verified: `src/agentbreak/owasp.py`) | Prompt Injection / Context Poisoning | **AML.T0051 — LLM Prompt Injection**, sub-technique **AML.T0051.001 — Indirect** |
| `indirect-injection` | **LLM08 — Excessive Agency** | Excessive Agency | *(no ATLAS technique cited here — see note below)* |
| `indirect-injection` (`tool_abuse` regression case) | **LLM08 — Excessive Agency** | Agent Goal Hijack / Tool Misuse & Exploitation | *(uncited — see note)* |
| `indirect-injection` (successful `attack` path) | **LLM06 — Sensitive Information Disclosure** | Data Exfiltration | *(uncited — see note)* |
| `indirect-injection` (`send_report` reaching a privileged/untrusted destination in the vulnerable path) | **LLM07 — Insecure Plugin Design** (nearest existing category for unchecked tool/plugin execution) | Tool Misuse & Exploitation | *(uncited — see note)* |

The four labels **Agent Goal Hijack**, **Tool Misuse & Exploitation**,
**Memory & Context Poisoning**, **Excessive Agency**, **Prompt Injection**,
and **Data Exfiltration** are the concept names given in AgentBreak's own
brief for an emerging "OWASP Top 10 for Agentic Applications" — at the time
of writing there is no single, versioned, numbered OWASP list for agentic
applications that this repo can cite an ID from the way it cites
`owasp.py`'s LLM01–LLM10. Treat the middle column as **descriptive concept
labels**, not a numbered external standard, until OWASP publishes one and
this table can be updated with real IDs.

## Broader OWASP-10-for-LLM lab (`agentbreak.cli scan`)

This repo already implements one probe per official category — see
`src/agentbreak/owasp.py` and `src/agentbreak/probes.py` for the
authoritative code-level mapping (LLM01 through LLM10). That table is not
duplicated here; read it directly from source rather than trusting a copy
that can drift.

## A note on MITRE ATLAS

**AML.T0051 (LLM Prompt Injection)** and its indirect sub-technique
**AML.T0051.001** are well-established, widely cited ATLAS entries and are
the only IDs in this document cited with confidence. ATLAS's tactic/technique
numbering for tool misuse, excessive agency, and data exfiltration via an LLM
application changes as the matrix evolves, and guessing an ID here would
violate this project's own "do not invent mappings" rule. Before citing an
ATLAS ID beyond AML.T0051 in a report or talk, check the current matrix at
MITRE ATLAS directly and update this table with the confirmed ID — do not
carry forward a placeholder.

## Design note

Only LLM01, LLM06, LLM07 and LLM08 are mapped to the flagship scenario
because those are the categories it actually exercises end to end (injection
→ excessive agency → attempted disclosure via an unchecked tool). Mapping
every OWASP LLM Top 10 category to a single scenario would be exactly the
kind of invented breadth this document is trying to avoid — the other six
categories are covered by the separate OWASP-10 lab, not by this scenario.
