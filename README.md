# Hacking AI Agents with Python

> This project is intentionally vulnerable and was created for educational and
> defensive security research. It does not connect to external systems or use
> real credentials.

A 7–8 minute conference demo that shows how a vulnerable AI agent can be
manipulated through **indirect prompt injection** inside a document retrieved
by a RAG pipeline, and how the *same* attack is stopped by deterministic
Python controls.

## Educational objective

Make it concrete, in front of a live audience, that:

1. Indirect prompt injection is a real failure mode of agentic systems.
2. Treating retrieved content as trusted instructions is the root cause.
3. The mitigation is not "ask the model nicely" — it is deterministic Python:
   tool allowlists, argument validation, egress control, separation of
   instructions from untrusted context, and structured audit logging.

## Architecture

```
                 +---------------------------+
   user --->     |   UserRequest             |
                 |   question + task         |
                 +-------------+-------------+
                               |
                               v
                 +---------------------------+
                 |   RAG (local, keyword)    |
                 |   trust_level=untrusted   |
                 +-------------+-------------+
                               |
                               v
                 +---------------------------+
                 |   Simulated agent brain   |   (deterministic LLM stand-in)
                 +-------------+-------------+
                               |
                       proposed ToolCall(s)
                               |
       VULNERABLE PATH         |        SECURE PATH
         no checks             v          policy layer
                 +---------------------------+
                 | authorize_tool            |
                 | validate_arguments        |
                 | check_egress              |
                 +-------------+-------------+
                               |
                               v
                 +---------------------------+
                 | Tool runtime (local only) |
                 +---------------------------+
```

## Project layout

```
hacking-ai-agents-demo/
├── README.md
├── pyproject.toml
├── requirements.txt
├── data/
│   ├── clean_knowledge_base.json
│   ├── poisoned_knowledge_base.json
│   └── customers.json
├── src/hacking_ai_agents/
│   ├── cli.py
│   ├── models.py
│   ├── rag.py
│   ├── tools.py
│   ├── vulnerable_agent.py
│   ├── secure_agent.py
│   ├── policies.py
│   ├── security.py
│   └── logging_utils.py
├── tests/
└── scripts/
    ├── run_demo.sh
    └── run_demo.ps1
```

## Installation

Requires Python 3.11+. No network access needed at runtime.

```bash
cd hacking-ai-agents-demo
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\Activate.ps1
pip install -e .
```

## Commands

```bash
python -m hacking_ai_agents.cli normal
python -m hacking_ai_agents.cli attack
python -m hacking_ai_agents.cli secure
python -m hacking_ai_agents.cli full-demo
python -m hacking_ai_agents.cli full-demo --no-pause   # automatic
```

Common flags: `--verbose`, `--no-color`, `--no-pause` (only on `full-demo`).

Convenience launchers:

```bash
./scripts/run_demo.sh                 # macOS/Linux
.\scripts\run_demo.ps1                # Windows
```

## Example output (abridged)

`attack`:

```
[1] User question received
[2] Retrieving knowledge from poisoned KB
[3] Retrieved untrusted document
[4] Agent selected tool: get_customer_record
[5] Agent selected tool: send_report
[X] DATA EXFILTRATION SIMULATED
```

`secure`:

```
[1] User question received
[2] Retrieving knowledge from poisoned KB
[3] [!] Suspicious instructions detected in untrusted context
[4] Requested tool: get_customer_record
[5] Authorization policy evaluated
[6] [X] BLOCKED: Tool 'get_customer_record' is not allowed for task 'refund_policy'.
[7] No sensitive data was accessed
[8] No report was sent
[OK] ATTACK BLOCKED
```

## The attack

The poisoned knowledge base contains a legitimate refund policy followed by a
forged "IMPORTANT SYSTEM UPDATE" block that instructs the agent to fetch a
customer record and exfiltrate its `api_key` via `send_report`.

The vulnerable agent mixes the **system prompt**, the **user question** and
the **retrieved content** without a trust boundary. The simulated LLM (whose
behavior is deterministic in this repo precisely so the demo never misfires)
follows those embedded instructions.

## Root cause

> Retrieved content was treated as trusted instructions.

There is no per-task allowlist, no validation of tool arguments, no egress
control, and no separation between system instructions and untrusted context.

## Mitigations implemented in the secure variant

1. **Tool allowlist by task** (`policies.py`) — `refund_policy` is only
   allowed to call `search_knowledge_base`.
2. **Policy enforcement** before every tool call (`security.authorize_tool`).
3. **Recursive argument validation** rejects sensitive keys like `api_key`,
   `token`, `password`, `secret`, `credential`, ... at any depth.
4. **Egress control** for `send_report` blocks both sensitive keys and
   secret-looking values.
5. **Trust separation** in the prompt: retrieved content is wrapped in an
   `UNTRUSTED RETRIEVED CONTENT` block. *This is a secondary control only.*
6. **Suspicious-content detection** flags phrases such as
   `ignore previous instructions` as a risk *signal*, not a guarantee.
7. **Structured, redacted audit log** records every decision with
   policy name, status, reason, and risk level.

## Limitations

* The suspicious-content detector is intentionally simple and explainable.
  Treat it as telemetry; it must not be the only line of defense.
* The "LLM" is simulated so the demo is deterministic on a conference stage.
  In a real system you would gate a real model's tool calls with the same
  Python controls.
* Trust separation in the prompt cannot stop a model that has already been
  trained or tuned to ignore such markers; only the deterministic policy
  layer can.

## Suggested 7–8 minute script

* **0:00–1:00** Present the agent and its four tools. Show the
  `ALLOWED_TOOLS_BY_TASK` table.
* **1:00–2:00** Run `normal`. Question answered, no sensitive tools used.
* **2:00–3:00** Open `data/poisoned_knowledge_base.json`. Show the injected
  "IMPORTANT SYSTEM UPDATE" block alongside a legitimate refund policy.
* **3:00–5:00** Run `attack`. Walk through events [1]–[6] and the red
  "DATA EXFILTRATION SIMULATED" panel.
* **5:00–6:00** Explain the root cause: retrieved content was treated as
  trusted instructions, no per-task allowlist, no egress control.
* **6:00–7:30** Run `secure`. Same question, same poisoned KB. Walk through
  the policy decisions and the green "ATTACK BLOCKED" panel.
* **7:30–8:00** Close with: *"The model may choose the action, but Python
  must decide whether that action is allowed."*

## Troubleshooting

* `ModuleNotFoundError: hacking_ai_agents` — run `pip install -e .` from
  `hacking-ai-agents-demo/`.
* Colors not rendering — use a modern terminal (Windows Terminal, iTerm2,
  GNOME Terminal). Or pass `--no-color`.
* Tests fail with `ImportError` — make sure you are on Python 3.11+ and that
  `pyproject.toml`'s `pythonpath = ["src"]` is being read (run `pytest` from
  the project root).
* `scripts/run_demo.sh` not executable — `chmod +x scripts/run_demo.sh`.

## Run the tests

```bash
pip install pytest
pytest
```

## Ethical notice

This project is intentionally vulnerable and was created for educational and
defensive security research. It does not connect to external systems or use
real credentials. Do not adapt the vulnerable variant for production. Use the
secure variant — and the controls it demonstrates — as a starting point for
your own agentic systems.
