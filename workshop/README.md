# AgentBreak Workshop: From AI Attack to CI Security Gate

> **Every successful AI attack should become a security test.**

In this 120-minute hands-on workshop you break a tool-using AI agent, capture
what happened as evidence, turn that evidence into a security regression test,
and wire the test into CI. That way a later change that reopens the hole fails
the build instead of reaching production.

```
NORMAL → ATTACK → OBSERVE → CREATE SECURITY TEST → FIX → RETEST → CI SECURITY GATE → SHIP
```

Everything runs locally and deterministically. There is no LLM API, no
network access, and no real credentials. The "agent" is a reproducible
stand-in, the knowledge base is a JSON file, and `send_report` writes to a
local folder.

## Setup (5 min)

```bash
git clone https://github.com/urcuqui/AgentBreak.git
cd AgentBreak
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
agentbreak verify          # should end with: SECURITY GATE: PASSED
```

`agentbreak <cmd>` and `python -m agentbreak <cmd>` are interchangeable.

## Agenda

| Time   | Module                                         | You will…                                                        |
|--------|------------------------------------------------|------------------------------------------------------------------|
| 0:00   | Setup + intro                                  | install, run the gate once, meet the scenario                    |
| 0:15   | [01 — Normal](01-normal.md)                    | see what correct behavior and an engaged policy layer look like  |
| 0:30   | [02 — Attack & observe](02-attack.md)          | poison the agent's context, read the evidence, replay it secured |
| 0:55   | [03 — Create a security test](03-create-test.md) | ship an "innocent" change, turn the attack into a test, see it fail |
| 1:20   | [04 — Fix & retest](04-fix.md)                 | understand each policy control, fix the change, get back to green |
| 1:40   | [05 — CI security gate](05-ci.md)              | watch GitHub Actions block the same regression in a pull request |
| 1:55   | Wrap-up                                        | Attack → Evidence → Regression Test → CI Gate                     |

## The scenario in one picture

```
            UNTRUSTED CONTEXT   (poisoned knowledge-base document)
                    │
                    ▼
                  AGENT          follows instructions it should have treated as data
                    │
                    ▼
             PROPOSED ACTION     get_asset_credentials, send_report
                    │
                    ▼
              POLICY LAYER       deterministic controls, outside the model
           ┌────────┴────────┐
           ▼                 ▼
         ALLOW              BLOCK
           │
           ▼
        EVIDENCE           artifacts/attack_report.{json,md}   (run_id=AB-RUN-…)
           │
           ▼
    SECURITY REGRESSION    tests/security_cases/AB-REG-*.json  (agentbreak create-test)
           │
           ▼
        CI/CD GATE         agentbreak verify  (.github/workflows/ai-security.yml)
           │
     ┌─────┴─────┐
     ▼           ▼
    PASS        FAIL
     │           │
    SHIP       BLOCK
```

## Three ideas to take home

1. **Influence ≠ impact.** An agent that *asks* for a credential has been
   influenced. Only an agent whose request *succeeds* has crossed a security
   boundary. AgentBreak reports these separately.
2. **Controls live outside the model.** No module in this workshop fixes the
   attack with a longer system prompt. The policy layer
   (`src/agentbreak/agent/policy.py`) decides what actually happens.
3. **Same attack, different posture.** Each retest replays the byte-identical
   payload (checked by its sha256). If the payload changes, the retest proves
   nothing about the control.

## Facilitator notes

- The intentionally vulnerable change lives in
  [`patches/broaden-incident-agent-access.patch`](patches/broaden-incident-agent-access.patch).
  It is applied with `git apply` and reverted with `git apply -R`. The default
  configuration is never modified permanently.
- `tests/test_regression.py::test_workshop_patch_breaks_and_revert_restores_gate`
  checks that the patch still applies, fails the gate, and passes again after
  revert, so the exercise cannot silently rot.
- Run IDs (`AB-RUN-1001`, …) are sequential per checkout. Learners will see
  different numbers if they ran the scenario before. Use the ID printed by
  *their* attack run.
- To reset a learner's machine: `git checkout -- src tests && git clean -n tests/security_cases`
  (review the list, then `-f`), and `rm artifacts/*.json artifacts/*.md`.
