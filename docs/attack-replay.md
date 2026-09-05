# Attack Replay

Attack replay is the core methodology AgentBreak uses to prove a mitigation
actually works, instead of asserting it. The rule: **never modify the
payload between the vulnerable run and the hardened run.** If you change the
attack to make it pass, you've tested nothing.

## Why it matters

* **Reproducibility** — a security finding that can't be re-triggered on
  demand is an anecdote, not evidence.
* **Regression testing** — `tests/test_scenario.py` and
  `tests/test_security_cases.py` replay the same payloads on every test run;
  a future change that silently reopens the hole fails CI, not a customer.
* **Control verification** — replaying proves the *control* changed
  (`authorize_tool`, `check_egress`, ...), not that the attacker gave up or
  the payload got weaker.
* **Security evaluation** — a report that says "blocked" is only credible if
  the exact input that used to succeed is what was retested.
* **Purple Team workflows** — this is the same loop a red team / blue team
  pairing runs by hand: reproduce, harden, replay, compare. AgentBreak just
  automates it locally.

## The six steps

1. **Establish expected behavior.**
   Run the scenario against benign context first:
   `python -m agentbreak.cli normal` (or `python run_demo.py normal`). This
   is the baseline the mitigation must not break.

2. **Execute adversarial input.**
   Run the scenario against the poisoned context with the policy layer off:
   `python -m agentbreak.cli attack`. The indirect prompt injection succeeds;
   `get_asset_credentials` and `send_report` execute unconditionally.

3. **Capture evidence.**
   Every run appends a finding to `artifacts/attack_report.json` /
   `attack_report.md` via `agentbreak.agent.evidence.append_finding` — the
   payload's sha256, the tools requested, the final status
   (`ATTACK_SUCCESS`).

4. **Introduce a security control.**
   Nothing to "introduce" here on stage — the policy layer
   (`agentbreak.agent.policy`) already exists; `secure` mode is what turns it
   on. In your own system, this is the step where you'd actually add
   `authorize_tool` / `validate_arguments` / `check_egress` in front of your
   tool-execution path.

5. **Replay exactly the same attack.**
   `python -m agentbreak.cli secure`. This calls the identical
   `run_indirect_injection` pipeline against the identical poisoned
   knowledge base and the identical question — `tests/test_scenario.py::
   test_secure_mode_blocks_the_identical_payload` asserts the retrieved
   document and the agent's proposed tool calls are byte-identical to the
   `attack` run before checking the outcome.

6. **Compare results.**
   `ATTACK_SUCCESS` → `ATTACK_BLOCKED` (or `PARTIALLY_MITIGATED`, see
   `tests/security_cases/tool_abuse.json`), with the reason logged per
   control (`policy_reason`, `security_control` in the telemetry schema).
   That comparison — not a subjective "looks fixed to me" — is the
   deliverable.

## Doing this against your own system

Swap step 4 for whatever change you actually made (a new allowlist entry, an
argument validator, an egress rule), keep steps 1/2/3/5/6 identical, and keep
the same payload on both sides of the comparison. If you can't replay the
exact same input, you don't have a verified mitigation yet.
