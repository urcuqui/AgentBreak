#!/usr/bin/env python3
"""Conference-friendly entry point for the flagship scenario.

    python run_demo.py normal
    python run_demo.py attack
    python run_demo.py secure

Equivalent to ``python -m agentbreak.cli <mode>``; this just saves typing the
module path on stage.
"""

from __future__ import annotations

import sys

from agentbreak.agent.evidence import append_finding
from agentbreak.agent.scenario import run_indirect_injection

MODES = ("normal", "attack", "secure")


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if len(argv) != 1 or argv[0] not in MODES:
        print(f"usage: python run_demo.py {{{'|'.join(MODES)}}}")
        return 2
    run = run_indirect_injection(argv[0])  # type: ignore[arg-type]
    append_finding(run)
    return 0


if __name__ == "__main__":
    sys.exit(main())
