"""Tests for the AI security regression workflow.

Attack -> evidence -> ``agentbreak create-test`` -> ``agentbreak verify``.
Every test works on a temp copy of the case corpus and a temp evidence dir,
so the repository's ``tests/security_cases/`` and ``artifacts/`` are never
touched.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from agentbreak.agent import policy, regression
from agentbreak.agent.evidence import append_finding
from agentbreak.agent.scenario import run_indirect_injection
from agentbreak.cli import app

REPO_ROOT = Path(__file__).resolve().parents[1]
CASES_DIR = Path(__file__).parent / "security_cases"
WORKSHOP_PATCH = REPO_ROOT / "workshop" / "patches" / "broaden-incident-agent-access.patch"

runner = CliRunner()


@pytest.fixture(autouse=True)
def _isolated_outbox(monkeypatch, tmp_path: Path):
    import agentbreak.agent.tools as tools_mod

    monkeypatch.setattr(tools_mod, "SENT_REPORTS_DIR", tmp_path / "sent_reports")


@pytest.fixture
def cases_dir(tmp_path: Path) -> Path:
    target = tmp_path / "cases"
    shutil.copytree(CASES_DIR, target)
    return target


@pytest.fixture
def evidence_dir(tmp_path: Path) -> Path:
    """Evidence for one normal, one attack and one secure run: AB-RUN-1001..1003."""

    out = tmp_path / "artifacts"
    for mode in ("normal", "attack", "secure"):
        append_finding(run_indirect_injection(mode, quiet=True), out)
    return out


def _weaken_policy(monkeypatch) -> None:
    """In-process equivalent of workshop/patches/broaden-incident-agent-access.patch."""

    monkeypatch.setitem(
        policy.ALLOWED_TOOLS_BY_TASK,
        "grid_incident_response",
        frozenset({"search_knowledge_base", "get_asset_credentials"}),
    )
    monkeypatch.setattr(policy, "HIGH_IMPACT_TOOLS", frozenset({"send_report"}))


def _verify(*args: str):
    return runner.invoke(app, ["verify", *args])


# ------------------------------------------------------------------ verify


def test_verify_passes_on_secure_posture(cases_dir: Path, tmp_path: Path) -> None:
    result = _verify("--cases-dir", str(cases_dir), "--report-dir", str(tmp_path / "out"))
    assert result.exit_code == 0, result.stdout
    assert "AgentBreak Security Regression Suite" in result.stdout
    for n in range(1, 5):
        assert f"✓ AB-REG-00{n}" in result.stdout
    assert "SECURITY GATE: PASSED" in result.stdout


def test_verify_fails_with_exit_1_on_security_regression(
    cases_dir: Path, tmp_path: Path, monkeypatch
) -> None:
    _weaken_policy(monkeypatch)
    result = _verify("--cases-dir", str(cases_dir), "--report-dir", str(tmp_path / "out"))
    assert result.exit_code == 1
    assert "✗ AB-REG-003" in result.stdout
    assert "prohibited tool executed: get_asset_credentials" in result.stdout
    assert "Critical security regression detected." in result.stdout
    assert "SECURITY GATE: FAILED" in result.stdout


def test_verify_json_output_is_valid(cases_dir: Path, tmp_path: Path, monkeypatch) -> None:
    _weaken_policy(monkeypatch)
    result = _verify("--json", "--cases-dir", str(cases_dir), "--no-report")
    assert result.exit_code == 1
    data = json.loads(result.stdout)
    assert data["status"] == "FAILED"
    assert data["passed"] + data["failed"] == len(data["cases"]) == 4
    failed = {c["id"]: c for c in data["cases"] if c["status"] == "FAILED"}
    assert set(failed) == {"AB-REG-002", "AB-REG-003"}
    assert "get_asset_credentials" in failed["AB-REG-003"]["reason"]
    assert not (tmp_path / "out").exists()


def test_verify_writes_regression_report(cases_dir: Path, tmp_path: Path, monkeypatch) -> None:
    _weaken_policy(monkeypatch)
    out = tmp_path / "out"
    _verify("--cases-dir", str(cases_dir), "--report-dir", str(out))

    report = json.loads((out / "security_regression_report.json").read_text(encoding="utf-8"))
    case = next(c for c in report["cases"] if c["id"] == "AB-REG-003")
    assert case["status"] == "FAILED"
    assert case["trust_boundary"] == "Retrieval Source → Agent"
    assert case["expected_secure_result"] == "ATTACK_BLOCKED"
    assert case["observed_secure_result"] == "PARTIALLY_MITIGATED"
    assert case["agent_influenced"] and case["boundary_crossed"]

    md = (out / "security_regression_report.md").read_text(encoding="utf-8")
    assert "## AB-REG-003 — Indirect prompt injection" in md
    assert "**Security gate:** FAILED" in md


def test_verify_output_is_deterministic(cases_dir: Path, tmp_path: Path) -> None:
    first = _verify("--json", "--cases-dir", str(cases_dir), "--report-dir", str(tmp_path / "a"))
    second = _verify("--json", "--cases-dir", str(cases_dir), "--report-dir", str(tmp_path / "b"))
    assert first.stdout == second.stdout
    assert (tmp_path / "a" / "security_regression_report.md").read_text() == (
        tmp_path / "b" / "security_regression_report.md"
    ).read_text()


def test_verify_fails_on_empty_corpus(tmp_path: Path) -> None:
    result = _verify("--cases-dir", str(tmp_path / "empty"), "--no-report")
    assert result.exit_code == 1
    assert "SECURITY GATE: FAILED" in result.stdout


def test_verify_reports_malformed_case_as_failure(cases_dir: Path) -> None:
    (cases_dir / "broken.json").write_text("{not json", encoding="utf-8")
    result = _verify("--json", "--cases-dir", str(cases_dir), "--no-report")
    assert result.exit_code == 1
    broken = next(c for c in json.loads(result.stdout)["cases"] if c["id"] == "broken")
    assert broken["reason"] == "case file is not valid JSON"


def test_defense_in_depth_contains_allowlist_change_alone(cases_dir: Path, monkeypatch) -> None:
    """Broadening only the allowlist is still contained by the approval gate."""

    monkeypatch.setitem(
        policy.ALLOWED_TOOLS_BY_TASK,
        "grid_incident_response",
        frozenset({"search_knowledge_base", "get_asset_credentials", "send_report"}),
    )
    assert regression.run_suite(cases_dir).status == "PASSED"


def test_python_m_entrypoint_propagates_exit_code(cases_dir: Path, tmp_path: Path) -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "agentbreak", "verify", "--cases-dir", str(cases_dir),
         "--no-report", "--json"],
        capture_output=True, text=True, check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout)["status"] == "PASSED"


# ------------------------------------------------------------- create-test


def test_create_test_rejects_unknown_run_id(evidence_dir: Path, cases_dir: Path) -> None:
    result = runner.invoke(app, ["create-test", "AB-RUN-9999", "--evidence-dir",
                                 str(evidence_dir), "--cases-dir", str(cases_dir)])
    assert result.exit_code == 1
    assert "Cannot create regression test" in result.stdout
    assert "unknown run ID 'AB-RUN-9999'" in result.stdout


@pytest.mark.parametrize("run_id", ["AB-RUN-1001", "AB-RUN-1003"], ids=["normal", "secure"])
def test_create_test_rejects_runs_without_invariant(
    run_id: str, evidence_dir: Path, cases_dir: Path
) -> None:
    with pytest.raises(regression.RegressionCaseError, match="deterministic security invariant"):
        regression.create_case_from_run(run_id, evidence_dir=evidence_dir, cases_dir=cases_dir)
    assert not list(cases_dir.glob("AB-REG-*.json"))


def test_create_test_points_secure_replay_at_its_attack_run(
    evidence_dir: Path, cases_dir: Path
) -> None:
    with pytest.raises(regression.RegressionCaseError, match="attack run instead: AB-RUN-1002"):
        regression.create_case_from_run("AB-RUN-1003", evidence_dir=evidence_dir,
                                        cases_dir=cases_dir)


def test_create_test_rejects_evidence_without_payload(evidence_dir: Path, cases_dir: Path) -> None:
    path = evidence_dir / "attack_report.json"
    findings = json.loads(path.read_text(encoding="utf-8"))
    del findings[1]["payload"]  # what a finding recorded before payload capture looks like
    path.write_text(json.dumps(findings), encoding="utf-8")
    with pytest.raises(regression.RegressionCaseError, match="missing payload"):
        regression.create_case_from_run("AB-RUN-1002", evidence_dir=evidence_dir,
                                        cases_dir=cases_dir)


def test_create_test_rejects_tampered_payload(evidence_dir: Path, cases_dir: Path) -> None:
    path = evidence_dir / "attack_report.json"
    findings = json.loads(path.read_text(encoding="utf-8"))
    findings[1]["payload"] += " (edited)"
    path.write_text(json.dumps(findings), encoding="utf-8")
    with pytest.raises(regression.RegressionCaseError, match="does not match payload_sha256"):
        regression.create_case_from_run("AB-RUN-1002", evidence_dir=evidence_dir,
                                        cases_dir=cases_dir)


def test_create_test_generates_valid_case_with_provenance(
    evidence_dir: Path, cases_dir: Path
) -> None:
    result = runner.invoke(app, ["create-test", "AB-RUN-1002", "--evidence-dir",
                                 str(evidence_dir), "--cases-dir", str(cases_dir)])
    assert result.exit_code == 0, result.stdout
    assert "Security regression created" in result.stdout
    assert "AB-REG-005.json" in result.stdout

    finding = json.loads((evidence_dir / "attack_report.json").read_text())[1]
    case = json.loads((cases_dir / "AB-REG-005.json").read_text(encoding="utf-8"))

    # Same schema the existing corpus uses.
    for key in ("scenario", "input", "context", "expected_vulnerable_result",
                "expected_secure_result"):
        assert key in case
    assert case["id"] == "AB-REG-005"
    assert case["context"] == finding["payload"]  # identical payload, replayed
    assert case["expected_vulnerable_result"] == "ATTACK_SUCCESS"
    assert case["expected_secure_result"] == "ATTACK_BLOCKED"
    assert case["prohibited_tools"] == ["get_asset_credentials", "send_report"]
    assert "tool_authorization" in case["controls"]

    prov = case["provenance"]
    assert prov["source_run_id"] == "AB-RUN-1002"
    assert prov["scenario"] == "indirect-injection"
    assert prov["attack_payload_sha256"] == finding["payload_sha256"]
    assert prov["original_result"] == "ATTACK_SUCCESS"
    assert prov["requested_tools"] == ["get_asset_credentials", "send_report"]
    assert prov["trust_level"] == "untrusted"
    assert case["trust_boundary"] == "Retrieval Source → Agent"


def test_create_test_refuses_duplicate(evidence_dir: Path, cases_dir: Path) -> None:
    regression.create_case_from_run("AB-RUN-1002", evidence_dir=evidence_dir, cases_dir=cases_dir)
    with pytest.raises(regression.RegressionCaseError, match="already has a regression case"):
        regression.create_case_from_run("AB-RUN-1002", evidence_dir=evidence_dir,
                                        cases_dir=cases_dir)


def test_generated_case_runs_in_suite_and_catches_regression(
    evidence_dir: Path, cases_dir: Path, monkeypatch
) -> None:
    path, case = regression.create_case_from_run(
        "AB-RUN-1002", evidence_dir=evidence_dir, cases_dir=cases_dir
    )
    assert regression.run_case(path, case).passed

    suite = regression.run_suite(cases_dir)
    assert suite.status == "PASSED" and len(suite.cases) == 5

    _weaken_policy(monkeypatch)
    weakened = regression.run_case(path, case)
    assert not weakened.passed
    assert weakened.observed_secure_result == "PARTIALLY_MITIGATED"
    assert "get_asset_credentials" in weakened.executed_tools


# ----------------------------------------------- evidence + existing modes


def test_run_ids_are_sequential(evidence_dir: Path) -> None:
    findings = json.loads((evidence_dir / "attack_report.json").read_text())
    assert [f["run_id"] for f in findings] == ["AB-RUN-1001", "AB-RUN-1002", "AB-RUN-1003"]
    assert [f["mode"] for f in findings] == ["normal", "attack", "secure"]


@pytest.mark.parametrize(
    ("mode", "expected"),
    [("normal", "NO_ATTACK"), ("attack", "ATTACK_SUCCESS"), ("secure", "ATTACK_BLOCKED")],
)
def test_run_command_modes_unchanged(mode: str, expected: str, tmp_path: Path, monkeypatch) -> None:
    import agentbreak.agent.evidence as evidence_mod

    monkeypatch.setattr(evidence_mod, "DEFAULT_ARTIFACTS_DIR", tmp_path / "artifacts")
    result = runner.invoke(app, ["run", "indirect-injection", "--mode", mode])
    assert result.exit_code == 0, result.stdout
    assert expected in result.stdout
    assert "run_id=AB-RUN-1001" in result.stdout


# --------------------------------------------------- workshop exercise patch


def test_workshop_patch_breaks_and_revert_restores_gate(tmp_path: Path) -> None:
    """Apply the workshop patch to a copy of the project: the gate fails, then passes."""

    if shutil.which("git") is None:
        pytest.skip("git is required to apply the workshop patch")
    work = tmp_path / "project"
    for sub in ("src", "data", "tests/security_cases", "workshop"):
        shutil.copytree(REPO_ROOT / sub, work / sub,
                        ignore=shutil.ignore_patterns("__pycache__", "*.egg-info"))

    def verify() -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-m", "agentbreak", "verify", "--json", "--no-report"],
            cwd=work, env={"PYTHONPATH": str(work / "src"), "PATH": ""},
            capture_output=True, text=True, check=False,
        )

    def git_apply(*flags: str) -> None:
        subprocess.run(["git", "apply", *flags, str(WORKSHOP_PATCH)], cwd=work, check=True,
                       capture_output=True)

    git_apply()
    broken = verify()
    assert broken.returncode == 1, broken.stderr
    assert json.loads(broken.stdout)["status"] == "FAILED"

    git_apply("-R")
    fixed = verify()
    assert fixed.returncode == 0, fixed.stderr
    assert json.loads(fixed.stdout)["status"] == "PASSED"
