from __future__ import annotations

from pathlib import Path
import yaml


REPO_ROOT = Path(__file__).resolve().parent.parent


def test_linux_ci_workflow_exists_and_runs_security_and_coverage_checks():
    ci_path = REPO_ROOT / ".github" / "workflows" / "ci.yml"
    assert ci_path.exists(), ".github/workflows/ci.yml must exist"
    workflow = yaml.safe_load(ci_path.read_text(encoding="utf-8"))
    assert "jobs" in workflow and len(workflow["jobs"]) >= 1

    ci_text = ci_path.read_text(encoding="utf-8")
    assert "ubuntu-latest" in ci_text
    assert "--require-hashes -r requirements.lock" in ci_text
    assert "pytest" in ci_text and "--cov" in ci_text
    assert "bandit" in ci_text
    assert "flake8" in ci_text
