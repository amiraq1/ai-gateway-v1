from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

DEV_PACKAGES = ["pytest", "pluggy", "iniconfig", "packaging", "pygments"]
CORE_PROD_PACKAGES = ["fastapi", "uvicorn", "httpx", "pydantic", "pyyaml"]


def test_production_requirements_have_no_dev_dependencies():
    req_in = (REPO_ROOT / "requirements.in").read_text(encoding="utf-8")
    for pkg in DEV_PACKAGES:
        assert pkg not in req_in.lower(), f"{pkg} must not be in production requirements.in"

    req_lock = (REPO_ROOT / "requirements.lock").read_text(encoding="utf-8")
    for pkg in DEV_PACKAGES:
        assert f"{pkg}==" not in req_lock.lower(), f"{pkg} must not be in production requirements.lock"


def test_production_requirements_retain_core_dependencies():
    req_lock = (REPO_ROOT / "requirements.lock").read_text(encoding="utf-8")
    for pkg in CORE_PROD_PACKAGES:
        assert f"{pkg}==" in req_lock.lower(), f"{pkg} must be in production requirements.lock"
    # Ensure every entry in requirements.lock has at least one hash
    assert "--hash=sha256:" in req_lock


def test_dev_requirements_files_exist_and_contain_pytest():
    dev_in = REPO_ROOT / "requirements-dev.in"
    assert dev_in.exists(), "requirements-dev.in must exist"
    dev_in_content = dev_in.read_text(encoding="utf-8")
    assert "pytest" in dev_in_content

    dev_lock = REPO_ROOT / "requirements-dev.lock"
    assert dev_lock.exists(), "requirements-dev.lock must exist"
    dev_lock_content = dev_lock.read_text(encoding="utf-8")
    assert "pytest==" in dev_lock_content
    for pkg in DEV_PACKAGES:
        assert f"{pkg}==" in dev_lock_content.lower()
