from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

def test_dockerignore_ignores_config_yaml():
    dockerignore_path = REPO_ROOT / ".dockerignore"
    assert dockerignore_path.exists()
    content = dockerignore_path.read_text(encoding="utf-8").splitlines()
    # Check that config.yaml or *.yaml is ignored in .dockerignore
    ignored = any(
        line.strip() in {"config/config.yaml", "config/*.yaml", "*.yaml", "config/*.yml", "*.yml"}
        for line in content
    )
    assert ignored, "config/config.yaml must be ignored in .dockerignore"
