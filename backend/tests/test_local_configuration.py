from pathlib import Path

from app.config import ENV_FILE, PROJECT_ROOT, Settings


def test_configuration_paths_are_project_relative(monkeypatch, tmp_path: Path):
    monkeypatch.chdir(tmp_path)
    item = Settings(
        _env_file=None,
        environment="development",
        auth_required=False,
        allow_unauthenticated_localhost=True,
        database_path="data/test.db",
        workspace_root="workspace-test",
    )
    assert ENV_FILE == PROJECT_ROOT / ".env"
    assert item.database_path == (PROJECT_ROOT / "data/test.db").resolve()
    assert item.workspace_root == (PROJECT_ROOT / "workspace-test").resolve()


def test_local_ollama_does_not_require_external_provider_key():
    item = Settings(
        _env_file=None,
        environment="development",
        auth_required=False,
        allow_unauthenticated_localhost=True,
    )
    assert str(item.ollama_base_url).startswith("http://127.0.0.1:11434")
    assert item.api_token is None
