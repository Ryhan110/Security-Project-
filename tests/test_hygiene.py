"""Project hygiene - no secret can be committed, and the app fails closed."""
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def test_gitignore_covers_secrets_and_runtime_files():
    lines = (ROOT / ".gitignore").read_text().split()
    for pattern in (".env", "*.db", "*.sqlite", "keys/", "*.pem", "anchors/", "__pycache__/",
                    ".venv/", ".pytest_cache/", "logs/", "*.log"):
        assert pattern in lines, f"{pattern} missing from .gitignore"


def test_env_example_contains_only_placeholders():
    for line in (ROOT / ".env.example").read_text().splitlines():
        if re.match(r"RG_.*(KEY|SECRET|PASSWORD)=", line) and "SIGNING" not in line:
            assert line.split("=", 1)[1].startswith("REPLACE_ME"), line


def test_no_secret_files_are_tracked_by_git():
    tracked = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True).stdout.split()
    bad = [name for name in tracked
           if name == ".env" or name.endswith((".db", ".sqlite", ".pem", ".key", ".jsonl", ".log"))]
    assert bad == []


def test_no_hard_coded_keys_in_source():
    suspicious = re.compile(r"""["'][0-9a-f]{64}["']|gAAAA[A-Za-z0-9_-]{20,}|BEGIN (?:PRIVATE|OPENSSH)""")
    hits = []
    for folder in ("rationguard", "attacks", "scripts"):
        for path in (ROOT / folder).rglob("*.py"):
            if suspicious.search(path.read_text()):
                hits.append(str(path))
    assert hits == []


def test_app_refuses_to_start_with_placeholder_keys(monkeypatch):
    from rationguard.config import ConfigError, get_settings
    monkeypatch.setenv("RG_TX_HMAC_KEY", "REPLACE_ME_run_setup_keys")
    get_settings.cache_clear()
    with pytest.raises(ConfigError):
        get_settings()
    monkeypatch.undo()
    get_settings.cache_clear()


def test_app_refuses_short_keys(monkeypatch):
    from rationguard.config import ConfigError, get_settings
    monkeypatch.setenv("RG_AUDIT_HMAC_KEY", "abcd")
    get_settings.cache_clear()
    with pytest.raises(ConfigError):
        get_settings()
    monkeypatch.undo()
    get_settings.cache_clear()


def test_three_hmac_keys_are_different():
    from rationguard.config import get_settings
    settings = get_settings()
    assert len({settings.tx_hmac_key, settings.audit_hmac_key, settings.record_hmac_key}) == 3


def test_hosted_entry_point_boots_on_an_empty_disk(tmp_path, monkeypatch):
    """The Vercel entry point must create and seed its own database, with the
    signing keys coming from environment variables instead of files."""
    import base64
    import importlib.util
    import os
    from pathlib import Path as P
    from fastapi.testclient import TestClient
    from rationguard import db
    from rationguard.config import get_settings
    for which in ("PRIVATE", "PUBLIC"):
        pem = P(os.environ[f"RG_SIGNING_{which}_KEY"]).read_bytes()
        monkeypatch.setenv(f"RG_SIGNING_{which}_KEY_B64", base64.b64encode(pem).decode())
        monkeypatch.setenv(f"RG_SIGNING_{which}_KEY", str(tmp_path / "missing.pem"))
    monkeypatch.setenv("RG_DB_PATH", str(tmp_path / "hosted.db"))
    monkeypatch.setenv("RG_ANCHOR_FILE", str(tmp_path / "hosted.jsonl"))
    get_settings.cache_clear()
    db.reset_engine()
    spec = importlib.util.spec_from_file_location("vercel_entry", ROOT / "vercel_entry.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    browser = TestClient(module.app, follow_redirects=False)
    assert browser.get("/login").status_code == 200
    from conftest import login, verify
    assert login(browser, "auditor1").status_code == 303
    assert verify().ok
    db.reset_engine()
    monkeypatch.undo()
    get_settings.cache_clear()


def test_pyproject_and_requirements_list_the_same_runtime_packages():
    import tomllib
    hosted = set(tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["dependencies"])
    local = set((ROOT / "requirements.txt").read_text().split())
    assert hosted <= local, f"in pyproject.toml but not requirements.txt: {hosted - local}"
    dev_only = {line.split(">=")[0] for line in local - hosted}
    assert dev_only == {"pytest", "httpx", "uvicorn"}
