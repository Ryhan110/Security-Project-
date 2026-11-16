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
