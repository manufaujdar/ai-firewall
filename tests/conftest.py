from pathlib import Path

import pytest

from ai_firewall.config import settings


@pytest.fixture(autouse=True)
def isolate_local_storage(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep all generated metadata stores inside each test's temporary directory."""

    monkeypatch.setattr(settings, "audit_path", tmp_path / "audit.jsonl")
    monkeypatch.setattr(settings, "database_path", tmp_path / "privacy.db")
