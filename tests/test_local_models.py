import hashlib
import socket
import time
from pathlib import Path

import pytest

from ai_firewall.privacy.models import (
    LocalModelRegistry,
    LocalModelSpec,
    ModelExecutionError,
    ModelManifest,
    ModelSpan,
    load_model_manifest,
)


class SyntheticSpanModel:
    def predict(self, text: str):
        return [ModelSpan(start=0, end=min(9, len(text)), entity_type="person", confidence=0.99)]


class MalformedSpanModel:
    def predict(self, text: str):
        return [{"start": 0, "end": len(text)}]


def _registry(tmp_path: Path, executor, *, timeout_ms: int = 100) -> LocalModelRegistry:
    artifact = tmp_path / "model.onnx"
    artifact.write_bytes(b"synthetic-offline-artifact")
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    spec = LocalModelSpec(
        id="synthetic_ner",
        runtime="onnx",
        artifact_path=artifact,
        sha256=digest,
        entity_types=frozenset({"person"}),
        confidence_threshold=0.9,
        timeout_ms=timeout_ms,
    )
    return LocalModelRegistry(ModelManifest(version=1, models=(spec,)), {spec.id: executor})


def test_empty_manifest_is_ready_without_downloading_models() -> None:
    manifest = load_model_manifest(Path("config/models.yaml"))
    registry = LocalModelRegistry(manifest)

    assert registry.ready() is True
    assert registry.model_ids == ()
    assert registry.topology() == []


@pytest.mark.asyncio
async def test_pinned_local_model_returns_block_findings(tmp_path: Path) -> None:
    findings = await _registry(tmp_path, SyntheticSpanModel()).inspect("Synthetic Person")

    assert len(findings) == 1
    assert findings[0].rule_id == "model_synthetic_ner_person"
    assert findings[0].action.value == "block"


@pytest.mark.asyncio
async def test_malformed_model_spans_fail_closed(tmp_path: Path) -> None:
    with pytest.raises(ModelExecutionError, match="invalid structured span"):
        await _registry(tmp_path, MalformedSpanModel()).inspect("Synthetic Person")


@pytest.mark.asyncio
async def test_digest_mismatch_fails_closed(tmp_path: Path) -> None:
    registry = _registry(tmp_path, SyntheticSpanModel())
    registry.manifest.models[0].artifact_path.write_bytes(b"changed-artifact")

    assert registry.ready() is False
    with pytest.raises(ModelExecutionError, match="artifact is unavailable"):
        await registry.inspect("Synthetic Person")


def test_manifest_rejects_runtime_download_or_absolute_path(tmp_path: Path) -> None:
    path = tmp_path / "models.yaml"
    path.write_text(
        """version: 1
models:
  - id: unsafe_model
    runtime: remote
    artifact_path: /tmp/model.onnx
    sha256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    entity_types: [person]
    confidence_threshold: 0.9
    timeout_ms: 100
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError):
        load_model_manifest(path)


def test_manifest_rejects_duplicate_keys_and_boolean_version(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate.yaml"
    duplicate.write_text("version: 1\nversion: 1\nmodels: []\n", encoding="utf-8")
    boolean = tmp_path / "boolean.yaml"
    boolean.write_text("version: true\nmodels: []\n", encoding="utf-8")

    with pytest.raises(ValueError):
        load_model_manifest(duplicate)
    with pytest.raises(ValueError, match="unsupported model manifest version"):
        load_model_manifest(boolean)


@pytest.mark.asyncio
async def test_model_timeout_is_one_deadline_for_all_segments(tmp_path: Path) -> None:
    class SlowLocalModel:
        def predict(self, text: str):
            time.sleep(0.06)
            return []

    registry = _registry(tmp_path, SlowLocalModel(), timeout_ms=100)

    with pytest.raises(ModelExecutionError, match="inference failed"):
        await registry.inspect({"first": "synthetic-a", "second": "synthetic-b"})


@pytest.mark.asyncio
async def test_model_input_budget_is_bounded(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("ai_firewall.privacy.models.MAX_MODEL_SEGMENTS", 1)
    registry = _registry(tmp_path, SyntheticSpanModel())

    with pytest.raises(ModelExecutionError, match="input budget exceeded"):
        await registry.inspect({"first": "synthetic-a", "second": "synthetic-b"})


@pytest.mark.asyncio
async def test_local_model_inspection_does_not_open_network_socket(
    tmp_path: Path, monkeypatch
) -> None:
    network_attempted = False

    def deny_network(self, address) -> None:
        nonlocal network_attempted
        network_attempted = True
        raise AssertionError("local model attempted network access")

    monkeypatch.setattr(socket.socket, "connect", deny_network)

    findings = await _registry(tmp_path, SyntheticSpanModel()).inspect("Synthetic Person")

    assert findings
    assert network_attempted is False
