from __future__ import annotations

import asyncio
import hashlib
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

import yaml
from yaml.nodes import MappingNode

from ai_firewall.models import Action, Finding

MODEL_ID_PATTERN = re.compile(r"[a-z][a-z0-9_-]{0,63}\Z")
DIGEST_PATTERN = re.compile(r"[a-f0-9]{64}\Z")
SUPPORTED_MODEL_MANIFEST_VERSION = 1
SUPPORTED_RUNTIMES = frozenset({"onnx"})
ENTITY_TYPE_PATTERN = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
MAX_MODEL_SEGMENTS = 4096
MAX_MODEL_CHARACTERS = 1_000_000


class ModelManifestError(ValueError):
    """Raised when local model configuration is unsafe or malformed."""


class ModelExecutionError(RuntimeError):
    """Raised when a configured mandatory local model cannot produce safe spans."""


class _DuplicateModelKeyError(yaml.YAMLError):
    pass


class _UniqueModelLoader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(
    loader: _UniqueModelLoader, node: MappingNode, deep: bool = False
) -> dict[Any, Any]:
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise _DuplicateModelKeyError("duplicate model manifest key")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueModelLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


@dataclass(frozen=True, slots=True)
class LocalModelSpec:
    id: str
    runtime: str
    artifact_path: Path
    sha256: str
    entity_types: frozenset[str]
    confidence_threshold: float
    timeout_ms: int


@dataclass(frozen=True, slots=True)
class ModelManifest:
    version: int
    models: tuple[LocalModelSpec, ...]


@dataclass(frozen=True, slots=True)
class ModelSpan:
    start: int
    end: int
    entity_type: str
    confidence: float


class LocalTextModel(Protocol):
    """Offline model contract. Implementations return spans only and never rewritten text."""

    def predict(self, text: str) -> Sequence[ModelSpan]: ...


def load_model_manifest(path: Path) -> ModelManifest:
    try:
        raw = yaml.load(path.read_text(encoding="utf-8"), Loader=_UniqueModelLoader)
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise ModelManifestError("unable to load local model manifest") from exc
    if not isinstance(raw, dict) or set(raw) != {"version", "models"}:
        raise ModelManifestError("model manifest must contain only version and models")
    if (
        isinstance(raw["version"], bool)
        or not isinstance(raw["version"], int)
        or raw["version"] != SUPPORTED_MODEL_MANIFEST_VERSION
    ):
        raise ModelManifestError("unsupported model manifest version")
    if not isinstance(raw["models"], list):
        raise ModelManifestError("models must be a list")
    specs = tuple(_parse_spec(item, index, path.parent) for index, item in enumerate(raw["models"]))
    if len({spec.id for spec in specs}) != len(specs):
        raise ModelManifestError("model ids must be unique")
    return ModelManifest(version=raw["version"], models=specs)


def _parse_spec(value: Any, index: int, base_path: Path) -> LocalModelSpec:
    required = {
        "id",
        "runtime",
        "artifact_path",
        "sha256",
        "entity_types",
        "confidence_threshold",
        "timeout_ms",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise ModelManifestError(f"models[{index}] has an invalid schema")
    model_id = value["id"]
    if not isinstance(model_id, str) or MODEL_ID_PATTERN.fullmatch(model_id) is None:
        raise ModelManifestError(f"models[{index}].id is invalid")
    runtime = value["runtime"]
    if runtime not in SUPPORTED_RUNTIMES:
        raise ModelManifestError(f"models[{index}].runtime is unsupported")
    raw_path = value["artifact_path"]
    if not isinstance(raw_path, str) or not raw_path or Path(raw_path).is_absolute():
        raise ModelManifestError(f"models[{index}].artifact_path must be relative")
    artifact_path = (base_path / raw_path).resolve()
    if base_path.resolve() not in artifact_path.parents:
        raise ModelManifestError(f"models[{index}].artifact_path escapes its directory")
    digest = value["sha256"]
    if not isinstance(digest, str) or DIGEST_PATTERN.fullmatch(digest) is None:
        raise ModelManifestError(f"models[{index}].sha256 is invalid")
    entity_types = value["entity_types"]
    if (
        not isinstance(entity_types, list)
        or not entity_types
        or any(
            not isinstance(item, str) or ENTITY_TYPE_PATTERN.fullmatch(item) is None
            for item in entity_types
        )
    ):
        raise ModelManifestError(f"models[{index}].entity_types is invalid")
    threshold = value["confidence_threshold"]
    if isinstance(threshold, bool) or not isinstance(threshold, (int, float)) or not 0 < threshold <= 1:
        raise ModelManifestError(f"models[{index}].confidence_threshold is invalid")
    timeout_ms = value["timeout_ms"]
    if isinstance(timeout_ms, bool) or not isinstance(timeout_ms, int) or not 1 <= timeout_ms <= 30_000:
        raise ModelManifestError(f"models[{index}].timeout_ms is invalid")
    return LocalModelSpec(
        id=model_id,
        runtime=runtime,
        artifact_path=artifact_path,
        sha256=digest,
        entity_types=frozenset(entity_types),
        confidence_threshold=float(threshold),
        timeout_ms=timeout_ms,
    )


class LocalModelRegistry:
    """Pinned offline local-model registry with fail-closed structured span validation."""

    def __init__(
        self,
        manifest: ModelManifest,
        executors: Mapping[str, LocalTextModel] | None = None,
    ) -> None:
        self.manifest = manifest
        self.executors = dict(executors or {})

    @property
    def model_ids(self) -> tuple[str, ...]:
        return tuple(spec.id for spec in self.manifest.models)

    def ready(self) -> bool:
        return all(self._artifact_valid(spec) and spec.id in self.executors for spec in self.manifest.models)

    def topology(self) -> list[dict[str, Any]]:
        return [
            {
                "id": spec.id,
                "runtime": spec.runtime,
                "digest": spec.sha256,
                "entity_types": sorted(spec.entity_types),
                "status": "ready" if self._artifact_valid(spec) and spec.id in self.executors else "unavailable",
                "network": "disabled",
                "remote_code": False,
            }
            for spec in self.manifest.models
        ]

    async def inspect(self, payload: Any) -> list[Finding]:
        if not self.manifest.models:
            return []
        findings: list[Finding] = []
        segments = _bounded_text_segments(payload)
        for spec in self.manifest.models:
            if not self._artifact_valid(spec):
                raise ModelExecutionError("mandatory local model artifact is unavailable")
            executor = self.executors.get(spec.id)
            if executor is None:
                raise ModelExecutionError("mandatory local model runtime is unavailable")
            try:
                findings.extend(
                    await asyncio.wait_for(
                        _inspect_segments(executor, spec, segments),
                        timeout=spec.timeout_ms / 1000,
                    )
                )
            except ModelExecutionError:
                raise
            except Exception as exc:
                raise ModelExecutionError("mandatory local model inference failed") from exc
        return findings

    def _artifact_valid(self, spec: LocalModelSpec) -> bool:
        try:
            hasher = hashlib.sha256()
            with spec.artifact_path.open("rb") as artifact:
                for chunk in iter(lambda: artifact.read(1024 * 1024), b""):
                    hasher.update(chunk)
            digest = hasher.hexdigest()
        except OSError:
            return False
        return digest == spec.sha256


async def _inspect_segments(
    executor: LocalTextModel,
    spec: LocalModelSpec,
    segments: tuple[tuple[str, str], ...],
) -> list[Finding]:
    model_findings: list[Finding] = []
    for path, text in segments:
        spans = await asyncio.to_thread(executor.predict, text)
        validated = _validate_spans(spans, text, spec)
        entity_counts: dict[str, int] = {}
        for span in validated:
            if span.confidence >= spec.confidence_threshold:
                entity_counts[span.entity_type] = entity_counts.get(span.entity_type, 0) + 1
        model_findings.extend(
            Finding(
                rule_id=f"model_{spec.id}_{entity_type}",
                severity="high",
                action=Action.BLOCK,
                path=path,
                count=count,
            )
            for entity_type, count in sorted(entity_counts.items())
        )
    return model_findings


def _validate_spans(
    spans: Sequence[ModelSpan], text: str, spec: LocalModelSpec
) -> tuple[ModelSpan, ...]:
    if isinstance(spans, (str, bytes)):
        raise ModelExecutionError("local model returned an invalid span collection")
    try:
        span_items = tuple(spans)
    except TypeError as exc:
        raise ModelExecutionError("local model returned an invalid span collection") from exc
    if any(not isinstance(span, ModelSpan) for span in span_items):
        raise ModelExecutionError("local model returned an invalid structured span")
    validated: list[ModelSpan] = []
    previous_end = -1
    for span in sorted(span_items, key=lambda item: (item.start, item.end)):
        if (
            isinstance(span.start, bool)
            or isinstance(span.end, bool)
            or not 0 <= span.start < span.end <= len(text)
            or span.start < previous_end
            or span.entity_type not in spec.entity_types
            or isinstance(span.confidence, bool)
            or not 0 <= span.confidence <= 1
        ):
            raise ModelExecutionError("local model returned an invalid structured span")
        validated.append(span)
        previous_end = span.end
    return tuple(validated)


def _text_segments(payload: Any, path: str = "$", depth: int = 0):
    if depth > 64:
        raise ModelExecutionError("model input depth exceeded")
    if isinstance(payload, str):
        yield path, payload
    elif isinstance(payload, list):
        for index, item in enumerate(payload):
            yield from _text_segments(item, f"{path}[{index}]", depth + 1)
    elif isinstance(payload, dict):
        for index, (key, value) in enumerate(payload.items()):
            if not isinstance(key, str):
                raise ModelExecutionError("model input contains an invalid key")
            yield from _text_segments(value, f"{path}.value[{index}]", depth + 1)


def _bounded_text_segments(payload: Any) -> tuple[tuple[str, str], ...]:
    segments: list[tuple[str, str]] = []
    characters = 0
    for path, text in _text_segments(payload):
        segments.append((path, text))
        characters += len(text)
        if len(segments) > MAX_MODEL_SEGMENTS or characters > MAX_MODEL_CHARACTERS:
            raise ModelExecutionError("local model input budget exceeded")
    return tuple(segments)
