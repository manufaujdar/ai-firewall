import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

from .models import ScanResponse


def audit_storage_usable(path: Path) -> bool:
    """Return whether the configured metadata-only audit sink can be appended to."""

    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8"):
            pass
    except OSError:
        return False
    return True


def write_audit_event(path: Path, result: ScanResponse, destination: str | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    event = {
        "timestamp": datetime.now(UTC).isoformat(),
        "decision": result.decision.value,
        "destination": destination,
        "finding_count": sum(finding.count for finding in result.findings),
        "rules": sorted({finding.rule_id for finding in result.findings}),
        "paths_hash": hashlib.sha256(
            "|".join(sorted(finding.path for finding in result.findings)).encode()
        ).hexdigest(),
    }
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, separators=(",", ":")) + "\n")
