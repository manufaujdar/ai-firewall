import pytest

from ai_firewall.privacy.events import EventEmitter, EventStatus, PrivacyPhase


@pytest.mark.asyncio
async def test_event_emitter_rejects_non_allowlisted_metadata() -> None:
    emitter = EventEmitter("00000000-0000-4000-8000-000000000003")

    with pytest.raises(ValueError, match="forbidden key"):
        await emitter.emit(
            PrivacyPhase.RECEIVED,
            EventStatus.COMPLETED,
            {"payload": "SYNTHETIC_SOURCE_MUST_NOT_ENTER_EVENT"},
        )


@pytest.mark.asyncio
async def test_event_sequences_are_ordered_and_metadata_only() -> None:
    events = []

    async def collect(event) -> None:
        events.append(event)

    emitter = EventEmitter("00000000-0000-4000-8000-000000000004", collect)
    await emitter.emit(PrivacyPhase.RECEIVED, EventStatus.COMPLETED, {"policy_version": 1})
    await emitter.emit(PrivacyPhase.DETERMINISTIC, EventStatus.STARTED)

    assert [event.sequence for event in events] == [1, 2]
    assert all("payload" not in event.model_dump_json() for event in events)
