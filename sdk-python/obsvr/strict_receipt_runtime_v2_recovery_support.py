"""Internal recovery-store helpers for the strict v2 runtime."""

from typing import Any


def validate_recovery_store(coordinator: Any, store: Any) -> bool:
    if store is None:
        return False
    return callable(getattr(store, "save", None)) and callable(
        getattr(coordinator, "export_recovery_checkpoint", None)
    )


def persist_recovery(coordinator: Any, store: Any) -> None:
    if store is not None:
        store.save(coordinator.export_recovery_checkpoint())
