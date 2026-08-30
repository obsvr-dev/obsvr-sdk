"""Atomic disk-backed storage for signed audit events awaiting delivery."""

from __future__ import annotations

import json
import os
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

_FORMAT = "obsvr-durable-outbox/1"
_lock = threading.RLock()
_config: Optional[Dict[str, Any]] = None
_status: Dict[str, Any] = {}


def _empty_status() -> Dict[str, Any]:
    return {
        "enabled": False,
        "pending": 0,
        "dead_letters": 0,
        "bytes_on_disk": 0,
        "persisted": 0,
        "replayed": 0,
        "acknowledged": 0,
        "dead_lettered": 0,
        "write_failures": 0,
    }


def _directory(name: str) -> Path:
    if _config is None:
        raise RuntimeError("durable outbox is not configured")
    return Path(_config["directory"]) / name


def _files(name: str) -> List[Path]:
    paths = sorted(_directory(name).glob("*.json"), key=lambda path: path.name)
    for path in paths:
        if path.is_symlink() or not path.is_file():
            raise RuntimeError(f"durable outbox record must be a regular file: {path}")
    return paths


def _secure_directory(path: Path) -> None:
    if path.is_symlink():
        raise ValueError(f"durable outbox directory must not be a symbolic link: {path}")
    if not path.is_dir():
        raise ValueError(f"durable outbox path must be a directory: {path}")
    # mkdir(mode=...) does not tighten permissions on an existing directory.
    path.chmod(0o700)


def _disk_usage() -> int:
    return sum(path.stat().st_size for name in ("pending", "dead") for path in _files(name))


def _fsync_directory(path: Path) -> None:
    if not _config or not _config["fsync"]:
        return
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def configure(value: Optional[Dict[str, Any]]) -> None:
    global _config, _status
    with _lock:
        _config = None if value is None else dict(value)
        _status = _empty_status()
        if _config is None:
            return
        raw = Path(_config["directory"])
        if not raw.is_absolute():
            raise ValueError("durable_delivery.directory must be absolute")
        if raw.is_symlink():
            raise ValueError("durable_delivery.directory must not be a symbolic link")
        directory = raw.resolve()
        _config["directory"] = str(directory)
        _directory("pending").mkdir(parents=True, exist_ok=True, mode=0o700)
        _directory("dead").mkdir(parents=True, exist_ok=True, mode=0o700)
        _secure_directory(directory)
        _secure_directory(_directory("pending"))
        _secure_directory(_directory("dead"))
        _status.update(
            enabled=True,
            directory=str(directory),
            pending=len(_files("pending")),
            dead_letters=len(_files("dead")),
            bytes_on_disk=_disk_usage(),
        )
        if _status["bytes_on_disk"] > _config["max_bytes"]:
            raise RuntimeError(
                f"durable outbox already uses {_status['bytes_on_disk']} bytes, "
                f"above max_bytes={_config['max_bytes']}"
            )


def enabled() -> bool:
    return _config is not None


def failure_mode() -> str:
    return "error" if _config is None else str(_config["failure_mode"])


def persist(event: Dict[str, Any]) -> Optional[str]:
    if _config is None:
        return None
    with _lock:
        record_id = f"{int(time.time() * 1000):016d}-{uuid.uuid4()}"
        record = {
            "format": _FORMAT,
            "id": record_id,
            "created_at_ms": int(time.time() * 1000),
            "event": event,
        }
        payload = json.dumps(record, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        if _status["bytes_on_disk"] + len(payload) > _config["max_bytes"]:
            _status["write_failures"] += 1
            raise RuntimeError(
                f"durable outbox max_bytes={_config['max_bytes']} would be exceeded"
            )
        target = _directory("pending") / f"{record_id}.json"
        temporary = _directory("pending") / f".{record_id}.tmp"
        try:
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                with os.fdopen(fd, "wb", closefd=False) as handle:
                    handle.write(payload)
                    handle.flush()
                    if _config["fsync"]:
                        os.fsync(handle.fileno())
            finally:
                os.close(fd)
            os.replace(temporary, target)
            _fsync_directory(_directory("pending"))
        except Exception:
            _status["write_failures"] += 1
            try:
                temporary.unlink()
            except OSError:
                pass
            raise
        _status["persisted"] += 1
        _status["pending"] += 1
        _status["bytes_on_disk"] += len(payload)
        return record_id


def pending_records() -> List[Dict[str, Any]]:
    if _config is None:
        return []
    records = []
    with _lock:
        for path in _files("pending"):
            parsed = json.loads(path.read_text(encoding="utf-8"))
            if (
                parsed.get("format") != _FORMAT
                or not isinstance(parsed.get("id"), str)
                or not isinstance(parsed.get("created_at_ms"), int)
                or not isinstance(parsed.get("event"), dict)
            ):
                raise RuntimeError(f"invalid durable outbox record: {path}")
            records.append(parsed)
    return records


def mark_replayed(count: int) -> None:
    with _lock:
        _status["replayed"] += max(0, count)


def acknowledge(record_id: str) -> None:
    if _config is None:
        return
    with _lock:
        path = _directory("pending") / f"{record_id}.json"
        if not path.exists():
            return
        size = path.stat().st_size
        path.unlink()
        _fsync_directory(_directory("pending"))
        _status["acknowledged"] += 1
        _status["pending"] = max(0, _status["pending"] - 1)
        _status["bytes_on_disk"] = max(0, _status["bytes_on_disk"] - size)


def dead_letter(record_id: str, reason: str) -> None:
    if _config is None:
        return
    with _lock:
        source = _directory("pending") / f"{record_id}.json"
        if not source.exists():
            return
        safe = "".join(ch if ch.isalnum() or ch == "_" else "_" for ch in reason)[:64]
        os.replace(source, _directory("dead") / f"{record_id}.{safe or 'unknown'}.json")
        _fsync_directory(_directory("pending"))
        _fsync_directory(_directory("dead"))
        _status["dead_lettered"] += 1
        _status["pending"] = max(0, _status["pending"] - 1)
        _status["dead_letters"] += 1


def status() -> Dict[str, Any]:
    with _lock:
        return dict(_status)


def reset() -> None:
    global _config, _status
    with _lock:
        _config = None
        _status = _empty_status()
