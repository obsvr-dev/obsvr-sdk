"""Opaque two-phase state for process-local strict receipt coordination."""

from __future__ import annotations

from typing import Any, Callable, Dict, Optional


class _DefinitiveNoStore:
    status = "definitive_no_store"


DEFINITIVE_NO_STORE = _DefinitiveNoStore()


class PreparedReceiptState:
    """Hold at most one signed receipt until transport certainty exists."""

    def __init__(self, token_factory: Callable[[], str]) -> None:
        self._token_factory = token_factory
        self._prepared: Optional[Dict[str, Any]] = None
        self._frozen_reason: Optional[str] = None

    def retry(self, fingerprint: str, kind: str) -> Optional[Dict[str, Any]]:
        self._assert_not_frozen()
        if self._prepared is None:
            return None
        if (
            self._prepared["fingerprint"] != fingerprint
            or self._prepared["kind"] != kind
        ):
            raise ValueError(
                "a different receipt is already prepared for this session"
            )
        return self._view(self._prepared)

    def prepare(
        self, *, fingerprint: str, receipt_hash: str, kind: str,
        value: Any, commit: Callable[[], None],
    ) -> Dict[str, Any]:
        self._assert_not_frozen()
        if self._prepared is not None:
            raise ValueError("a receipt is already prepared for this session")
        token = self._token_factory()
        if not isinstance(token, str) or not token.strip():
            raise ValueError("prepared token factory must return a nonblank string")
        self._prepared = {
            "token": token, "receipt_hash": receipt_hash, "kind": kind,
            "value": value, "fingerprint": fingerprint, "commit": commit,
        }
        return self._view(self._prepared)

    def commit(self, token: str, receipt_hash: str) -> Any:
        prepared = self._match(token, receipt_hash)
        try:
            prepared["commit"]()
        except Exception:
            self._frozen_reason = "accepted_but_local_commit_failed"
            raise
        self._prepared = None
        self._frozen_reason = None
        return prepared["value"]

    def abort(self, token: str, receipt_hash: str, capability: Any) -> None:
        if capability is not DEFINITIVE_NO_STORE:
            raise ValueError("abort requires the definitive_no_store capability")
        self._match(token, receipt_hash)
        self._prepared = None
        self._frozen_reason = None

    def freeze(self, token: str, receipt_hash: str, reason: str) -> None:
        self._match(token, receipt_hash)
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("freeze reason must be nonblank")
        self._frozen_reason = reason

    def reconcile(self, input_value: Dict[str, Any]) -> Any:
        status = input_value.get("status")
        if status == "stored":
            return self.commit(input_value.get("token"), input_value.get("receipt_hash"))
        if status == "definitive_no_store":
            self.abort(
                input_value.get("token"), input_value.get("receipt_hash"),
                input_value.get("capability"),
            )
            return None
        if status == "ambiguous":
            self.freeze(
                input_value.get("token"), input_value.get("receipt_hash"),
                input_value.get("reason"),
            )
            return None
        raise ValueError("unsupported prepared reconciliation status")

    def inspect(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {"frozen": self._frozen_reason is not None}
        if self._frozen_reason is not None:
            result["freeze_reason"] = self._frozen_reason
        if self._prepared is not None:
            result["prepared"] = {
                key: self._prepared[key]
                for key in ("token", "receipt_hash", "kind")
            }
        return result

    def reset(self) -> None:
        self._prepared = None
        self._frozen_reason = None

    def _assert_not_frozen(self) -> None:
        if self._frozen_reason is not None:
            raise ValueError("strict receipt session is frozen pending reconciliation")

    def _match(self, token: str, receipt_hash: str) -> Dict[str, Any]:
        if self._prepared is None:
            raise ValueError("no receipt is prepared")
        if token != self._prepared["token"]:
            raise ValueError("prepared token mismatch")
        if receipt_hash != self._prepared["receipt_hash"]:
            raise ValueError("prepared receipt hash mismatch")
        return self._prepared

    @staticmethod
    def _view(prepared: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "token": prepared["token"], "receipt_hash": prepared["receipt_hash"],
            "kind": prepared["kind"], "value": prepared["value"],
        }
