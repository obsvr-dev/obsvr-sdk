"""Run a Python entry point with obsvr initialized before application imports.

Usage::

    obsvr-run app.py [args...]
    obsvr-run -m package.module [args...]

Configuration is read from ``OBSVR_*`` environment variables. Provider
construction interception is installed by ``init(auto=True)`` before the target
script or module begins importing its dependencies.
"""

from __future__ import annotations

import json
import os
import runpy
import sys
from typing import Any, Dict, List, Optional

from .config import init
from .binding_report import assert_required_bindings


def _json_object(name: str) -> Optional[Dict[str, Any]]:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return None
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"[obsvr] {name} must be valid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise SystemExit(f"[obsvr] {name} must be a JSON object")
    return value


def _optional_float(name: str) -> Optional[float]:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return None
    try:
        return float(raw)
    except ValueError as exc:
        raise SystemExit(f"[obsvr] {name} must be a number, got {raw!r}") from exc


def _initialize_from_environment() -> None:
    api_key = os.environ.get("OBSVR_API_KEY", "").strip()
    if not api_key:
        raise SystemExit(
            "[obsvr] OBSVR_API_KEY is required by obsvr-run. Set it or call "
            "obsvr.init() explicitly in the application."
        )
    init(
        api_key=api_key,
        ingest_url=os.environ.get("OBSVR_INGEST_URL") or None,
        environment=os.environ.get("OBSVR_ENVIRONMENT") or None,
        pii_policy=_json_object("OBSVR_PII_POLICY"),
        agent_policy=_json_object("OBSVR_AGENT_POLICY"),
        mcp_tool_policy=_json_object("OBSVR_MCP_TOOL_POLICY"),
        enforcement_mode=os.environ.get("OBSVR_ENFORCEMENT_MODE") or None,
        fail_mode=os.environ.get("OBSVR_FAIL_MODE") or None,
        policy_refresh_interval_s=_optional_float(
            "OBSVR_POLICY_REFRESH_INTERVAL_S"
        ),
        auto=True,
    )
    required = [
        value.strip()
        for value in os.environ.get("OBSVR_REQUIRED_BINDINGS", "").split(",")
        if value.strip()
    ]
    assert_required_bindings(required)


def main(argv: Optional[List[str]] = None) -> None:
    """Initialize obsvr, then execute a script or module as ``__main__``."""
    args = list(sys.argv[1:] if argv is None else argv)
    if args[:1] == ["--"]:
        args = args[1:]
    if not args:
        raise SystemExit("usage: obsvr-run [-m module | script.py] [args ...]")

    _initialize_from_environment()

    if args[0] == "-m":
        if len(args) < 2:
            raise SystemExit("obsvr-run: -m requires a module name")
        module = args[1]
        sys.argv = [module, *args[2:]]
        runpy.run_module(module, run_name="__main__", alter_sys=True)
        return

    script = args[0]
    sys.argv = [script, *args[1:]]
    runpy.run_path(script, run_name="__main__")


if __name__ == "__main__":  # pragma: no cover - exercised through subprocess
    main()
