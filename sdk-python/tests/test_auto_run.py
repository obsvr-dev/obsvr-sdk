"""The zero-edit Python runner governs before application imports."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]


def _runner_env() -> dict:
    env = dict(os.environ)
    env.update(
        {
            "PYTHONPATH": str(ROOT),
            "OBSVR_API_KEY": "test-key",
            "OBSVR_INGEST_URL": "http://127.0.0.1:1",
            "OBSVR_ENVIRONMENT": "development",
            "OBSVR_PII_POLICY": "{}",
            "OBSVR_POLICY_REFRESH_INTERVAL_S": "0",
        }
    )
    return env


def test_runner_blocks_real_openai_before_http_transport(tmp_path):
    pytest.importorskip("openai")
    pytest.importorskip("httpx")
    script = tmp_path / "app.py"
    script.write_text(
        """
import httpx
from openai import OpenAI

transport_calls = 0
def transport(_request):
    global transport_calls
    transport_calls += 1
    return httpx.Response(200, json={"id": "should-not-run", "choices": []})

client = OpenAI(
    api_key="provider-key",
    http_client=httpx.Client(transport=httpx.MockTransport(transport)),
)
blocked = False
try:
    client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": "SSN 123-45-6789"}],
    )
except Exception as exc:
    blocked = exc.__class__.__name__ == "ObsvrPolicyError"

print(f"RESULT:{blocked}:{transport_calls}:{type(client).__name__}")
""",
        encoding="utf-8",
    )

    result = subprocess.run(
        [sys.executable, "-m", "obsvr.auto_run", str(script)],
        cwd=ROOT,
        env=_runner_env(),
        text=True,
        capture_output=True,
        timeout=60,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "RESULT:True:0:_ObsvrProxy" in result.stdout


def test_runner_refuses_to_start_without_api_key(tmp_path):
    script = tmp_path / "app.py"
    script.write_text("raise AssertionError('application must not start')\n")
    env = _runner_env()
    env["OBSVR_API_KEY"] = ""

    result = subprocess.run(
        [sys.executable, "-m", "obsvr.auto_run", str(script)],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        timeout=60,
        check=False,
    )

    assert result.returncode != 0
    assert "OBSVR_API_KEY is required" in result.stderr
    assert "application must not start" not in result.stderr


def test_runner_preserves_script_arguments(tmp_path):
    script = tmp_path / "args.py"
    script.write_text(
        "import sys\nprint('ARGS:' + '|'.join(sys.argv))\n",
        encoding="utf-8",
    )

    result = subprocess.run(
        [sys.executable, "-m", "obsvr.auto_run", str(script), "one", "two"],
        cwd=ROOT,
        env=_runner_env(),
        text=True,
        capture_output=True,
        timeout=60,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert f"ARGS:{script}|one|two" in result.stdout


def test_runner_refuses_an_unbound_required_integration(tmp_path):
    script = tmp_path / "app.py"
    script.write_text("raise AssertionError('application must not start')\n")
    env = _runner_env()
    env["OBSVR_REQUIRED_BINDINGS"] = "not-installed"

    result = subprocess.run(
        [sys.executable, "-m", "obsvr.auto_run", str(script)],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        timeout=60,
        check=False,
    )

    assert result.returncode != 0
    assert "not-installed was never bound" in result.stderr
    assert "application must not start" not in result.stderr
