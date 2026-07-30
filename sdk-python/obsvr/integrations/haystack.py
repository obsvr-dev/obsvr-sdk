"""Haystack 2.x / 3.x integration — a governance @component for a pipeline.

``ObsvrGuard`` is a real Haystack ``@component``: drop it into a Pipeline ahead
of your Generator and wire its ``prompt`` output into the Generator's text
input. On every run it applies the obsvr pre-call pipeline (built-in PII scan,
structured rules, the pre-call hook / HITL) to the prompt flowing through it:

- BLOCK  -> ``run`` raises. A raising component aborts ``pipeline.run()``, so
            the downstream Generator never executes — a real, enforceable stop.
- REDACT -> the redacted prompt is emitted downstream (the Generator sees the
            governed text, never the raw PII).
- ALLOW  -> the prompt passes through unchanged.

All three were driven against a real Pipeline and a real Generator on both ends
of the supported range, graded on the bytes the provider received rather than
on the return value: blocked reaches the provider zero times while an allowed
run through the same pipeline reaches it once, and a redacted run puts the
scrubbed text on the wire while the same prompt under no policy puts the raw
value there.

The guard itself is version-independent; only the Generator you put behind it
differs, because Haystack 3.0 removed the text ``OpenAIGenerator`` and its
``prompt`` socket. Both forms::

    from haystack import Pipeline
    from obsvr.integrations.haystack import ObsvrGuard
    import obsvr

    obsvr.init(api_key="...", ingest_url="https://...",
               pii_policy={"rules": {"ssn": "block"}})
    pipe = Pipeline()
    pipe.add_component("guard", ObsvrGuard())

    # haystack-ai 2.x
    from haystack.components.generators import OpenAIGenerator
    pipe.add_component("llm", OpenAIGenerator())
    pipe.connect("guard.prompt", "llm.prompt")

    # haystack-ai 3.x — no text generator ships any more; the chat generator's
    # `messages` socket accepts a bare str, so the same wire still type-checks
    from haystack.components.generators.chat import OpenAIChatGenerator
    pipe.add_component("llm", OpenAIChatGenerator())
    pipe.connect("guard.prompt", "llm.messages")

    pipe.run({"guard": {"prompt": "..."}})
"""

# Interception: Haystack 2.x @component node (non-mutating). Placed in the
# pipeline graph; a policy block raises out of run(), aborting the pipeline
# before the downstream generator runs.

from typing import Any, Dict, Optional

from ..config import try_get_config
from ..binding_report import record_binding
from ..events import emit_event
from ..policy import apply_pre_call_policy, blocked_prompt_for_storage

SOURCE = "haystack_py"
PROVIDER = "haystack"

try:  # real Haystack component registration when installed
    from haystack import component as _component  # type: ignore

    _HAS_HAYSTACK = True
    record_binding("haystack", "haystack.component")
except Exception as _exc:  # pragma: no cover - Haystack not installed
    _HAS_HAYSTACK = False
    record_binding("haystack", "haystack.component", _exc)

    class _ComponentShim:
        """Duck-types haystack.component enough to define the class + run I/O."""

        def __call__(self, cls: Any) -> Any:
            return cls

        def output_types(self, **_kw: Any):
            def _deco(fn: Any) -> Any:
                return fn

            return _deco

    _component = _ComponentShim()  # type: ignore


class ObsvrHaystackBlocked(RuntimeError):
    """Raised inside run() when the prompt is blocked by policy; aborts the pipeline."""


@_component
class ObsvrGuard:
    """Policy-enforcing Haystack component. Governs the prompt passing through.

    ``options`` may carry ``user_id`` / ``service_name`` / ``metadata``.
    """

    def __init__(self, **options: Any) -> None:
        self._options: Dict[str, Any] = options

    def _identity_meta(self) -> Optional[Dict[str, Any]]:
        opts = self._options or {}
        meta = dict(opts.get("metadata") or {})
        if opts.get("user_id") is not None:
            meta["user_id"] = opts["user_id"]
        if opts.get("service_name") is not None:
            meta["service_name"] = opts["service_name"]
        return meta or None

    @_component.output_types(prompt=str, blocked=bool, redacted=bool)
    def run(self, prompt: str) -> Dict[str, Any]:
        cfg = try_get_config()
        if cfg is None:
            return {"prompt": prompt, "blocked": False, "redacted": False}

        opts = self._options or None
        result = apply_pre_call_policy(
            prompt, cfg, provider=PROVIDER, operation="haystack.pipeline.run",
            metadata=self._identity_meta(),
        )
        compliance = result["compliance"]

        if result["decision"] == "block":
            emit_event(
                cfg, provider=PROVIDER, model="unknown", operation="haystack.pipeline.run",
                source=SOURCE,
                prompt=blocked_prompt_for_storage(
                    prompt, compliance, result.get("security_normalized")
                ),
                response="", success=False, status_code=403, compliance=compliance,
                options=opts,
            )
            raise ObsvrHaystackBlocked("[obsvr] Prompt blocked by policy")

        out_prompt = prompt
        redacted = False
        if result["decision"] == "redact":
            out_prompt = result["redacted_prompt"]
            redacted = True

        emit_event(
            cfg, provider=PROVIDER, model="unknown", operation="haystack.pipeline.run",
            source=SOURCE, prompt=out_prompt, response="", compliance=compliance,
            options=opts,
        )
        return {"prompt": out_prompt, "blocked": False, "redacted": redacted}
