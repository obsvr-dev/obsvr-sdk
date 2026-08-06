"""Framework-agnostic tool governance — govern the tool itself.

``govern_tool(tool)`` wraps a tool object from ANY agent framework so that
every invocation is governed at the point of execution, before the tool's own
code runs:

  1. allow/deny against ``agent_policy`` (``denied_tools`` / ``allowed_tools``)
     — a denied tool RAISES the SDK's typed policy error before its function
     runs, so the side effect never exists;
  2. the full pre-call policy net — ``policy_rules``, the ``policy_floor``,
     PII block/redact, ``on_pre_call``, canary and session-taint gates
     (including ``destructive_tools``) — the SAME pipeline ``obsvr.wrap()``
     and the MCP integration run, not an integration-grade subset;
  3. a signed audit event per call (``tool.call`` / ``tool.policy.tool_blocked``)
     carrying the sealed tool-content digest of the descriptor and arguments.

This is the Python twin of the TypeScript SDK's ``obsvrGovernTool``
(``integrations/tools.ts``), and it exists for the same reason: most agent
frameworks either surface no pre-execution tool callback at all, or change it
across versions. Wrapping the tool's own callable is the one boundary every
framework converges on — its dispatch has to call SOMETHING, and this is the
something::

    from obsvr.integrations.tools import govern_tool
    safe_search = govern_tool(search_tool)
    agent = Agent(..., tools=[safe_search])

Where the gate physically sits, per framework shape (first match wins). The
right-hand column is MEASURED — every supported framework's real tool object was
resolved through this table and the result is pinned in
``tests/test_tool_governor.py``:

    on_invoke_tool     openai-agents ``FunctionTool`` (input is argument 1)
    _run / _arun       crewai ``BaseTool`` and langchain ``StructuredTool``
                       (what structured-tool conversion captures)
    execute            execute-shaped tool objects
    call / acall       llamaindex ``FunctionTool``, ``QueryEngineTool`` and the
                       sync-to-async adapter
    invoke / ainvoke   structured tools exposing only the public surface
    run / arun         run-shaped tool objects
    func               plain function-holder shapes
    (bare callable)    a plain function is wrapped and returned directly

Two surfaces resolve to nothing here, by shape rather than by omission:
pydantic-ai's ``Tool`` carries no execute attribute at all and is governed at
its toolset boundary, and MCP has no client-side tool object — its gate binds
``ClientSession.send_request``.

PLUS ``func`` alongside whichever attr matched, whenever the object stores
its callable in a ``func`` field: entry points fan out (crewai's ``Tool.run``
calls ``self.func`` directly, bypassing ``_run``), and the stored callable is
where they converge. PLUS the async ALIASES in ``_ASYNC_ALIASES``, because one
logical entry point can have more than one async spelling and Haystack's
``Tool`` uses ``invoke_async`` rather than ``ainvoke``. A reentrancy guard keeps
a delegating entry point from being gated or audited twice for one invocation.

A governed tool also DECLINES RESULT CACHING where the framework offers a say
(``cache_function``). A result cache serves a repeat call from the framework's
own memory without entering the callable, so a cached answer would escape this
gate entirely — and escape it invisibly, since no execution happens for a
side-effect instrument to count. Measured on CrewAI: allowed once, denied
after, the caller still received the cached output. See :func:`_never_cache`.

A refusal is a RAISE of ``ObsvrPolicyError`` from inside the tool's callable.
What the framework does with it is the framework's contract — CrewAI converts
it into a failed-tool observation and the run continues; LangChain propagates
it out of the tool — but in every case the guarantee is the same: the tool
body was never entered. A tool shape the table does not recognize is returned
unchanged; a wrapped tool is a shallow COPY where the object permits it, so the
caller's original is not mutated.

GOVERNING A CALLER MUST NOT DAMAGE THE CALLER, and one shape used to. The gate
installs by SHADOWING — an instance attribute that wins at lookup over the class
one — so an attribute backed by a data descriptor cannot be gated however
callable it looks. ``ag2``'s ``autogen.tools.Tool`` exposes its callable as
``func``, a property with no setter over a private ``_func``, and
``object.__setattr__`` honours data descriptors: the write raised
``AttributeError`` straight out of ``govern_tool`` and into the caller's
program. A property WITH a setter is quieter and worse — the write succeeds, the
setter runs, and no gate is installed.

Such an attribute is therefore not an entry point at all. It is skipped during
resolution, and a recognized tool whose entry points are ALL ungateable comes
back exactly as it was passed: never converted into a bare function, and — the
part that matters beyond this module — never registered in the governed-name
registry, because the audit rails on other surfaces stand down for a registered
name and would turn a coverage gap into their silence.

To govern such a tool, wrap the underlying FUNCTION before the framework builds
its tool object around it. That is gated normally, and on ag2 the gated callable
survives all of the framework's own wrapping layers into the executor's function
map — which is where ``integrations/autogen.py`` puts it.
"""

import contextvars
import copy
import functools
import inspect
import json
import types
from typing import Any, Callable, Dict, Optional, Set, Tuple

from ..capability_hints import declares_destructive
from ..config import try_get_config
from ..errors import ObsvrPolicyError
from ..events import (
    blocked_call_error,
    emit_event,
    tool_denied_compliance,
)
from ..policy import (
    apply_outbound_redaction,
    apply_pre_call_policy,
    assert_redaction_applied,
    blocked_prompt_for_storage,
    outbound_redaction_blocked_compliance,
    redact_arguments,
    redact_builtin_pii,
)
from ..tool_content_hash import safe_tool_content_hash, tool_content_metadata

SOURCE = "obsvr_tool"

#: Set on an object :func:`govern_tool` verifiably installed a gate on, and
#: checked before wrapping, so governing twice yields one gate: without it a
#: second wrap re-gates the first wrapper's callables and every invocation is
#: evaluated and audited twice (the per-call ``inflight`` guard is allocated
#: fresh per govern_tool call and cannot see across wraps). The marker lives
#: on the RETURNED object — govern_tool hands back a copy — never on the
#: caller's original, and it is set only on the paths that confirmed a
#: wrapper took: a tool where nothing was gateable stays unmarked, so a later
#: legitimate attempt still runs rather than being refused by a claim no gate
#: backs.
_GOVERNED_MARKER_ATTR = "_obsvr_tool_governed"


def _already_governed(tool: Any) -> bool:
    """Whether this object is one govern_tool returned. Never raises — an
    exotic __getattr__ must not break the caller's wrap call."""
    try:
        return getattr(tool, _GOVERNED_MARKER_ATTR, False) is True
    except Exception:  # noqa: BLE001 - a getter that raises is not a marker
        return False

#: Names of every tool a governor wraps, for the audit rails that would
#: otherwise re-judge a governed call after the fact (CrewAI's step callback
#: consults this so it never stamps ``not_evaluated`` beside the wrapper's own
#: verdict). Process-lifetime by design — a governed name stays the wrapper's
#: to speak for.
_GOVERNED_TOOL_NAMES: Set[str] = set()


def is_tool_governed(tool_name: str) -> bool:
    """Whether a tool of this name has been wrapped by :func:`govern_tool`."""
    return tool_name in _GOVERNED_TOOL_NAMES


def governed_tool_names() -> Set[str]:
    """A copy of the governed-name registry.

    For audit rails whose framework renames tools before dispatch and so
    cannot ask about a name they can only recognize after normalizing it
    (CrewAI sanitizes, and the transform is not invertible).
    """
    return set(_GOVERNED_TOOL_NAMES)


def register_governed_tool_name(tool_name: str) -> None:
    """Record that a pre-execution gate outside this module speaks for a name.

    For integration-owned gates whose refusal lives in the framework's own
    pre-invocation surface (openai-agents' tool input guardrails) rather than
    in a wrapped callable. One registry serves every audit rail that must not
    stamp ``not_evaluated`` beside a real gate's own verdict, whichever
    mechanism the gate is. Process-lifetime, like the wrapper's own entries.
    """
    _GOVERNED_TOOL_NAMES.add(tool_name)

#: Exec-attr resolution table: (sync_attr, async_attr) in priority order.
#: ORDER IS THE CONTRACT (the TS twin learned this the hard way: three shapes
#: appended late were silent no-ops until added). ``_run`` outranks the public
#: ``run``/``invoke`` because crewai's structured-tool conversion captures the
#: BOUND ``_run`` (``base_tool.py: func=self._run``) — gating anything shallower
#: leaves that captured reference ungoverned.
#:
#: What each supported framework resolves to is pinned in
#: ``tests/test_tool_governor.py`` against shapes read off the real tool classes,
#: so an addition here that moved an existing shape onto a different attribute
#: would fail rather than be discovered by a customer.
_EXEC_ATTR_PAIRS: Tuple[Tuple[str, Optional[str]], ...] = (
    ("on_invoke_tool", None),
    ("_run", "_arun"),
    ("execute", None),
    ("call", "acall"),
    ("invoke", "ainvoke"),
    ("run", "arun"),
    ("func", None),
)

#: Extra async spellings for a sync entry point, co-gated whenever present.
#: Additive to the pairs above: a tool that carries none of these resolves
#: exactly as it did before. Haystack's ``Tool`` pairs ``invoke`` with
#: ``invoke_async``, not ``ainvoke``, and its Agent reaches ONLY that one on the
#: async path — measured: a governed tool refused under ``Agent.run`` and ran
#: under ``Agent.run_async``, returned its payload, and recorded no event at all.
#: Same lesson as ``func``: one logical entry point, more than one spelling.
_ASYNC_ALIASES: Dict[str, Tuple[str, ...]] = {
    "invoke": ("invoke_async",),
}

#: Every name the table can reach, for recognizing a tool shape whose entry
#: points turn out not to be gateable (see :func:`_carries_exec_attr`).
_ALL_EXEC_ATTR_NAMES: frozenset = frozenset(
    [name for pair in _EXEC_ATTR_PAIRS for name in pair if name]
    + [alias for aliases in _ASYNC_ALIASES.values() for alias in aliases]
)


def _shadowable(tool: Any, attr: str) -> bool:
    """Whether an instance attribute could shadow this class attribute.

    The gate installs by SHADOWING: an entry in the instance ``__dict__`` wins
    at lookup over a plain function or any other non-data descriptor, which is
    what the conversion helpers that capture a bound callable then read. A DATA
    descriptor never loses to the instance dict, so an attribute backed by one
    cannot be gated however callable it looks — and both of the outcomes that
    produced were wrong. ag2's ``Tool.func`` is a property with no setter, so
    ``object.__setattr__`` RAISED ``AttributeError`` out of the caller's
    program; a property WITH a setter is quieter and worse, because the write
    succeeds, runs the setter, and installs no gate at all.

    Slots are the exception and are treated as writable: a ``member_descriptor``
    is storage rather than behaviour, so shadowing one does reach dispatch. It
    is not decidable statically whether a given slot is read-only —
    ``functools.partial.func`` is a ``member_descriptor`` too and refuses the
    write — which is why the install site verifies rather than trusting this.

    Reading the CLASS rather than the instance is deliberate: it answers the
    question without running a property getter, and some getters raise.
    """
    for klass in type(tool).__mro__:
        if attr in klass.__dict__:
            descriptor = klass.__dict__[attr]
            descriptor_type = type(descriptor)
            if not (
                hasattr(descriptor_type, "__set__")
                or hasattr(descriptor_type, "__delete__")
            ):
                return True
            return isinstance(descriptor, types.MemberDescriptorType)
    return True  # absent from every class: instance-only, so plainly writable


def _is_gateable(tool: Any, attr: str) -> bool:
    """Present, callable, and installable. Shadowability is checked FIRST so a
    property getter is never run just to decide it cannot be gated."""
    if not _shadowable(tool, attr):
        return False
    try:
        return callable(getattr(tool, attr, None))
    except Exception:  # noqa: BLE001 - a getter that raises is not an entry point
        return False


def _carries_exec_attr(tool: Any) -> bool:
    """Whether this looks like a framework TOOL OBJECT rather than a callable.

    Used only when nothing could be gated, to decide between the two ways of
    coming back empty-handed. A tool object whose entry points are all
    ungateable must be returned AS IT IS; running it through the bare-callable
    branch would hand the caller a plain function in place of their tool, which
    on ag2 fails at ``Agent()`` construction rather than anywhere near here. A
    plain function carries none of these names and is unaffected.
    """
    return any(hasattr(type(tool), name) for name in _ALL_EXEC_ATTR_NAMES)


def _resolve_exec_attrs(
    tool: Any, extra: Optional[Tuple[str, ...]] = None
) -> Tuple[str, ...]:
    """The attrs to gate on this object.

    The first present pair, both halves — PLUS ``func`` whenever the object
    stores its callable in a field, because public entry points fan out and
    the stored callable is where they converge: crewai's ``Tool.run`` and
    ``Tool.arun`` call ``self.func`` directly without passing through
    ``_run``, so a gate on ``_run`` alone covers the ReAct dispatch (which
    captures ``_run``) and MISSES the native dispatch (which captures
    ``run``). Measured live before this was learned: the same governed tool
    blocked on ReAct and executed on native. The per-call reentrancy guard
    below keeps an entry point that DOES delegate inward from being gated
    and audited twice.

    An attribute that cannot be SHADOWED is not an entry point and is skipped —
    see :func:`_shadowable`. Every framework whose exec attributes were
    enumerated resolves to the same attributes it did before that filter
    existed; the one shape it changes is ag2's ``Tool``, whose only match was a
    property and which used to raise out of ``govern_tool``.

    ``extra`` names further attrs a CALLER knows this framework's dispatch can
    reach, appended to whatever the table resolved. It exists because the table
    is framework-agnostic by design and some shapes hide a second, equally
    dispatchable reference behind a private name — LlamaIndex's ``FunctionTool``
    keeps ``_fn``/``_async_fn``/``_real_fn`` beside the public ``call``/``acall``
    pair, and its CodeAct agent reads ``real_fn`` and never calls the tool at
    all. Names absent from the object are skipped, so passing a shape's attrs to
    a tool that is not that shape is a no-op rather than an error.
    """
    resolved: Tuple[str, ...] = ()
    for sync_attr, async_attr in _EXEC_ATTR_PAIRS:
        if _is_gateable(tool, sync_attr):
            attrs = [sync_attr]
            if async_attr and _is_gateable(tool, async_attr):
                attrs.append(async_attr)
            for alias in _ASYNC_ALIASES.get(sync_attr, ()):
                if _is_gateable(tool, alias):
                    attrs.append(alias)
            if sync_attr != "func" and _is_gateable(tool, "func"):
                attrs.append("func")
            resolved = tuple(attrs)
            break
    if extra:
        seen = set(resolved)
        for name in extra:
            if name in seen or not _is_gateable(tool, name):
                continue
            seen.add(name)
            resolved = resolved + (name,)
    return resolved


def _resolve_tool_name(tool: Any, explicit: Optional[str]) -> str:
    if explicit:
        return explicit
    for source in (
        getattr(tool, "name", None),
        getattr(getattr(tool, "metadata", None), "name", None),
        getattr(tool, "__name__", None),
    ):
        if isinstance(source, str) and source:
            return source
    return "unknown_tool"


def _descriptor_of(
    tool: Any, tool_name: str, override: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Best-effort descriptor under the evidence contract's wire names.

    The schema is included when the tool carries one that can be projected to
    JSON; a tool carrying none contributes no schema rather than a guessed one
    (same posture as the TS twin).

    ``override`` lets a framework-aware caller FILL WHAT THE GENERIC READ MISSES.
    The reads below look for ``description`` and ``args_schema`` ON THE TOOL; a
    shape that keeps both behind a metadata object (LlamaIndex) would otherwise
    seal a name-only digest, which is weaker evidence than the contract is built
    to carry. It fills only keys the generic read did not produce, so what a
    recognized shape seals is unchanged whether or not an override is passed.
    """
    descriptor: Dict[str, Any] = {"name": tool_name}
    description = getattr(tool, "description", None)
    if isinstance(description, str) and description:
        descriptor["description"] = description
    schema = getattr(tool, "args_schema", None)
    try:
        if schema is not None and hasattr(schema, "model_json_schema"):
            descriptor["inputSchema"] = schema.model_json_schema()
        elif isinstance(schema, dict):
            descriptor["inputSchema"] = schema
    except Exception:
        pass  # sealed evidence: a missing schema beats a wrong one
    for key, value in (override or {}).items():
        if key != "name" and value is not None and key not in descriptor:
            descriptor[key] = value
    return descriptor


def _declared_params(tool: Any, original: Callable[..., Any]) -> Optional[Set[str]]:
    """The parameter names this tool DECLARES, or None when it declares none.

    AUDIT THE DECLARED SURFACE, NOT WHAT THE FRAMEWORK HAPPENED TO PASS. A
    framework calls a tool's entry point with its own machinery alongside the
    model's arguments: LangChain adds ``run_manager`` and the whole
    ``RunnableConfig``, and under LangGraph that config carries the Pregel
    scratchpad, callback-manager handles, weakrefs and checkpoint UUIDs. Merging
    args and kwargs wholesale put all of it in the SIGNED event, and had three
    consequences that were each worse than the noise:

      * the PII scanner matched the debris — a LangGraph ``checkpoint_id`` is a
        UUID — so every governed tool call recorded ``PII_DETECTED`` for
        arguments that contained no PII;
      * the sealed tool-content digest could not be computed over unhashable
        framework objects, so ``safe_tool_content_hash`` returned None and the
        evidence field was simply ABSENT — indistinguishable from a deployment
        that seals nothing;
      * memory addresses in the reprs made the signed content differ between two
        identical calls.

    Resolution order, strongest declaration first:

      1. ``args_schema`` — the schema the MODEL is given. What is in it is the
         whole of what a caller may send, so it is the exact allow-list. The
         same read already feeds the descriptor digest (:func:`_descriptor_of`).
      2. ``args`` — LangChain's projection of that schema, for shapes that
         expose the properties without the model class.
      3. the entry point's own signature, but only when it has no ``**kwargs``:
         a signature that collects overflow declares nothing about what lands
         there, and the overflow is exactly where the framework's machinery
         arrives.

    None means "this shape declares nothing" and the caller keeps the whole
    payload. That direction is deliberate: an audited payload narrowed to
    nothing is silence, which is worse than noise.
    """
    for schema in (getattr(tool, "args_schema", None),):
        try:
            if schema is not None and hasattr(schema, "model_json_schema"):
                props = schema.model_json_schema().get("properties")
                if isinstance(props, dict) and props:
                    return set(props)
            elif isinstance(schema, dict):
                props = schema.get("properties")
                if isinstance(props, dict) and props:
                    return set(props)
        except Exception:  # noqa: BLE001 - a schema that will not project
            pass
    try:
        args_map = getattr(tool, "args", None)
        if isinstance(args_map, dict) and args_map:
            return set(args_map)
    except Exception:  # noqa: BLE001 - a property that raises is not a schema
        pass
    try:
        params = inspect.signature(original).parameters
    except (TypeError, ValueError):
        return None
    names = set()
    for name, param in params.items():
        if param.kind is inspect.Parameter.VAR_KEYWORD:
            return None
        if param.kind is inspect.Parameter.VAR_POSITIONAL:
            return None
        if name != "self":
            names.add(name)
    return names or None


class _Binding:
    """A call's arguments addressed BY NAME, and writable back into the call.

    One binding serves both halves of the fix: it is how the declared names are
    selected out of a call that may have passed them positionally, and it is how
    a redacted value is written BACK into the call — so the two halves cannot
    disagree about which value is which.

    The overflow parameter is flattened, and that is the whole reason this is a
    class rather than a bare ``BoundArguments``. A framework entry point
    collects the model's arguments in ``**kwargs``: LangChain's
    ``StructuredTool._run(*args, config, run_manager=None, **kwargs)`` puts
    ``order_id`` inside ``arguments["kwargs"]``, one level down, where a lookup
    by declared name finds nothing at all. Selecting on the unflattened view
    silently matched no declared parameter and fell back to auditing everything
    — the same defect, reached by a different route.
    """

    def __init__(self, bound: inspect.BoundArguments, var_keyword: Optional[str]):
        self._bound = bound
        self._var_keyword = var_keyword

    def named(self) -> Dict[str, Any]:
        """Every argument this call supplied, addressed by parameter name."""
        flat = dict(self._bound.arguments)
        overflow = flat.pop(self._var_keyword, None) if self._var_keyword else None
        if isinstance(overflow, dict):
            flat.update(overflow)
        return flat

    def set(self, name: str, value: Any) -> None:
        """Replace one named argument, wherever the binding actually holds it."""
        if name in self._bound.arguments and name != self._var_keyword:
            self._bound.arguments[name] = value
            return
        if self._var_keyword:
            overflow = self._bound.arguments.get(self._var_keyword)
            if isinstance(overflow, dict) and name in overflow:
                # A fresh dict: BoundArguments hands back the caller's mapping
                # for the overflow, and governing a caller must not mutate it.
                updated = dict(overflow)
                updated[name] = value
                self._bound.arguments[self._var_keyword] = updated

    def call(self) -> Tuple[tuple, dict]:
        return self._bound.args, self._bound.kwargs


def _bind_arguments(
    original: Callable[..., Any], args: tuple, kwargs: dict
) -> Optional[_Binding]:
    """Bind this call to the callable's parameters, or None if the shape resists."""
    try:
        signature = inspect.signature(original)
        bound = signature.bind_partial(*args, **kwargs)
    except (TypeError, ValueError):
        return None
    var_keyword = next(
        (
            name
            for name, param in signature.parameters.items()
            if param.kind is inspect.Parameter.VAR_KEYWORD
        ),
        None,
    )
    return _Binding(bound, var_keyword)


def _input_of(
    exec_attr: str,
    args: tuple,
    kwargs: dict,
    bound: Optional["_Binding"] = None,
    declared: Optional[Set[str]] = None,
) -> Any:
    """The tool input, normalized across calling conventions.

    ``on_invoke_tool(run_context, input)`` carries the input at position 1;
    every other shape carries it at position 0 or as keyword arguments.

    When the tool declares a parameter surface (see :func:`_declared_params`)
    and the call could be bound to names, the payload is narrowed to exactly
    that surface. A narrowing that selects NOTHING is discarded rather than
    reported: an empty payload beside a call that plainly carried arguments is a
    shape this resolution does not understand, and the wholesale value is the
    honest answer there.
    """
    if exec_attr == "on_invoke_tool" and len(args) >= 2:
        return args[1]
    if bound is not None and declared:
        selected = {
            name: value
            for name, value in bound.named().items()
            if name in declared
        }
        if selected:
            return selected
    if kwargs and not args:
        return kwargs
    if len(args) == 1 and not kwargs:
        return args[0]
    payload: Dict[str, Any] = {}
    if args:
        payload["args"] = list(args)
    if kwargs:
        payload["kwargs"] = kwargs
    return payload


def _redacted_call(
    exec_attr: str,
    args: tuple,
    kwargs: dict,
    bound: Optional["_Binding"],
    declared: Optional[Set[str]],
    redact: Callable[[Optional[str]], str],
) -> Tuple[tuple, dict, Any]:
    """Rebuild this invocation with its declared arguments redacted.

    Returns ``(args, kwargs, payload)`` — the call to make, and the payload the
    record should describe. The payload is derived from the REDACTED values
    rather than from the policy engine's own redacted copy of the text, so what
    the event says the tool received is what the tool received.

    ONLY DECLARED ARGUMENTS ARE REWRITTEN. The framework's own handles travel
    through untouched: rewriting a callback manager or a checkpoint id would
    corrupt the run, and neither is content the policy was asked about.
    """
    if bound is not None and declared:
        supplied = bound.named()
        targets = [name for name in supplied if name in declared]
        if targets:
            payload = {}
            for name in targets:
                value = redact_arguments(supplied[name], redact)
                bound.set(name, value)
                payload[name] = value
            new_args, new_kwargs = bound.call()
            return new_args, new_kwargs, payload

    if exec_attr == "on_invoke_tool" and len(args) >= 2:
        redacted = redact_arguments(args[1], redact)
        return (args[0], redacted) + tuple(args[2:]), kwargs, redacted

    # No declared surface to narrow to: redact everything the call carried,
    # which is also everything that was scanned.
    new_args = tuple(redact_arguments(value, redact) for value in args)
    new_kwargs = {key: redact_arguments(value, redact) for key, value in kwargs.items()}
    return new_args, new_kwargs, _input_of(exec_attr, new_args, new_kwargs)


def _input_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value if value is not None else {}, default=str)
    except Exception:
        return str(value)


def _check_tool(tool_name: str, policy: Dict[str, Any]) -> Tuple[bool, str]:
    """Return (allowed, reason). reason is empty string when allowed."""
    denied = policy.get("denied_tools") or []
    allowed = policy.get("allowed_tools")  # None = all allowed
    if tool_name in denied:
        return False, "tool_denied"
    if allowed is not None and tool_name not in allowed:
        return False, "tool_not_in_allowlist"
    return True, ""


def _identity_meta(options: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Identity metadata for the enforcing channel and the event record.

    The caller principal reaches enforcement THROUGH the metadata dict: the
    quota meter buckets on ``metadata.user_id``, the session-taint latch keys
    on it, approval grants bind to it, and the decision-input hash commits to
    it. The ``user_id=`` / ``service_name=`` wrap-time kwargs therefore have
    to be folded in here, or a caller who passes them gets a signed principal
    on the record and none of the user-scoped enforcement.

    Precedence matches every other surface that threads identity
    (``pydantic_ai.py``, ``bedrock.py``, ``vertex.py``, ``haystack.py``,
    ``mcp.py``): start from ``metadata``, then the wrap-time kwargs overlay.
    Consistency across surfaces matters more than either ordering.

    The ambient ``use_subject()`` scope fills only what is still unset, so
    the enforcing channel resolves the same identity the signed channel does
    (``events.build_audit_event`` applies the same fallback) and an explicit
    identity always wins over the ambient one.
    """
    opts = options or {}
    meta = dict(opts.get("metadata") or {})
    if opts.get("user_id") is not None:
        meta["user_id"] = opts["user_id"]
    if opts.get("service_name") is not None:
        meta["service_name"] = opts["service_name"]
    from ..subject import get_current_subject

    ambient = get_current_subject() or {}
    for key in ("user_id", "tenant_id", "service_name"):
        if meta.get(key) is None and ambient.get(key) is not None:
            meta[key] = ambient[key]
    return meta or None


def _gate(
    tool: Any,
    tool_name: str,
    exec_attr: str,
    args: tuple,
    kwargs: dict,
    options: Dict[str, Any],
    descriptor: Optional[Dict[str, Any]] = None,
    original: Optional[Callable[..., Any]] = None,
) -> Tuple[tuple, dict]:
    """Run every check that must precede the tool body. Raises to refuse.

    Returns the ``(args, kwargs)`` the body is to be called with. On a ``redact``
    verdict those are NOT the arguments that came in: the declared arguments are
    rewritten and the tool receives the redacted values, because a tool is where
    side effects live and a redaction that stops at the audit copy protects
    nothing that a file, a row, or a third-party API will see.
    """
    config = try_get_config()
    if config is None:
        return args, kwargs

    declared = _declared_params(tool, original) if original is not None else None
    bound = _bind_arguments(original, args, kwargs) if original is not None else None
    raw_input = _input_of(exec_attr, args, kwargs, bound, declared)
    input_text = _input_text(raw_input)
    content_meta = tool_content_metadata(
        safe_tool_content_hash(
            tool_name=tool_name,
            descriptor=_descriptor_of(tool, tool_name, descriptor),
            args=raw_input,
        )
    )
    event_options = options or None
    # One resolution feeds the policy evaluation AND the emitted events, so
    # the identity that scoped enforcement is the identity the record carries.
    # The record's own facts (tool_name, sealed content digest) merge after
    # caller identity, so caller metadata can never overwrite them.
    identity_meta = _identity_meta(options)

    # 1) allow/deny — refuse a denied tool before it runs.
    policy = getattr(config, "agent_policy", None) or {}
    ok, reason = _check_tool(tool_name, policy)
    if not ok:
        compliance = tool_denied_compliance()
        emit_event(
            config,
            provider="unknown",
            model="unknown",
            operation="tool.policy.tool_blocked",
            source=SOURCE,
            prompt="",
            response="",
            success=False,
            metadata={
                **(identity_meta or {}),
                "tool_name": tool_name,
                "reason": reason,
                **content_meta,
            },
            compliance=compliance,
            options=event_options,
        )
        raise blocked_call_error(compliance)

    # 2) the full pre-call net, exactly as the MCP boundary runs it: gated on
    # the same trigger list, blocking on the same decision, honouring
    # fail_mode the same way. This is deliberately NOT the observe-only
    # subset the callback integrations run — a wrapped tool is a real
    # enforcement boundary, so it gets the real pipeline.
    from ..canary import canary_registry_size
    from ..session_taint import session_taint_size

    compliance_out: Optional[Dict[str, Any]] = None
    stored_prompt = input_text
    if (
        config.policy_floor
        # Same entry, same reason as the MCP boundary: a deployment whose only
        # policy is a customer rule set must still reach the pipeline, or the
        # rules are silently inert at this boundary and the call records
        # `allowed` without them having been consulted.
        or config.policy_rules
        or config.pii_policy is not None
        or config.on_pre_call is not None
        # require_principal arms the net by itself: a config whose only
        # policy is "refuse unattributed calls" still needs the pipeline to
        # run, or the flag is silently inert at this boundary.
        or getattr(config, "require_principal", False)
        or canary_registry_size() > 0
        or session_taint_size() > 0
    ):
        try:
            result = apply_pre_call_policy(
                input_text,
                config,
                provider="unknown",
                operation="tool.call",
                metadata=identity_meta,
                tool_name=tool_name,
                tool_declared_destructive=declares_destructive(tool),
            )
            compliance_out = result["compliance"]
            stored_prompt = result["redacted_prompt"]
            if result["decision"] == "redact":
                # ENFORCEMENT APPLICATION, not a record of one. The pipeline's
                # own ``redacted_prompt`` is a redacted copy of the SCANNED
                # TEXT; it cannot be handed to a callable that takes arguments.
                # So the declared arguments are rewritten value by value and
                # the stored prompt is then derived from THOSE — the record
                # describes what the tool received because it is built from it.
                #
                # Fails closed exactly as the wrap() path does: a redaction the
                # SDK cannot carry out blocks the call rather than forwarding
                # the content it was told to remove, and the event drops every
                # "redacted" claim (see outbound_redaction_blocked_compliance).
                redacted_state: Dict[str, Any] = {}

                def _apply_redaction() -> None:
                    new_args, new_kwargs, payload = _redacted_call(
                        exec_attr, args, kwargs, bound, declared, redact_builtin_pii
                    )
                    assert_redaction_applied(payload, compliance_out)
                    redacted_state["call"] = (new_args, new_kwargs)
                    redacted_state["payload"] = payload

                not_redacted = apply_outbound_redaction(_apply_redaction)
                if not_redacted is not None:
                    compliance_out = outbound_redaction_blocked_compliance(
                        compliance_out, not_redacted
                    )
                    emit_event(
                        config,
                        provider="unknown",
                        model="unknown",
                        operation="tool.call",
                        source=SOURCE,
                        prompt=blocked_prompt_for_storage(
                            input_text, compliance_out,
                            result.get("security_normalized"),
                        ),
                        response="",
                        success=False,
                        status_code=403,
                        metadata={
                            **(identity_meta or {}),
                            "tool_name": tool_name,
                            **content_meta,
                        },
                        compliance=compliance_out,
                        options=event_options,
                    )
                    raise blocked_call_error(compliance_out)
                args, kwargs = redacted_state["call"]
                stored_prompt = _input_text(redacted_state["payload"])
                # Re-seal: the digest commits to what the tool was handed, so a
                # verifier reproducing it from the stored prompt gets the same
                # value instead of a digest of arguments nobody ever received.
                content_meta = tool_content_metadata(
                    safe_tool_content_hash(
                        tool_name=tool_name,
                        descriptor=_descriptor_of(tool, tool_name, descriptor),
                        args=redacted_state["payload"],
                    )
                )
            if result["decision"] == "block":
                emit_event(
                    config,
                    provider="unknown",
                    model="unknown",
                    operation="tool.call",
                    source=SOURCE,
                    prompt=blocked_prompt_for_storage(
                        input_text, compliance_out, result.get("security_normalized")
                    ),
                    response="",
                    success=False,
                    status_code=403,
                    metadata={
                        **(identity_meta or {}),
                        "tool_name": tool_name,
                        **content_meta,
                    },
                    compliance=compliance_out,
                    options=event_options,
                )
                raise blocked_call_error(compliance_out)
        except ObsvrPolicyError:
            raise
        except Exception as e:
            # Parity with the MCP boundary: an engine that cannot render a
            # verdict is not approval under fail_mode="closed"; under the
            # default "open" the evaluation error does not block the tool.
            if getattr(config, "fail_mode", "open") == "closed":
                raise blocked_call_error(
                    {
                        "event_type": "blocked_call",
                        "policy_version": "none",
                        "action_taken": "blocked",
                        "action_reason": "policy_violation",
                        "action_source": "policy_rules",
                        "redacted_types": [],
                        "blocked_types": [],
                    }
                ) from e
            compliance_out = None
            stored_prompt = input_text

    # 3) signed tool.call audit event.
    emit_event(
        config,
        provider="unknown",
        model="unknown",
        operation="tool.call",
        source=SOURCE,
        prompt=stored_prompt,
        response="",
        metadata={
            **(identity_meta or {}),
            "tool_name": tool_name,
            **content_meta,
        },
        # The pipeline's own verdict when it ran — it carries the
        # decision_input_hash that EVIDENCES the evaluation, so an `allowed`
        # tool call can be told apart from one nothing looked at. The fallback
        # is reached only when no policy the pipeline enforces was configured,
        # and it names NO deciding layer: "policy_rules" here credited the
        # rules engine with a permit it was never asked for.
        compliance=compliance_out
        or {
            "event_type": "tool_call",
            "policy_version": "none",
            "action_taken": "allowed",
            "action_reason": "none",
            "action_source": "unknown",
            "redacted_types": [],
            "blocked_types": [],
        },
        options=event_options,
    )
    return args, kwargs


def _wrap_callable(
    tool: Any,
    tool_name: str,
    exec_attr: str,
    original: Callable[..., Any],
    options: Dict[str, Any],
    inflight: "contextvars.ContextVar[bool]",
    descriptor: Optional[Dict[str, Any]] = None,
) -> Callable[..., Any]:
    """Gate one callable. ``inflight`` is shared across every gated attr of
    one governed object: an outer entry point that delegates to an inner
    gated attr (crewai's ``_run`` → ``func``, LlamaIndex's ``call`` → ``_fn``)
    must be gated ONCE — a second verdict and a second audit event for one
    invocation is how a step budget silently drifts.

    THE GATE'S RETURN IS THE CALL. Under a ``redact`` verdict the arguments it
    hands back are not the ones that came in, and the body is entered with those
    — the tool is the surface where a redaction has to be real, because a tool
    writes files and rows rather than a transcript."""
    if inspect.iscoroutinefunction(original):

        @functools.wraps(original)
        async def gated_async(*args: Any, **kwargs: Any) -> Any:
            if inflight.get():
                return await original(*args, **kwargs)
            token = inflight.set(True)
            try:
                args, kwargs = _gate(
                    tool, tool_name, exec_attr, args, kwargs, options, descriptor,
                    original,
                )
                return await original(*args, **kwargs)
            finally:
                inflight.reset(token)

        return gated_async

    @functools.wraps(original)
    def gated(*args: Any, **kwargs: Any) -> Any:
        if inflight.get():
            return original(*args, **kwargs)
        token = inflight.set(True)
        try:
            args, kwargs = _gate(
                tool, tool_name, exec_attr, args, kwargs, options, descriptor,
                original,
            )
            return original(*args, **kwargs)
        finally:
            inflight.reset(token)

    return gated


def _never_cache(_args: Any = None, _result: Any = None) -> bool:
    """Decline memoization of a governed tool's result.

    A framework result cache answers a repeat call out of its own memory
    WITHOUT invoking the tool's callable — which is the only place this
    governor sits. Measured on CrewAI with the crew's cache enabled: a tool
    run while allowed and re-requested after the policy denied it was served
    the cached output, the tool body was never entered, and so the
    side-effect instrument read ZERO while the caller still received the
    content — a block that never happened, reported as one.

    Refusing to cache is what keeps "every invocation is governed" literally
    true: the call reaches the callable every time, so the gate rules every
    time. Frameworks that consult a ``cache_function`` to decide whether to
    store a result (CrewAI reads it at every cache-write site) therefore get
    a permanent no from a governed tool.
    """
    return False


def _refuse_result_caching(tool: Any) -> bool:
    """Neutralize a framework's result cache for this tool. Returns applied."""
    if not hasattr(tool, "cache_function"):
        return False
    try:
        object.__setattr__(tool, "cache_function", _never_cache)
        return True
    except Exception:
        # A container that will not accept the override still gets the gate;
        # it just keeps whatever caching it had. Never break the caller's tool
        # over a defence-in-depth measure.
        return False


def _copy_tool(tool: Any) -> Any:
    """A shallow copy when the object permits one, else the object itself.

    pydantic models copy through ``model_copy``; most plain objects through
    ``copy.copy``. An object that refuses both is gated in place — documented,
    and strictly better than returning it ungoverned.
    """
    try:
        if hasattr(tool, "model_copy"):
            return tool.model_copy()
        return copy.copy(tool)
    except Exception:
        return tool


def govern_tool(
    tool: Any,
    name: Optional[str] = None,
    extra_exec_attrs: Optional[Tuple[str, ...]] = None,
    descriptor: Optional[Dict[str, Any]] = None,
    **options: Any,
) -> Any:
    """Wrap a framework tool so its execution is governed by obsvr.

    Returns an object of the same type whose execute callable(s) are gated;
    the original is not mutated when the object supports copying. A tool whose
    shape is not recognized is returned unchanged (never breaks the caller) —
    unless it is itself callable, in which case the callable is wrapped.

    ``name=`` pins the audit name for tools that carry none of their own.
    ``extra_exec_attrs=`` names further callables this framework's dispatch can
    reach beyond what the resolution table finds, and ``descriptor=`` fills the
    descriptor fields the generic read cannot see; both are for framework-aware
    callers (see :func:`_resolve_exec_attrs` and :func:`_descriptor_of`) and
    both default to the table's own behaviour. Remaining keyword options
    (``user_id=``, ``service_name=``, ``metadata=``) attach the audit principal
    to every event AND scope the enforcement to it — user-scoped quota buckets,
    the session-taint key, approval-grant binding and the decision-input hash
    all resolve from the same folded identity (see :func:`_identity_meta`) —
    the same way the other integrations accept them.

    Governing an already-governed object is a no-op returning it unchanged:
    re-gating the first wrapper's callables would evaluate and audit every
    invocation twice (see ``_GOVERNED_MARKER_ATTR``).
    """
    if _already_governed(tool):
        return tool

    exec_attrs = _resolve_exec_attrs(tool, extra_exec_attrs)
    tool_name = _resolve_tool_name(tool, name)

    if not exec_attrs:
        if callable(tool) and not _carries_exec_attr(tool):
            original = tool
            inflight: "contextvars.ContextVar[bool]" = contextvars.ContextVar(
                "obsvr_tool_gate_inflight", default=False
            )
            _GOVERNED_TOOL_NAMES.add(tool_name)
            gated_callable = _wrap_callable(
                original, tool_name, "__call__", original, options, inflight,
                descriptor,
            )
            # A wrapped bare callable IS the installed gate, so it carries the
            # marker directly (functions accept attributes).
            setattr(gated_callable, _GOVERNED_MARKER_ATTR, True)
            return gated_callable
        return tool

    governed = _copy_tool(tool)
    _refuse_result_caching(governed)
    inflight = contextvars.ContextVar("obsvr_tool_gate_inflight", default=False)
    installed = []
    for attr in exec_attrs:
        original = getattr(governed, attr)
        wrapped = _wrap_callable(
            governed, tool_name, attr, original, options, inflight, descriptor
        )
        # object.__setattr__ so pydantic/frozen containers cannot veto the
        # gate: the instance attribute shadows the class method (or replaces
        # the stored field value, for `func`), which is exactly what the
        # conversion helpers that capture the BOUND callable read.
        #
        # THEN CONFIRM IT TOOK, because resolution cannot always know. A slot
        # and a read-only C-level attribute are the same descriptor type, so
        # `functools.partial.func` refuses a write that a real slot accepts;
        # and a container could accept the write and store it somewhere lookup
        # never reads. Governing a caller must not damage the caller, so a
        # refusal is skipped rather than raised through them.
        try:
            object.__setattr__(governed, attr, wrapped)
            took = getattr(governed, attr, None) is wrapped
        except Exception:  # noqa: BLE001 - a container that vetoes the write
            took = False
        if took:
            installed.append(attr)

    if not installed:
        # Recognized, and gateable nowhere. Hand back the ORIGINAL: the copy
        # may carry a disabled result cache, and the caller is better off with
        # the object they passed. The name is deliberately NOT registered —
        # the governed-name registry is what the audit rails on other surfaces
        # consult before standing down, so claiming a name here would convert
        # a coverage gap into their silence.
        return tool

    _GOVERNED_TOOL_NAMES.add(tool_name)
    # Marked only HERE — after read-back confirmed at least one wrapper took —
    # and on the returned copy, never the caller's original. A container that
    # refuses the marker write simply stays re-governable; that costs a
    # duplicate gate in an exotic shape, where marking a tool no gate backs
    # would silently disable governance on it.
    try:
        object.__setattr__(governed, _GOVERNED_MARKER_ATTR, True)
    except Exception:  # noqa: BLE001 - marker is best-effort, the gate is not
        pass
    return governed


def govern_tools(tools: Any, **options: Any) -> list:
    """Wrap several tools at once. Names are read from each tool."""
    return [govern_tool(t, **options) for t in tools]
