#!/usr/bin/env python3
"""_debugshim.py — Pydantic-free model + FastMCP shim for the debugger port.

The debugger module (``debug.py``) is a near-verbatim port of the upstream
``re_mcp_ida_debugger.py`` FastMCP tool module. That module builds its results
with Pydantic ``BaseModel`` / ``Field`` and registers tools via a FastMCP
instance. The worker has neither dependency, so this shim provides drop-in
replacements:

  * ``BaseModel`` / ``Field`` — construct-by-keyword models that serialize to
    plain dicts via :func:`dump` (recursively, including nested models/lists).
  * ``McpShim`` — a stand-in for ``FastMCP`` whose ``.tool(...)`` decorator just
    records each registered function (and its read-only/mutate annotation) so
    the footer can auto-generate the command manifest from signatures.
  * The ``ANNO_*`` sentinels used by the upstream decorators.

Nothing here imports ``ida_*`` — the model classes and tool functions only
touch IDA at call time.
"""
from __future__ import annotations

from typing import Any


class _Required:
    """Sentinel marking a model field with no default (required)."""


_REQUIRED = _Required()


def Field(default: Any = _REQUIRED, *, default_factory: Any = None, **_kw: Any) -> Any:
    """Return the field default. Mirrors pydantic's ``Field`` call signature but
    ignores validation metadata (description, ge, ...)."""
    if default_factory is not None and default is _REQUIRED:
        try:
            return default_factory()
        except Exception:  # noqa: BLE001
            return None
    return default


class BaseModel:
    """Minimal stand-in for pydantic.BaseModel.

    Construct with keyword arguments only. Declared fields come from the
    class annotations across the MRO; a class attribute (produced by
    ``= Field(...)``) supplies the default. Required fields default to
    ``None`` when omitted. ``model_dump()`` / :func:`dump` produce plain
    JSON-serializable dicts.
    """

    def __init__(self, **kwargs: Any):
        anns: dict[str, Any] = {}
        for klass in reversed(type(self).__mro__):
            anns.update(getattr(klass, "__annotations__", {}))
        for fname in anns:
            if fname in kwargs:
                setattr(self, fname, kwargs.pop(fname))
                continue
            default = getattr(type(self), fname, _REQUIRED)
            if default is _REQUIRED:
                default = None
            elif isinstance(default, (list, dict, set)):
                default = type(default)(default)  # fresh copy per instance
            setattr(self, fname, default)
        # Preserve any extra keyword arguments the caller passed.
        for k, v in kwargs.items():
            setattr(self, k, v)

    def model_dump(self) -> Any:
        return dump(self)

    # Some upstream code paths may call dict()/.json — keep them working.
    def dict(self) -> Any:  # noqa: A003
        return dump(self)


def dump(obj: Any) -> Any:
    """Recursively convert shim models / containers to JSON-serializable data."""
    if isinstance(obj, BaseModel):
        return {k: dump(v) for k, v in vars(obj).items()}
    if isinstance(obj, dict):
        return {k: dump(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [dump(v) for v in obj]
    return obj


# ---------------------------------------------------------------------------
# FastMCP decorator shim
# ---------------------------------------------------------------------------
ANNO_READ_ONLY = "read_only"
ANNO_MUTATE = "mutate"
ANNO_MUTATE_NON_IDEMPOTENT = "mutate"
ANNO_DESTRUCTIVE = "destructive"


class McpShim:
    """Records ``@mcp.tool(...)`` registrations without a real MCP server."""

    def __init__(self) -> None:
        self.tools: dict[str, Any] = {}
        self.annotations: dict[str, Any] = {}

    def tool(self, *dargs: Any, annotations: Any = None, tags: Any = None,
             meta: Any = None, name: str | None = None, **_kw: Any):
        def deco(fn):
            key = name or fn.__name__
            self.tools[key] = fn
            self.annotations[key] = annotations
            return fn

        # Support bare @mcp.tool usage too.
        if dargs and callable(dargs[0]):
            return deco(dargs[0])
        return deco
