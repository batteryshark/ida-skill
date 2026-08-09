"""handlers — auto-discovered command modules for the idalib worker.

Every ``*.py`` in this package that defines a module-level ``COMMANDS`` list
(of :class:`ida_cmd.Command`) is discovered and flattened into a single
registry. Because handler modules keep their ``ida_*`` imports inside function
bodies, importing this package (and therefore ``REGISTRY``) requires **no** IDA
runtime — that is what lets ``cli.py`` and ``mcp.py`` introspect the full
command surface anywhere.

Public API:
  * ``REGISTRY``   — dict[str, Command] keyed by name and alias
  * ``COMMANDS``   — list[Command], de-duplicated, in discovery order
  * ``MODULES``    — list of imported handler modules
"""
from __future__ import annotations

import importlib
import pkgutil

from ida_cmd import Command, build_registry

MODULES: list = []
for _info in pkgutil.iter_modules(__path__):
    if _info.name.startswith("_"):
        continue
    _mod = importlib.import_module(f"{__name__}.{_info.name}")
    if hasattr(_mod, "COMMANDS"):
        MODULES.append(_mod)

# Stable ordering by (category, name) keeps generated docs/help deterministic.
MODULES.sort(key=lambda m: m.__name__)

REGISTRY: dict[str, Command] = build_registry(MODULES)

# De-duplicated command list (a Command with aliases appears once).
_seen: set[int] = set()
COMMANDS: list[Command] = []
for _cmd in REGISTRY.values():
    if id(_cmd) not in _seen:
        _seen.add(id(_cmd))
        COMMANDS.append(_cmd)
COMMANDS.sort(key=lambda c: (c.category, c.name))
