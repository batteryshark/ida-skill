"""Resolve a binary to one coherent, session-guarded worker endpoint."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path


class WorkerNotReady(RuntimeError):
    """A missing or starting worker may be made ready by the bridge."""


def load_worker_target(runtime: Path, binary: str) -> tuple[int, str]:
    requested_path = os.path.realpath(binary)
    digest = hashlib.md5(requested_path.encode()).hexdigest()[:12]
    stem = runtime / f"worker-{digest}"
    try:
        state = json.loads(stem.with_suffix(".json").read_text())
    except FileNotFoundError:
        if stem.with_suffix(".pid").exists() or stem.with_suffix(".port").exists():
            raise ValueError("Unverified legacy worker state; stop it with the previous "
                             "bridge before upgrading") from None
        raise WorkerNotReady(f"No worker found for {binary}") from None
    except json.JSONDecodeError as error:
        raise ValueError(f"Invalid worker state for {binary}; state preserved") from error

    if (not isinstance(state, dict)
            or type(state.get("protocol")) is not int or state["protocol"] != 1
            or type(state.get("pid")) is not int or state["pid"] <= 0
            or not isinstance(state.get("session_id"), str) or not state["session_id"]
            or state.get("requested_path") != requested_path
            or "port" not in state):
        raise ValueError(f"Invalid or mismatched worker state for {binary}; state preserved")
    port = state["port"]
    if port is None:
        # The worker can finish after the bridge's startup deadline. Its atomic
        # readiness signal supplies a candidate port; every call still uses
        # worker-command to verify this captured session before dispatch.
        try:
            port = int(stem.with_suffix(".port").read_text().strip())
        except FileNotFoundError:
            raise WorkerNotReady(f"Worker for {binary} is not ready; inspect bridge status and log") from None
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError(f"Invalid worker port for {binary}; state preserved")
    return port, state["session_id"]
