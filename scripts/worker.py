#!/usr/bin/env python3
"""worker.py — Persistent idalib TCP command server.

Boots once, opens a database, then serves JSON commands over TCP.
All IDA calls are dispatched to the main thread (idalib is single-threaded).

Protocol: newline-delimited JSON. One request per connection.
  Request:  {"cmd": "decompile-function", "args": {"address": "main"}}
  Response: {"status": "ok", "result": {...}}
  Error:    {"status": "error", "error": "message", "error_type": "..."}

Commands are auto-discovered from the ``handlers/`` package (see
``handlers/__init__.py`` and ``ida_cmd.py``). Lifecycle commands
(``open``/``close``/``save``) are built in below. Run ``python cli.py commands``
for the full catalog, or read ``references/*.md``.
"""
from __future__ import annotations

import json
import logging
import os
import queue
import signal
import socketserver
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable

# ─────────────────────────────────────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.DEBUG if os.environ.get("IDA_WORKER_DEBUG") else logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stderr,
)
log = logging.getLogger("ida-worker")

# Make sibling modules (ida_cmd, ida_helpers, handlers/) importable when the
# worker is spawned from an arbitrary CWD.
SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))


def _host_platform() -> str:
    """Return the platform key matching setup.mjs/bridge.mjs convention."""
    if sys.platform == "win32":
        return "windows"
    if sys.platform == "darwin":
        return "mac"
    return "linux"


DEFAULT_BIN_DIR = Path(
    os.environ.get("IDA_SKILL_BIN_DIR", SCRIPT_DIR.parent / "bin")
).expanduser().resolve()
RUNTIME_DIR = Path(
    os.environ.get("IDA_RUNTIME_DIR", DEFAULT_BIN_DIR / f"ida-runtime-{_host_platform()}")
).expanduser().resolve()


def _setup_environment():
    """Set IDADIR, IDAUSR, and sys.path so idapro can be imported from the
    portable runtime. Also handles Windows license registration automatically.
    """
    ida_dir = str(RUNTIME_DIR)
    if not os.path.isdir(ida_dir):
        print(f"ERROR: Runtime directory not found: {ida_dir}", file=sys.stderr)
        print("Run: node scripts/setup.mjs --ida-dir /path/to/ida", file=sys.stderr)
        sys.exit(1)

    os.environ["IDADIR"] = ida_dir

    license_dir = os.path.join(ida_dir, "license")
    has_license = (
        os.path.isfile(os.path.join(license_dir, "idapro.hexlic"))
        and (
            os.path.isfile(os.path.join(license_dir, "ida.reg"))  # macOS/Linux
            or sys.platform == "win32"  # Windows: worker auto-registers
        )
    )
    if has_license:
        os.environ["IDAUSR"] = license_dir
        log.info("Using bundled license from %s", license_dir)
    else:
        log.info("No bundled license — using system IDA config")

    idalib_py = os.path.join(ida_dir, "idalib", "python")
    python_dir = os.path.join(ida_dir, "python")
    for p in [idalib_py, python_dir]:
        if os.path.isdir(p) and p not in sys.path:
            sys.path.insert(0, p)

    if sys.platform == "win32" and has_license:
        _register_windows_license()


def _register_windows_license():
    """Set the single HKCU registry value IDA's batch mode requires.

    IDA's kernel checks ONLY ``HKCU\\Software\\Hex-Rays\\IDA\\EULA 90``
    (REG_DWORD) before allowing batch-mode open_database(). The license itself
    is discovered via IDAUSR (the ``idapro.hexlic`` file). Writes are
    idempotent and per-user (HKCU); no admin rights required.
    """
    import winreg

    try:
        key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Hex-Rays\IDA")
        try:
            existing, _ = winreg.QueryValueEx(key, "EULA 90")
            log.debug("EULA 90 already accepted (value=%s)", existing)
        except FileNotFoundError:
            winreg.SetValueEx(key, "EULA 90", 0, winreg.REG_DWORD, 1)
            log.info("Set HKCU\\Software\\Hex-Rays\\IDA\\EULA 90 = 1 (first run)")
        winreg.CloseKey(key)
    except Exception as e:  # noqa: BLE001
        log.warning("Could not set EULA 90 registry value: %s", e)

# Imports that require ida_cmd/ida_helpers/handlers on sys.path (safe — they
# lazy-import ida_* internally, so this does not touch idapro yet).
from ida_cmd import IDAError  # noqa: E402
from ida_helpers import session as ida_session  # noqa: E402
import handlers  # noqa: E402


# ─────────────────────────────────────────────────────────────────────────────
# MainThreadExecutor — dispatches calls to the main thread (idalib is
# thread-affine: the idapro import and all IDA API calls must happen on the
# same thread). Jobs are queued FIFO and each carries its own completion event
# and result slot, so concurrent submitters can never clobber or cross-deliver
# each other's results.
# ─────────────────────────────────────────────────────────────────────────────
class _Job:
    __slots__ = ("fn", "args", "kwargs", "done", "result", "error")

    def __init__(self, fn: Callable, args: tuple, kwargs: dict):
        self.fn = fn
        self.args = args
        self.kwargs = kwargs
        self.done = threading.Event()
        self.result: Any = None
        self.error: BaseException | None = None


class MainThreadExecutor:
    def __init__(self):
        self._jobs: "queue.Queue[_Job]" = queue.Queue()
        self._shutdown = False

    def submit(self, fn: Callable, *args, **kwargs) -> Any:
        if self._shutdown:
            raise RuntimeError("Executor is shut down")
        job = _Job(fn, args, kwargs)
        self._jobs.put(job)
        while not job.done.wait(timeout=0.5):
            # Jobs still queued at shutdown are failed by shutdown() itself;
            # this check only covers a submit racing the shutdown drain.
            if self._shutdown and job.done.wait(timeout=0.1) is False:
                raise RuntimeError("Worker is shutting down")
        if job.error is not None:
            raise job.error
        return job.result

    def drain(self, timeout: float) -> None:
        """Run queued jobs on the calling thread, waiting up to ``timeout``
        seconds for new work. A job that has started always runs to completion.
        """
        deadline = time.monotonic() + timeout
        while not self._shutdown:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return
            try:
                job = self._jobs.get(timeout=remaining)
            except queue.Empty:
                return
            self._run(job)

    @staticmethod
    def _run(job: _Job) -> None:
        try:
            job.result = job.fn(*job.args, **job.kwargs)
        except Exception as e:  # noqa: BLE001 — delivered to the submitter
            job.error = e
        except BaseException as e:
            # SystemExit/KeyboardInterrupt (e.g. SIGTERM landing mid-command):
            # fail the job for its submitter, then let the signal propagate to
            # the main loop for graceful shutdown.
            job.error = RuntimeError(f"Worker interrupted by {type(e).__name__}")
            raise
        finally:
            job.done.set()

    def pending(self) -> bool:
        return not self._jobs.empty()

    def shutdown(self):
        """Refuse new submissions and fail any jobs still queued."""
        self._shutdown = True
        while True:
            try:
                job = self._jobs.get_nowait()
            except queue.Empty:
                break
            job.error = RuntimeError("Worker is shutting down")
            job.done.set()


_executor: MainThreadExecutor | None = None


def get_executor() -> MainThreadExecutor:
    global _executor
    if _executor is None:
        raise RuntimeError("Executor not initialized")
    return _executor


def set_executor(executor: MainThreadExecutor):
    global _executor
    _executor = executor


def call_ida(fn: Callable, *args, **kwargs) -> Any:
    """Dispatch a function call to the main thread."""
    return get_executor().submit(fn, *args, **kwargs)


# ─────────────────────────────────────────────────────────────────────────────
# ActivityTracker — in-flight request count + last-activity time, so the idle
# shutdown never fires while a request is being served.
# ─────────────────────────────────────────────────────────────────────────────
class ActivityTracker:
    def __init__(self):
        self._lock = threading.Lock()
        self._in_flight = 0
        self._last_activity = time.time()

    def begin(self):
        with self._lock:
            self._in_flight += 1
            self._last_activity = time.time()

    def end(self):
        with self._lock:
            self._in_flight = max(0, self._in_flight - 1)
            self._last_activity = time.time()

    def busy(self) -> bool:
        with self._lock:
            return self._in_flight > 0

    def idle_seconds(self) -> float:
        with self._lock:
            return time.time() - self._last_activity


# ─────────────────────────────────────────────────────────────────────────────
# IDA state management — session state lives in ida_helpers.session so that
# handler helpers (decompile_at, require_capability, ...) see the same view.
# ─────────────────────────────────────────────────────────────────────────────
def is_open() -> bool:
    return ida_session.is_open()


# Backwards-compatible alias for any external caller.
IDAWorkerError = IDAError


# ─────────────────────────────────────────────────────────────────────────────
# Multi-agent / autosave policy. MULTI_AGENT is set once from CLI args in
# main(); _autosave is mutated only on the main thread (which executes every
# command), so no locking is needed.
# ─────────────────────────────────────────────────────────────────────────────
MULTI_AGENT = False

# Commands that operate on global database state: with concurrent clients, an
# undo or snapshot restore would silently destroy other agents' work.
_MULTI_AGENT_BLOCKED = {"undo", "redo", "restore-snapshot"}

_autosave = {"mutations": 0, "last_save": time.time()}


def _mark_saved():
    _autosave["mutations"] = 0
    _autosave["last_save"] = time.time()


def _probe_capabilities() -> dict[str, bool]:
    import ida_hexrays
    import ida_idp

    return {
        "decompiler": bool(ida_hexrays.init_hexrays_plugin()),
        "assembler": ida_idp.get_idp_name() == "metapc",
    }


# ─────────────────────────────────────────────────────────────────────────────
# Lifecycle commands (built in — they own idapro open/close/save)
# ─────────────────────────────────────────────────────────────────────────────
def cmd_open(args: dict) -> dict:
    """Open a binary or existing database for analysis."""
    import idapro

    file_path = os.path.realpath(os.path.expanduser(args["file_path"]))
    run_auto = args.get("run_auto_analysis", True)

    if is_open():
        cmd_close({"save": True})

    log.info("Opening database: %s (auto_analysis=%s)", file_path, run_auto)
    rc = idapro.open_database(file_path, run_auto)
    if rc != 0:
        codes = {1: "File not found", 2: "Invalid format", 3: "License error", 4: "Stale database"}
        msg = codes.get(rc, f"Error code {rc}")
        raise IDAError(f"Failed to open database: {msg}", "OpenFailed")

    ida_session.current_path = file_path
    ida_session.capabilities = _probe_capabilities()
    _mark_saved()
    log.info("Opened (capabilities: %s)", ida_session.capabilities)
    return {"status": "ok", "path": file_path, "capabilities": ida_session.capabilities}


def cmd_close(args: dict) -> dict:
    """Close the current database."""
    import idapro

    save = args.get("save", True)
    if not is_open():
        return {"status": "no_database_open"}
    path = ida_session.current_path
    try:
        idapro.close_database(save)
    except Exception as e:  # noqa: BLE001
        log.exception("Error closing database")
        raise IDAError(f"Error closing database: {e}", "CloseFailed")
    ida_session.current_path = None
    ida_session.capabilities = {}
    _mark_saved()
    return {"status": "closed", "path": path, "saved": save}


def cmd_save(args: dict) -> dict:
    """Save the database (close+reopen without re-analysis to flush to disk)."""
    import idapro
    import ida_loader

    if not is_open():
        raise IDAError("No database open", "NoDatabase")
    path = ida_session.current_path
    database_path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
    if not database_path:
        raise IDAError("Cannot save without a database path", "SaveFailed")
    idapro.close_database(True)
    ida_session.current_path = None
    ida_session.capabilities = {}
    _mark_saved()
    rc = idapro.open_database(database_path, False)
    if rc != 0:
        raise IDAError(f"Database saved but failed to reopen (error code {rc})", "SaveReopenFailed")
    ida_session.current_path = path
    ida_session.capabilities = _probe_capabilities()
    return {"status": "saved", "path": path}


def cmd_list_commands(args: dict) -> dict:
    """List every available command with its category and summary."""
    out = []
    for c in handlers.COMMANDS:
        out.append({
            "name": c.name,
            "aliases": c.aliases,
            "category": c.category,
            "mutates": c.mutates,
            "summary": c.summary,
        })
    return {"commands": out, "count": len(out)}


_BUILTINS: dict[str, Callable[[dict], Any]] = {
    "open": cmd_open,
    "close": cmd_close,
    "save": cmd_save,
    "list-commands": cmd_list_commands,
}

# Lifecycle commands that are allowed without an open database.
_NO_OPEN_REQUIRED = {"open", "close", "save", "list-commands"}


# ─────────────────────────────────────────────────────────────────────────────
# Dispatch
# ─────────────────────────────────────────────────────────────────────────────
def handle_command(cmd: str, args: dict) -> dict:
    args = args or {}

    builtin = _BUILTINS.get(cmd)
    if builtin is not None:
        return builtin(args)

    command = handlers.REGISTRY.get(cmd)
    if command is None:
        available = sorted(set(_BUILTINS) | set(handlers.REGISTRY))
        raise IDAError(
            f"Unknown command: {cmd}. Run 'list-commands' for the catalog.",
            "UnknownCommand",
            available=available,
        )

    if MULTI_AGENT and command.name in _MULTI_AGENT_BLOCKED:
        raise IDAError(
            f"'{command.name}' is disabled in multi-agent mode: it rolls back "
            "global database state and would destroy other agents' concurrent "
            "work. Fix forward instead (re-apply the correct label/type).",
            "MultiAgentBlocked",
        )
    if command.requires_open and not is_open():
        raise IDAError(
            "No database is open. Start a worker with --binary, or 'open' first.",
            "NoDatabase",
        )
    result = command.handler(args)
    if command.mutates:
        _autosave["mutations"] += 1
    return result


# ─────────────────────────────────────────────────────────────────────────────
# TCP server
# ─────────────────────────────────────────────────────────────────────────────
MAX_REQUEST_SIZE = 16 * 1024 * 1024  # 16 MB


class CommandHandler(socketserver.StreamRequestHandler):
    tracker: ActivityTracker | None = None  # set in main()

    def handle(self):
        if self.tracker is not None:
            self.tracker.begin()
        try:
            self._handle_request()
        finally:
            if self.tracker is not None:
                self.tracker.end()

    def _handle_request(self):
        try:
            line = self.rfile.readline(MAX_REQUEST_SIZE)
            if not line:
                return
            req = json.loads(line)
            cmd = req.get("cmd", "")
            args = req.get("args", {})
            log.debug("CMD: %s args=%s", cmd, list((args or {}).keys()))
            result = call_ida(handle_command, cmd, args)
            self.send_response({"status": "ok", "result": result})
        except json.JSONDecodeError as e:
            self.send_response({"status": "error", "error": f"Invalid JSON: {e}", "error_type": "JSONError"})
        except IDAError as e:
            resp = {"status": "error", "error": e.message, "error_type": e.error_type}
            if e.details:
                resp["details"] = e.details
            self.send_response(resp)
        except Exception as e:  # noqa: BLE001
            log.exception("Unhandled error handling command")
            self.send_response({"status": "error", "error": str(e), "error_type": type(e).__name__})

    def send_response(self, resp: dict):
        data = (json.dumps(resp, default=str) + "\n").encode("utf-8")
        self.wfile.write(data)
        self.wfile.flush()


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


# ─────────────────────────────────────────────────────────────────────────────
# Signal handlers
# ─────────────────────────────────────────────────────────────────────────────
def _terminate_handler(signum, frame):
    raise SystemExit(0)


def _cancel_handler(signum, frame):
    import ida_kernwin

    if ida_kernwin.user_cancelled():
        raise SystemExit(0)
    ida_kernwin.set_cancelled()


# ─────────────────────────────────────────────────────────────────────────────
# Main entry point
# ─────────────────────────────────────────────────────────────────────────────
def main():
    import argparse

    parser = argparse.ArgumentParser(description="idalib worker process")
    parser.add_argument("--port", type=int, default=0, help="TCP port (0=auto)")
    parser.add_argument("--port-file", required=True, help="File to write the actual port")
    parser.add_argument("--binary", required=False, help="Binary to auto-open")
    analysis = parser.add_mutually_exclusive_group()
    analysis.add_argument("--run-auto-analysis", dest="run_auto_analysis", action="store_true")
    analysis.add_argument("--no-run-auto-analysis", dest="run_auto_analysis", action="store_false")
    parser.set_defaults(run_auto_analysis=True)
    parser.add_argument("--idle-timeout", type=int, default=600, help="Idle shutdown seconds (0=disable)")
    parser.add_argument("--autosave", type=int, default=300,
                        help="Save the database this many seconds after unsaved "
                             "changes accumulate (0=disable)")
    parser.add_argument("--multi-agent", dest="multi_agent", action="store_true",
                        help="Block global-state commands (undo/redo/restore-snapshot) "
                             "that are unsafe with concurrent clients")
    args = parser.parse_args()

    global MULTI_AGENT
    MULTI_AGENT = args.multi_agent

    _setup_environment()
    log.info("Bootstrapping idalib from %s", RUNTIME_DIR)
    import idapro

    log.info("idalib version: %s", idapro.get_library_version())
    log.info("Registered %d commands across %d handler modules",
             len(handlers.REGISTRY), len(handlers.MODULES))

    executor = MainThreadExecutor()
    set_executor(executor)

    server = ThreadedTCPServer(("127.0.0.1", args.port), CommandHandler)
    actual_port = server.server_address[1]
    log.info("TCP server listening on 127.0.0.1:%d", actual_port)

    if args.binary:
        log.info("Auto-opening: %s", args.binary)
        cmd_open({"file_path": args.binary, "run_auto_analysis": args.run_auto_analysis})
        log.info("Database opened successfully")

    # Written only after the database opened: the bridge's "Worker ready" is
    # gated on this file, and an open failure must not leave a port file
    # pointing at a worker that is about to die.
    Path(args.port_file).write_text(str(actual_port))
    log.info("Port file: %s", args.port_file)

    signal.signal(signal.SIGTERM, _terminate_handler)
    signal.signal(signal.SIGINT, _cancel_handler)
    if hasattr(signal, "SIGUSR1"):
        signal.signal(signal.SIGUSR1, lambda s, f: None)

    tracker = ActivityTracker()
    CommandHandler.tracker = tracker

    server_thread = threading.Thread(target=server.serve_forever, daemon=True, name="tcp-server")
    server_thread.start()

    idle_label = f"{args.idle_timeout}s" if args.idle_timeout > 0 else "disabled"
    autosave_label = f"{args.autosave}s" if args.autosave > 0 else "disabled"
    log.info("Worker ready. Idle timeout: %s, autosave: %s, multi-agent: %s",
             idle_label, autosave_label, MULTI_AGENT)

    try:
        while True:
            executor.drain(timeout=1.0)
            _maybe_autosave(args.autosave, tracker, executor)
            if (args.idle_timeout > 0
                    and not tracker.busy()
                    and not executor.pending()
                    and tracker.idle_seconds() > args.idle_timeout):
                log.info("Idle timeout (%ds), shutting down...", args.idle_timeout)
                break
    except (KeyboardInterrupt, SystemExit):
        log.info("Shutting down...")
    finally:
        server.shutdown()
        # Serve requests that were already in flight when the listener closed.
        grace_deadline = time.monotonic() + 10
        while (tracker.busy() or executor.pending()) and time.monotonic() < grace_deadline:
            executor.drain(timeout=0.5)
        executor.shutdown()

        if is_open():
            log.info("Saving database on shutdown: %s", ida_session.current_path)
            try:
                cmd_close({"save": True})
            except Exception:  # noqa: BLE001
                log.exception("Failed to save database on shutdown")

        try:
            Path(args.port_file).unlink(missing_ok=True)
        except Exception:  # noqa: BLE001
            pass
        log.info("Worker stopped")


def _maybe_autosave(interval: int, tracker: ActivityTracker, executor: MainThreadExecutor):
    """Flush unsaved mutations once they are older than ``interval`` seconds.

    Prefers a quiet moment (no in-flight or queued requests) so the save —
    which is a close+reopen and can take a while on large databases — doesn't
    land in the middle of a command burst, but never defers past 2x the
    interval. Runs on the main thread only.
    """
    if interval <= 0 or not is_open() or _autosave["mutations"] == 0:
        return
    elapsed = time.time() - _autosave["last_save"]
    if elapsed < interval:
        return
    if (tracker.busy() or executor.pending()) and elapsed < 2 * interval:
        return
    count = _autosave["mutations"]
    log.info("Autosave: flushing %d unsaved mutation(s)...", count)
    try:
        cmd_save({})
        log.info("Autosave complete")
    except Exception:  # noqa: BLE001
        # cmd_save failing on the reopen leg leaves the database closed —
        # subsequent commands will surface NoDatabase loudly.
        log.exception("Autosave failed")
        _autosave["last_save"] = time.time()  # back off instead of retrying every second


if __name__ == "__main__":
    main()
