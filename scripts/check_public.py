#!/usr/bin/env python3
"""Fail if Git would publish private or proprietary IDA payloads."""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MAX_TRACKED_SIZE = 5 * 1024 * 1024
BLOCKED_SUFFIXES = {
    ".dll", ".dylib", ".exe", ".hexlic", ".pyd", ".pyc", ".so", ".til",
}
PRIVATE_PATH_PATTERNS = (
    re.compile(("/" + "Users" + r"/[^/\s]+/").encode()),
    re.compile((r"[A-Za-z]:\\" + "Users" + r"\\[^\\\s]+\\").encode(), re.IGNORECASE),
    re.compile(("/" + "home" + r"/[^/\s]+/").encode()),
)


def tracked_files() -> list[Path]:
    result = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files", "-z"],
        check=False,
        capture_output=True,
    )
    if result.returncode != 0:
        print("ERROR: public-safety check requires a Git worktree", file=sys.stderr)
        raise SystemExit(1)
    return [ROOT / path.decode() for path in result.stdout.split(b"\0") if path]


def main() -> int:
    problems: list[str] = []
    for path in tracked_files():
        relative = path.relative_to(ROOT)
        parts = relative.parts
        if parts[0] == "bin":
            problems.append(f"proprietary/private payload path: {relative}")
            continue
        if ".DS_Store" in parts or "__pycache__" in parts:
            problems.append(f"generated artifact: {relative}")
        if path.suffix.lower() in BLOCKED_SUFFIXES:
            problems.append(f"blocked binary/license extension: {relative}")
        if path.stat().st_size > MAX_TRACKED_SIZE:
            problems.append(f"tracked file exceeds 5 MiB: {relative}")
        try:
            content = path.read_bytes()
        except OSError as error:
            problems.append(f"cannot inspect {relative}: {error}")
            continue
        if any(pattern.search(content) for pattern in PRIVATE_PATH_PATTERNS):
            problems.append(f"private absolute path: {relative}")

    if problems:
        print("Public-safety check failed:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1
    print("Public-safety check passed: no tracked IDA payloads, licenses, or private paths.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
