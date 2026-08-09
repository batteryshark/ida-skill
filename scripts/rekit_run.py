#!/usr/bin/env python3
"""Factory-safe IDA entry: start the private bridge and return a read-only summary."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("target", type=Path)
    parser.add_argument("--format", choices=("json",), default="json")
    args = parser.parse_args()
    target = args.target.expanduser().resolve()
    if not target.is_file():
        print(json.dumps({"ok": False, "error": "target must be an existing file"}))
        return 2
    here = Path(__file__).resolve().parent
    start = subprocess.run(
        ["node", str(here / "bridge.mjs"), "start", "--binary", str(target)],
        cwd=here.parent, capture_output=True, text=True, timeout=360,
    )
    if start.returncode:
        print(json.dumps({"ok": False, "error": "IDA bridge failed to start",
                          "detail": (start.stderr or start.stdout)[-2000:]}))
        return start.returncode
    info = subprocess.run(
        ["python3", str(here / "cli.py"), "info", "--binary", str(target), "--raw"],
        cwd=here.parent, capture_output=True, text=True, timeout=360,
        env={**os.environ, "IDA_SKILL_ALLOW_JSON": "1"},
    )
    if info.returncode:
        print(json.dumps({"ok": False, "error": "IDA summary failed",
                          "detail": (info.stderr or info.stdout)[-2000:]}))
        return info.returncode
    try:
        payload = json.loads(info.stdout)
    except json.JSONDecodeError:
        payload = {"output": info.stdout.strip()}
    print(json.dumps({"ok": True, "engine": "ida", "target": target.name,
                      "summary": payload}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
