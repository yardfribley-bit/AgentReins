#!/usr/bin/env python3
"""Import every script launchd or the app runs with /usr/bin/python3.

`py_compile` is not enough: `X | Y` in a runtime alias is legal syntax and still
raises TypeError on Python 3.9. This must be executed by that interpreter.
"""
from __future__ import annotations

import importlib.util
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
MODULES = (
    "tools/socket-sampler/proc_lookup.py",
    "tools/socket-sampler/socket_sampler.py",
    "tools/agentreins-mcp/evidence.py",
    "scripts/install_socket_sampler.py",
    "Resources/agentguard-memory-scan.py",
)


def load(path: pathlib.Path) -> None:
    name = "py39_" + path.stem.replace("-", "_")
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)


def main() -> int:
    sys.path[:0] = [
        str(ROOT / "tools" / "socket-sampler"),
        str(ROOT / "tools" / "agentreins-mcp"),
        str(ROOT / "scripts"),
        str(ROOT / "Resources"),
    ]
    for rel in MODULES:
        path = ROOT / rel
        load(path)
        print("py39-import", rel)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
