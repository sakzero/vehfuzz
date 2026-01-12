#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path


def _bootstrap_src_path() -> None:
    project_root = Path(__file__).resolve().parents[1]
    src_dir = project_root / "src"
    sys.path.insert(0, str(src_dir))


def main() -> int:
    _bootstrap_src_path()
    from vehfuzz.core.cli import main as cli_main

    return cli_main()


if __name__ == "__main__":
    raise SystemExit(main())

