"""Entrypoint: ``python -m llm_vuln_scanner``."""

from __future__ import annotations

import sys

from llm_vuln_scanner.cli import main

if __name__ == "__main__":
    sys.exit(main())
