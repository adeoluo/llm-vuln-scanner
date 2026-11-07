"""Entrypoint: `python -m llm_vuln_scanner`."""

from __future__ import annotations

from llm_vuln_scanner import __version__
from llm_vuln_scanner.configuration import settings


def main() -> None:
    header = f"Llm Vuln Scanner v{__version__}"
    status = f"environment={settings.environment}, seed={settings.seed}"
    print(f"{header} - {status}")


if __name__ == "__main__":
    main()
