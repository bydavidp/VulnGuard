#!/usr/bin/env python3
"""
VulnGuard — Android Security Auditor
======================================
Punto de entrada principal para la herramienta.

Uso:
    python -m src.main audit
    python -m src.main audit --html reporte.html
    python -m src.main audit --checks root_detection,selinux_status
    python -m src.main info
    python -m src.main checks
    python -m src.main --help
"""

import io
import sys

# Forzar UTF-8 en stdout para caracteres especiales en Windows
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

from src.cli import cli
from src.utils.logger import setup_logging


def main():
    """Punto de entrada principal."""
    cli()


if __name__ == "__main__":
    main()
