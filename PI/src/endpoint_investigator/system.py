"""Único ponto de execução de comandos read-only do sistema."""

import os
import subprocess


def run_systemctl(operation: str, *arguments: str) -> subprocess.CompletedProcess:
    if operation not in {"list-units", "show"}:
        raise ValueError("Operação systemctl não permitida")
    return subprocess.run(
        ["systemctl", "--no-pager", "--no-ask-password", operation, *arguments],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=10, check=False, stdin=subprocess.DEVNULL,
        env={**os.environ, "LC_ALL": "C", "SYSTEMD_COLORS": "0"},
    )
