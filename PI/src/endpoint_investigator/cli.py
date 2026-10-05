"""CLI de coleta, análise offline e apresentação."""

import argparse
import os
from pathlib import Path
import sys

from .correlations import analyze_snapshot
from .dataset import import_dataset
from .models import Snapshot
from .reporting import build_report, render_json, render_text
from .scan import collect_snapshot


def save_snapshot(path: str, snapshot: Snapshot) -> None:
    data = snapshot.to_json()
    # Cria somente um arquivo novo; não sobrescreve dados nem segue symlink existente.
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(data + "\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="endpoint_investigator",
        description="Endpoint Investigator — investigação local sob demanda.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan", help="Coletar e analisar o host local")
    scan.add_argument("--save-snapshot", metavar="ARQUIVO", help="Salvar snapshot em arquivo novo")
    analyze = commands.add_parser("analyze", help="Analisar um snapshot JSON sem consultar o host")
    analyze.add_argument("snapshot", metavar="SNAPSHOT")
    dataset = commands.add_parser("analyze-dataset", help="Analisar dataset da disciplina sem consultar o host")
    dataset.add_argument("directory", metavar="DATASET_DIR")
    for command in (scan, analyze, dataset):
        command.add_argument("--format", choices=("text", "json"), default="text")
    args = parser.parse_args(argv)
    try:
        if args.command == "scan":
            snapshot = collect_snapshot()
        elif args.command == "analyze-dataset":
            snapshot = import_dataset(args.directory)
        else:
            snapshot = Snapshot.from_json(Path(args.snapshot).read_text(encoding="utf-8"))
        report = build_report(snapshot, analyze_snapshot(snapshot))
        if args.command == "scan" and args.save_snapshot:
            save_snapshot(args.save_snapshot, snapshot)
        print(render_json(report) if args.format == "json" else render_text(report))
    except (OSError, ValueError) as error:
        print(f"Erro de execução: {error}", file=sys.stderr)
        return 1
    return 0
