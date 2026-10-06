"""Cenários sintéticos completos atravessando a CLI e seus dois formatos."""

import json
from pathlib import Path
import socket
import subprocess
import sys

import pytest

from endpoint_investigator import cli
from endpoint_investigator.models import Snapshot


FIXTURES = Path(__file__).parent / "fixtures"
EXPECTED = {
    "normal": [("C3", "informational")],
    "unsafe_service": [("C1", "needs_review"), ("C3", "informational")],
    "listener": [("C2", "informational"), ("C3", "informational"), ("C3", "informational")],
    "partial": [("C1", "inconclusive"), ("C2", "inconclusive"), ("C3", "inconclusive")],
}


@pytest.mark.parametrize("name", EXPECTED)
def test_scenario_end_to_end(name):
    path = FIXTURES / f"scenario_{name}.json"
    original = path.read_bytes()
    source = Snapshot.from_json(original.decode())
    command = [sys.executable, "-m", "endpoint_investigator", "analyze", str(path)]
    result = subprocess.run(command + ["--format", "json"], capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    assert not result.stderr
    report = json.loads(result.stdout)
    assert report["snapshot"] == source.to_dict()
    assert [(f["correlation"], f["disposition"]) for f in report["findings"]] == EXPECTED[name]
    assert report["summary"]["findings"]["needs_review"] == (1 if name == "unsafe_service" else 0)
    assert report["summary"]["collection_status"] == ("partial_or_limited" if name == "partial" else "no_reported_issues")
    for finding in report["findings"]:
        assert all(finding[key] for key in ("entities", "evidence", "interpretation", "hypothesis", "missing_evidence"))
        for path_ref in finding["entities"].get("permissions", []):
            assert path_ref in {p.path for p in source.permissions}
    text = subprocess.run(command, capture_output=True, text=True, timeout=15)
    assert text.returncode == 0 and not text.stderr
    for explanation in (
        "informational: contexto observável útil; não afirma vulnerabilidade.",
        "inconclusive: faltam evidências necessárias para avaliar a relação investigada.",
        "needs_review: evidência concreta sustenta uma relação potencialmente insegura",
        "IDs como C1:1 são identificadores técnicos, não níveis de risco.",
    ):
        assert explanation in text.stdout
    for finding in report["findings"]:
        kind = {"C1": "services", "C2": "sockets", "C3": "processes"}[finding["correlation"]]
        assert (f"ID técnico: {finding['id']}\nCorrelação: {finding['correlation']}\n"
                f"Entidade principal: {kind}={finding['entities'][kind][0]}\n"
                f"Disposition: {finding['disposition']}") in text.stdout
    for label in ("Evidência:", "Interpretação:", "Hipótese:", "Evidência ausente:"):
        assert label in text.stdout
    if name == "unsafe_service":
        assert "0o777" in text.stdout and "/opt/demo/worker" in text.stdout
    if name == "listener":
        c2 = report["findings"][0]
        assert c2["entities"]["services"] == ["demo.service"]
        assert c2["entities"]["processes"] == ["43", "42"]
        assert any("association=descendant_of_main_pid" in e for e in c2["evidence"])
        assert any("43 -> 42" in e for e in c2["evidence"])
        assert "descendant_of_main_pid" in text.stdout and "43 -> 42" in text.stdout
        assert "não prova de membership" in text.stdout
    if name == "partial":
        assert "parcial ou com limitações" in text.stdout
    assert path.read_bytes() == original


@pytest.mark.parametrize("name", EXPECTED)
def test_offline_scenarios_do_not_collect_or_connect(name, monkeypatch, capsys):
    def forbidden(*args, **kwargs):
        pytest.fail("A análise offline tentou coletar, executar comando ou abrir socket")
    monkeypatch.setattr(cli, "collect_snapshot", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    assert cli.main(["analyze", str(FIXTURES / f"scenario_{name}.json"), "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["report_version"] == 1
