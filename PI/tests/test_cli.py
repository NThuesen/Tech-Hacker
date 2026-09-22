import subprocess
import sys
import json

import pytest

from endpoint_investigator import cli
from endpoint_investigator.models import CollectionIssue, Finding, NetworkRecord, Snapshot


def test_module_help():
    result = subprocess.run(
        [sys.executable, "-m", "endpoint_investigator", "--help"],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0
    assert "Endpoint Investigator" in result.stdout
    assert "--help" in result.stdout
    assert result.stderr == ""


def test_missing_snapshot_argument_is_usage_error():
    result = subprocess.run(
        [sys.executable, "-m", "endpoint_investigator", "analyze"],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 2


def test_scan_save_and_offline_are_identical(monkeypatch, tmp_path, capsys):
    snapshot = Snapshot(sockets=[NetworkRecord(None, "tcp", "127.0.0.1", 8080, "LISTEN")],
                        issues=[CollectionIssue("services", "unavailable", "Fonte indisponível")])
    monkeypatch.setattr(cli, "collect_snapshot", lambda: snapshot)
    target = tmp_path / "snapshot.json"
    assert cli.main(["scan", "--format", "json", "--save-snapshot", str(target)]) == 0
    live = json.loads(capsys.readouterr().out)
    assert Snapshot.from_json(target.read_text()) == snapshot
    assert target.stat().st_mode & 0o777 == 0o600
    monkeypatch.setattr(cli, "collect_snapshot", lambda: pytest.fail("Offline não deve coletar"))
    assert cli.main(["analyze", str(target), "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out) == live
    assert live["summary"]["collection_status"] == "partial_or_limited"
    assert live["findings"][0]["disposition"] == "inconclusive"
    assert cli.main(["analyze", str(target)]) == 0
    output = capsys.readouterr().out
    for label in ("Evidência:", "Interpretação:", "Hipótese:", "Evidência ausente:", "Fonte indisponível"):
        assert label in output


@pytest.mark.parametrize("contents", ["not json", '{"schema_version":2}', '{"processes":"invalid"}'])
def test_bad_input_returns_execution_error(tmp_path, capsys, contents):
    target = tmp_path / "bad.json"
    target.write_text(contents)
    assert cli.main(["analyze", str(target), "--format", "json"]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "Erro de execução" in captured.err


def test_missing_input_and_existing_output(monkeypatch, tmp_path, capsys):
    target = tmp_path / "snapshot.json"
    assert cli.main(["analyze", str(target)]) == 1
    monkeypatch.setattr(cli, "collect_snapshot", Snapshot)
    target.write_text("preserve")
    assert cli.main(["scan", "--save-snapshot", str(target)]) == 1
    assert target.read_text() == "preserve"
    assert capsys.readouterr().out == ""


def test_offline_module_subprocess(tmp_path):
    target = tmp_path / "snapshot.json"
    target.write_text(Snapshot().to_json())
    result = subprocess.run([sys.executable, "-m", "endpoint_investigator", "analyze", str(target), "--format", "json"], capture_output=True, text=True)
    assert result.returncode == 0
    assert result.stderr == ""
    assert json.loads(result.stdout)["report_version"] == 1


def test_needs_review_is_not_execution_failure(monkeypatch, capsys):
    monkeypatch.setattr(cli, "collect_snapshot", Snapshot)
    finding = Finding("C1:0", "Revisar", "C1", {}, ["fato"], "interpretação", "hipótese", ["lacuna"], "needs_review")
    monkeypatch.setattr(cli, "analyze_snapshot", lambda snapshot: [finding])
    assert cli.main(["scan", "--format", "json"]) == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    assert json.loads(captured.out)["summary"]["findings"]["needs_review"] == 1
