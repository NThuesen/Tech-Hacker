"""Contrato offline do generator, guardrails e integração com a CLI existente."""

import argparse
import csv
import io
import json
import os
from pathlib import Path
import pwd
import grp
import socket
import subprocess
import sys

import psutil
import pytest

from endpoint_investigator import cli, scan, system
from endpoint_investigator.collectors import network, permissions, processes, services
from endpoint_investigator.correlations import analyze_snapshot
from endpoint_investigator.dataset import import_dataset, parse_dataset
from endpoint_investigator.models import Finding, Snapshot


ROOT = Path(__file__).resolve().parents[1]
META = json.dumps(dict(dataset_type="synthetic_training", level="intermediate",
                       scenario="test", seed=5, generated_at="2026-10-05", warning="synthetic"))
PROC = "timestamp,pid,ppid,user,stat,cmd\nt,1,0,root,Ss,/sbin/init\nt,42,1,root,S,/bin/bash /opt/test/run.sh\n"
PERM = "path,type,owner,group,mode,mtime\n/opt/test,directory,root,root,0755,t\n/opt/test/run.sh,file,root,root,0777,t\n"
SERV = "UNIT ACTIVE USER EXECSTART\ntest.service running root /bin/bash /opt/test/run.sh\n"


def parse(proc=PROC, perm=PERM, serv=SERV, meta=META):
    return parse_dataset(proc, perm, serv, meta)


def test_valid_normalization_and_provenance():
    snapshot = parse()
    assert Snapshot.from_json(snapshot.to_json()) == snapshot
    assert snapshot.services[0].main_pid == 42
    assert snapshot.services[0].active_state == "active"
    assert snapshot.services[0].fragment_path is None
    assert snapshot.processes[1].exe == "/bin/bash"
    assert snapshot.processes[1].cmdline == ["/bin/bash", "/opt/test/run.sh"]
    assert snapshot.processes[1].gid is None
    assert snapshot.permissions[1].mode == 0o777
    assert snapshot.permissions[1].parent_path == "/opt/test"
    assert snapshot.permissions[1].parent_mode == 0o755
    assert snapshot.permissions[0].parent_path is None
    assert snapshot.metadata.collected_at is None
    assert not snapshot.sockets
    finding = next(f for f in analyze_snapshot(snapshot) if f.correlation == "C1")
    assert finding.disposition == "needs_review"
    assert any("main_pid_inferred" in gap for gap in finding.missing_evidence)


def test_nonroot_identity_does_not_use_local_ids():
    snapshot = parse(PROC.replace(",root,", ",aluno,"), PERM.replace(",root,root,", ",aluno,staff,"))
    assert all(p.uid is None and p.gid is None and p.username == "aluno" for p in snapshot.processes)
    assert all(p.owner_uid is None and p.group_gid is None for p in snapshot.permissions)
    assert snapshot.permissions[0].owner_name == "aluno"
    assert snapshot.permissions[0].group_name == "staff"
    assert all(f.disposition != "needs_review" for f in analyze_snapshot(snapshot))


@pytest.mark.parametrize("proc,serv", [
    (PROC + "t,43,1,root,S,/bin/bash /opt/test/run.sh\n", SERV),
    (PROC, SERV.replace("/bin/bash /opt", "/bin/bash  /opt")),
    (PROC, SERV.replace("run.sh", "other.sh")),
])
def test_ambiguous_or_inexact_commands_are_not_guessed(proc, serv):
    snapshot = parse(proc=proc, serv=serv)
    assert snapshot.services[0].main_pid is None
    assert any(i.code == "main_pid_unresolved" for i in snapshot.issues)
    assert all(f.disposition == "inconclusive" for f in analyze_snapshot(snapshot))


@pytest.mark.parametrize("kwargs", [
    {"proc": "bad header"}, {"perm": "bad header"}, {"serv": "bad header"},
    {"proc": PROC + "t,42,1,root,S,/bin/other\n"},
    {"proc": PROC.replace(",42,", ",-1,")},
    {"proc": PROC + "t,3\n"},
    {"proc": PROC + 't,3,1,root,S,"unterminated'},
    {"perm": PERM.replace("0777", "0999")},
    {"perm": PERM.replace("/opt/test/run.sh", "relative")},
    {"perm": PERM + "/opt/test,directory,root,root,0755,t\n"},
    {"serv": SERV + "incomplete\n"}, {"serv": SERV + SERV.splitlines()[1]},
    {"meta": "{"}, {"meta": "[]"}, {"meta": "{}"},
    {"meta": META.replace('"seed": 5', '"seed": true')},
])
def test_malformed_inputs_rejected(kwargs):
    with pytest.raises(ValueError):
        parse(**kwargs)


def test_unknown_state_and_non_directory_parent_remain_unknown():
    snapshot = parse(perm=PERM.replace("directory", "file"), serv=SERV.replace("running", "mystery"))
    assert snapshot.permissions[1].parent_path is None
    assert snapshot.services[0].active_state is None
    assert analyze_snapshot(snapshot)[0].disposition == "inconclusive"


@pytest.mark.parametrize("command", ['/bin/bash -c "touch /tmp/not-executed"',
                                      '/bin/echo $(id)', 'relative arg', '"unclosed'])
def test_commands_are_data(command):
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["timestamp", "pid", "ppid", "user", "stat", "cmd"])
    writer.writerow(["t", "42", "1", "root", "S", command])
    snapshot = parse(proc=output.getvalue(), serv="UNIT ACTIVE USER EXECSTART\n")
    assert snapshot.processes[0].pid == 42
    if command != '/bin/bash -c "touch /tmp/not-executed"':
        assert snapshot.processes[0].exe is None


@pytest.mark.parametrize("missing", ["processes.csv", "permissions.csv", "services.txt", "metadata.json"])
def test_missing_files_cli_error(tmp_path, capsys, missing):
    for name, text in zip(("processes.csv", "permissions.csv", "services.txt", "metadata.json"),
                          (PROC, PERM, SERV, META)):
        if name != missing:
            (tmp_path / name).write_text(text)
    assert cli.main(["analyze-dataset", str(tmp_path)]) == 1
    output = capsys.readouterr()
    assert not output.out
    assert "Erro de execução" in output.err


def test_malformed_cli_error(tmp_path, capsys):
    for name in ("processes.csv", "permissions.csv", "services.txt", "metadata.json"):
        (tmp_path / name).write_text("invalid")
    assert cli.main(["analyze-dataset", str(tmp_path)]) == 1
    output = capsys.readouterr()
    assert not output.out and "Erro de execução" in output.err


@pytest.mark.parametrize("seed,expected", [(5, "needs_review"), (1, "inconclusive"), (2, None)])
def test_real_generator_end_to_end(tmp_path, seed, expected):
    result = subprocess.run([sys.executable, str(ROOT / "tools/generate_dataset.py"),
                             "--level", "intermediate", "--seed", str(seed), "--output", str(tmp_path)],
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    before = {p.name: p.read_bytes() for p in tmp_path.iterdir()}
    snapshot = import_dataset(tmp_path)
    findings = analyze_snapshot(snapshot)
    backup = [f for f in findings if f.correlation == "C1" and "backup-agent.service" in f.entities["services"]]
    if expected:
        assert len(backup) == 1 and backup[0].disposition == expected
        service = next(s for s in snapshot.services if s.unit == "backup-agent.service")
        assert service.main_pid == 2417
    else:
        assert not backup
        assert all("/opt/reports/report.sh" not in f.entities.get("permissions", []) for f in findings)
    assert sum(f.disposition == "needs_review" for f in findings) == (seed == 5)
    assert not any(f.correlation == "C2" for f in findings)
    if seed == 5:
        cron = next(f for f in findings if f.correlation == "C1" and f.entities["services"] == ["cron.service"])
        assert cron.id == "C1:1" and cron.disposition == "inconclusive"
        assert "relação de escrita/privilégio não pôde ser avaliada" in cron.interpretation
        assert "Permissões não observadas: /usr/sbin/cron" in cron.interpretation
        assert "evidências faltantes" in cron.hypothesis
        assert "código modificado pode executar" not in cron.hypothesis
        assert backup[0].id == "C1:2"
        assert "/opt/backup/backup.sh (modo 0777, owner_uid=0)" in backup[0].interpretation
        assert "Se o recurso puder ser alterado" in backup[0].hypothesis
        assert "código modificado pode executar com privilégios elevados" in backup[0].hypothesis
        assert "Alteração e exploração não foram demonstradas" in backup[0].hypothesis
        assert cron.hypothesis != backup[0].hypothesis
    for fmt in ("text", "json"):
        result = subprocess.run([sys.executable, "-m", "endpoint_investigator", "analyze-dataset",
                                 str(tmp_path), "--format", fmt], capture_output=True, text=True, timeout=15)
        assert result.returncode == 0 and not result.stderr
        if fmt == "json":
            report = json.loads(result.stdout)
            assert report["snapshot"] == snapshot.to_dict()
            assert report["findings"] == [f.to_dict() for f in findings]
            assert report["report_version"] == report["snapshot"]["schema_version"] == 1
            for item in report["findings"]:
                assert set(item) == {"id", "title", "correlation", "entities", "evidence",
                                     "interpretation", "hypothesis", "missing_evidence", "disposition"}
                assert Finding.from_dict(item).to_dict() == item
            if seed == 5:
                assert report["summary"]["findings"] == {"informational": 3, "needs_review": 1, "inconclusive": 2}
                assert [(f["id"], f["disposition"]) for f in report["findings"]] == [
                    ("C1:0", "inconclusive"), ("C1:1", "inconclusive"), ("C1:2", "needs_review"),
                    ("C3:612", "informational"), ("C3:821", "informational"), ("C3:2417", "informational"),
                ]
        else:
            for label in ("Evidência:", "Interpretação:", "Hipótese:", "Evidência ausente:"):
                assert label in result.stdout
            if seed == 5:
                assert "Dispositions são estados da investigação/evidência, não níveis de risco" in result.stdout
                for finding in (cron, backup[0]):
                    assert (f"ID técnico: {finding.id}\nCorrelação: C1\n"
                            f"Entidade principal: services={finding.entities['services'][0]}\n"
                            f"Disposition: {finding.disposition}") in result.stdout
                    assert "Interpretação: " + finding.interpretation in result.stdout
                    assert "Hipótese: " + finding.hypothesis in result.stdout
    assert before == {p.name: p.read_bytes() for p in tmp_path.iterdir()}


def test_dataset_never_consults_host(monkeypatch, tmp_path, capsys):
    for name, text in zip(("processes.csv", "permissions.csv", "services.txt", "metadata.json"),
                          (PROC, PERM, SERV, META)):
        (tmp_path / name).write_text(text)
    def forbidden(*args, **kwargs):
        raise AssertionError("Consulta ao host proibida")
    with monkeypatch.context() as patch:
        # argparse/gettext consulta catálogos de tradução via stat, fora da análise.
        patch.setattr(argparse, "_", lambda text: text)
        for module, names in (
            (cli, ["collect_snapshot"]), (scan, ["collect_snapshot", "collect_processes", "collect_services", "collect_network", "collect_permissions"]),
            (processes, ["collect_processes"]), (services, ["collect_services"]),
            (permissions, ["collect_permissions"]), (network, ["collect_network"]),
            (system, ["run_systemctl"]), (psutil, ["process_iter", "Process", "net_connections"]),
            (os, ["stat", "lstat", "system"]), (pwd, ["getpwnam", "getpwuid"]),
            (grp, ["getgrnam", "getgrgid"]), (socket, ["socket", "gethostname"]),
            (subprocess, ["run", "Popen"]),
        ):
            for name in names:
                patch.setattr(module, name, forbidden)
        assert cli.main(["analyze-dataset", str(tmp_path), "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["findings"][0]["disposition"] == "needs_review"
