import socket
from types import SimpleNamespace as NS
from unittest.mock import Mock

import psutil
import pytest

from endpoint_investigator.collectors import network, processes
from endpoint_investigator.models import Snapshot
from endpoint_investigator.scan import collect_snapshot


@pytest.fixture(autouse=True)
def isolate_service_source(monkeypatch):
    monkeypatch.setattr("endpoint_investigator.scan.collect_services", lambda processes: ([], []))
    monkeypatch.setattr("endpoint_investigator.scan.collect_permissions", lambda paths: ([], []))


def process(pid=42):
    return NS(
        pid=pid, is_running=Mock(return_value=True),
        ppid=Mock(return_value=1), name=Mock(return_value="malware-looking-name"),
        username=Mock(return_value="root"), uids=Mock(return_value=NS(real=1000, effective=0)),
        gids=Mock(return_value=NS(real=1000, effective=0)), status=Mock(return_value="sleeping"),
        cmdline=Mock(return_value=["/opt/demo", "ação"]), exe=Mock(return_value="/opt/demo"),
    )


def connection(kind=socket.SOCK_STREAM, status=psutil.CONN_LISTEN, pid=42, remote=(), family=socket.AF_INET):
    return NS(type=kind, status=status, pid=pid, family=family,
              laddr=NS(ip="::" if family == socket.AF_INET6 else "127.0.0.1", port=8080), raddr=remote)


def test_process_normalization(monkeypatch):
    monkeypatch.setattr(processes.psutil, "process_iter", lambda: iter([process()]))
    records, issues = processes.collect_processes()
    assert not issues
    assert records[0].to_dict() == dict(pid=42, ppid=1, name="malware-looking-name", username="root",
                                      uid=0, gid=0, status="sleeping", cmdline=["/opt/demo", "ação"], exe="/opt/demo")


@pytest.mark.parametrize("error,code", [(psutil.AccessDenied(42), "access_denied"),
                                       (psutil.ZombieProcess(42), "zombie_process"),
                                       (OSError("unavailable"), "os_error")])
def test_field_failure_preserves_other_fields_and_next_process(monkeypatch, error, code):
    first = process()
    first.exe.side_effect = error
    monkeypatch.setattr(processes.psutil, "process_iter", lambda: iter([first, process(43)]))
    records, issues = processes.collect_processes()
    assert records[0].exe is None
    assert records[0].uid == 0
    assert records[1].exe == "/opt/demo"
    assert (issues[0].code, issues[0].entity, issues[0].field) == (code, "42", "exe")


@pytest.mark.parametrize("phase", ["before", "during", "after"])
def test_process_race_never_aborts_next_process(monkeypatch, phase):
    first = process()
    if phase == "during":
        first.cmdline.side_effect = psutil.NoSuchProcess(42)
    else:
        first.is_running.side_effect = [False] if phase == "before" else [True, False]
    monkeypatch.setattr(processes.psutil, "process_iter", lambda: iter([first, process(43)]))
    records, issues = processes.collect_processes()
    assert records[0].uid is None
    assert records[1].pid == 43
    assert issues[0].code == "process_disappeared"


def test_empty_executable_is_unknown(monkeypatch):
    item = process()
    item.exe.return_value = ""
    monkeypatch.setattr(processes.psutil, "process_iter", lambda: iter([item]))
    records, issues = processes.collect_processes()
    assert records[0].exe is None
    assert issues[0].field == "exe"


def test_enumeration_failure_keeps_observations(monkeypatch):
    def partial():
        yield process()
        raise psutil.AccessDenied()
    monkeypatch.setattr(processes.psutil, "process_iter", partial)
    records, issues = processes.collect_processes()
    assert len(records) == 1
    assert issues[0].code == "enumeration_failed"


def test_network_filters_and_preserves_pid(monkeypatch):
    source = Mock(return_value=[
        connection(), connection(family=socket.AF_INET6, pid=None),
        connection(status=psutil.CONN_ESTABLISHED, remote=("example", 443)),
        connection(kind=socket.SOCK_DGRAM, status=psutil.CONN_NONE),
        connection(kind=socket.SOCK_DGRAM, status=psutil.CONN_NONE, remote=("example", 53)),
        connection(family=socket.AF_UNIX),
    ])
    monkeypatch.setattr(network.psutil, "net_connections", source)
    monkeypatch.setattr(network.os, "geteuid", lambda: 1000)
    records, issues = network.collect_network()
    source.assert_called_once_with(kind="inet")
    assert [(r.protocol, r.pid, r.status) for r in records] == [("tcp", 42, "LISTEN"), ("tcp", None, "LISTEN"), ("udp", 42, "NONE")]
    assert records[1].local_address == "::"
    assert {i.code for i in issues} == {"visibility_limited", "pid_unavailable"}


def test_socket_without_local_address_is_ignored():
    item = connection()
    item.laddr = ()
    assert network.normalize_listener(item) is None


@pytest.mark.parametrize("error,code", [(psutil.AccessDenied(), "access_denied"), (OSError(), "collection_failed")])
def test_network_failure_returns_issue(monkeypatch, error, code):
    monkeypatch.setattr(network.psutil, "net_connections", Mock(side_effect=error))
    monkeypatch.setattr(network.os, "geteuid", lambda: 0)
    records, issues = network.collect_network()
    assert records == []
    assert issues[0].code == code


def test_snapshot_composes_partial_collectors_and_round_trips(monkeypatch):
    item = process()
    item.exe.side_effect = psutil.AccessDenied(42)
    monkeypatch.setattr(processes.psutil, "process_iter", lambda: iter([item]))
    monkeypatch.setattr(network.psutil, "net_connections", Mock(return_value=[connection()]))
    monkeypatch.setattr(network.os, "geteuid", lambda: 0)
    snapshot = collect_snapshot()
    assert snapshot.processes[0].pid == snapshot.sockets[0].pid
    assert snapshot.issues[0].field == "exe"
    assert snapshot.metadata.collected_at.endswith("+00:00")
    assert snapshot.services == snapshot.permissions == []
    assert Snapshot.from_json(snapshot.to_json()) == snapshot


def test_process_source_failure_does_not_prevent_network(monkeypatch):
    monkeypatch.setattr(processes.psutil, "process_iter", Mock(side_effect=OSError()))
    monkeypatch.setattr(network.psutil, "net_connections", Mock(return_value=[connection()]))
    monkeypatch.setattr(network.os, "geteuid", lambda: 0)
    snapshot = collect_snapshot()
    assert snapshot.processes == []
    assert len(snapshot.sockets) == 1
    assert snapshot.issues[0].severity == "error"
