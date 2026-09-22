import stat
from types import SimpleNamespace as NS
from unittest.mock import Mock

import pytest

from endpoint_investigator import scan
from endpoint_investigator.collectors import permissions as collector
from endpoint_investigator.models import PermissionRecord, ProcessRecord, ServiceRecord, Snapshot
from endpoint_investigator.permissions import assess_permissions


def observed(mode=0o755, uid=0, gid=0, directory=False):
    return NS(st_mode=(stat.S_IFDIR if directory else stat.S_IFREG) | mode, st_uid=uid, st_gid=gid)


@pytest.fixture
def identity_names(monkeypatch):
    monkeypatch.setattr(collector.pwd, "getpwuid", lambda uid: NS(pw_name=f"user-{uid}"))
    monkeypatch.setattr(collector.grp, "getgrgid", lambda gid: NS(gr_name=f"group-{gid}"))


def test_selection_deduplicates_only_related_paths():
    paths, issues = collector.select_paths(
        [ProcessRecord(1, exe="/usr/bin/python3"), ProcessRecord(2, exe="/usr/bin/python3")],
        [ServiceRecord("demo.service", fragment_path="/etc/systemd/system/demo.service",
                       exec_start="{ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 /opt/demo.py ; ignore_errors=no ; }")],
    )
    assert paths == ["/etc/systemd/system/demo.service", "/opt/demo.py", "/usr/bin/python3"]
    assert not issues


@pytest.mark.parametrize("command", ["relative arg", "/bin/sh -c '/tmp/script'", "/usr/bin/python3 $SCRIPT", "{ broken }", "/usr/bin/python3 /tmp/a\\x20b"])
def test_ambiguous_command_is_not_executed_or_guessed(command):
    paths, issues = collector.select_paths([], [ServiceRecord("demo.service", exec_start=command)])
    assert paths == []
    assert issues[0].code == "unresolved_exec_start"


def test_deleted_relative_and_null_paths():
    paths, issues = collector.select_paths(
        [ProcessRecord(1), ProcessRecord(2, exe="/tmp/gone (deleted)"), ProcessRecord(3, exe="relative")], [],
    )
    assert paths == []
    assert len(issues) == 2


@pytest.mark.parametrize("mode,uid,expected", [
    (0o644, 0, False), (0o644, 1000, True), (0o664, 0, None), (0o666, 0, True), (0o444, 1000, False),
])
def test_posix_facts_and_separate_assessment(monkeypatch, identity_names, mode, uid, expected):
    source = Mock(side_effect=lambda path: observed(mode, uid, 1000) if path == "/opt/demo" else observed(directory=True))
    monkeypatch.setattr(collector.os, "stat", source)
    records, issues = collector.collect_permissions(["/opt/demo", "/opt/demo"])
    resource = next(r for r in records if r.path == "/opt/demo")
    parent = next(r for r in records if r.path == "/opt")
    before = resource.to_dict()
    assessment = assess_permissions(resource, parent)
    assert assessment.direct_write is expected
    assert assessment.replacement is False
    assert resource.to_dict() == before
    assert resource.mode == mode
    assert resource.owner_uid == uid
    assert resource.owner_name == f"user-{uid}"
    assert resource.group_name == "group-1000"
    assert resource.owner_writable == bool(mode & 0o200)
    assert resource.group_writable == bool(mode & 0o020)
    assert resource.other_writable == bool(mode & 0o002)
    assert resource.parent_mode == 0o755
    assert {call.args[0] for call in source.call_args_list} == {"/opt/demo", "/opt"}
    assert source.call_count == 2
    assert issues[-1].code == "posix_scope"
    assert len(assessment.missing_evidence) == 4
    snapshot = Snapshot(permissions=records, issues=issues)
    assert Snapshot.from_json(snapshot.to_json()) == snapshot


@pytest.mark.parametrize("mode,uid,expected", [
    (0o777, 0, True), (0o1777, 0, False), (0o1777, 1000, True),
    (0o766, 0, False), (0o775, 0, None), (0o755, 1000, True),
])
def test_parent_replacement_requires_traversal_and_respects_sticky(mode, uid, expected):
    resource = PermissionRecord("/opt/demo", exists=True, file_type="file", owner_uid=0, mode=0o644, parent_path="/opt")
    parent = PermissionRecord("/opt", exists=True, file_type="directory", owner_uid=uid, mode=mode)
    assert assess_permissions(resource, parent).replacement is expected


@pytest.mark.parametrize("error,exists,code", [
    (FileNotFoundError(), False, "not_found"),
    (NotADirectoryError(), False, "not_found"),
    (PermissionError(), None, "stat_unavailable"),
    (OSError(), None, "stat_unavailable"),
])
def test_stat_failure_keeps_next_resource(monkeypatch, identity_names, error, exists, code):
    def source(path):
        if path == "/opt/bad":
            raise error
        return observed(directory=path == "/opt")
    monkeypatch.setattr(collector.os, "stat", source)
    records, issues = collector.collect_permissions(["/opt/bad", "/opt/good"])
    bad = next(r for r in records if r.path == "/opt/bad")
    assert bad.exists is exists
    assert bad.mode is None
    assert next(r for r in records if r.path == "/opt/good").exists is True
    assert any(i.code == code and i.entity == "/opt/bad" for i in issues)
    assert assess_permissions(bad).direct_write is None


def test_parent_failure_preserves_file_mode(monkeypatch, identity_names):
    def source(path):
        if path == "/opt":
            raise PermissionError()
        return observed()
    monkeypatch.setattr(collector.os, "stat", source)
    records, _ = collector.collect_permissions(["/opt/demo"])
    resource = next(r for r in records if r.path == "/opt/demo")
    assert resource.mode == 0o755
    assert resource.parent_mode is None


def test_identity_resolution_failure_keeps_numeric_ids(monkeypatch):
    monkeypatch.setattr(collector.os, "stat", lambda path: observed())
    monkeypatch.setattr(collector.pwd, "getpwuid", Mock(side_effect=KeyError()))
    monkeypatch.setattr(collector.grp, "getgrgid", Mock(side_effect=OSError()))
    records, issues = collector.collect_permissions(["/demo"])
    assert all(r.owner_uid == r.group_gid == 0 for r in records)
    assert all(r.owner_name is None and r.group_name is None for r in records)
    assert len([i for i in issues if i.code == "identity_unresolved"]) == 4


def test_no_paths_never_stats(monkeypatch):
    source = Mock(side_effect=AssertionError("unexpected stat"))
    monkeypatch.setattr(collector.os, "stat", source)
    assert collector.collect_permissions([]) == ([], [])


def test_snapshot_includes_contextual_permissions(monkeypatch, identity_names):
    monkeypatch.setattr(scan, "collect_processes", lambda: ([ProcessRecord(42, exe="/opt/demo")], []))
    monkeypatch.setattr(scan, "collect_network", lambda: ([], []))
    monkeypatch.setattr(scan, "collect_services", lambda processes: ([ServiceRecord("demo.service", main_pid=42, exec_start="/opt/demo")], []))
    monkeypatch.setattr(collector.os, "stat", lambda path: observed(directory=path == "/opt"))
    snapshot = scan.collect_snapshot()
    assert {r.path for r in snapshot.permissions} == {"/opt", "/opt/demo"}
    assert Snapshot.from_json(snapshot.to_json()) == snapshot
