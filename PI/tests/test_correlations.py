import pytest

from endpoint_investigator.correlations import analyze_snapshot
from endpoint_investigator.models import (
    CollectionIssue, Finding, NetworkRecord, PermissionRecord, ProcessRecord, ServiceRecord, Snapshot,
)


def sample(mode=0o644, owner=0):
    return Snapshot(
        processes=[ProcessRecord(1, uid=0), ProcessRecord(42, ppid=1, uid=0, exe="/opt/demo")],
        services=[ServiceRecord("demo.service", active_state="active", main_pid=42, exec_start="/opt/demo")],
        permissions=[PermissionRecord("/opt/demo", exists=True, file_type="file", owner_uid=owner, group_gid=0, mode=mode, parent_path="/opt", parent_mode=0o755),
                     PermissionRecord("/opt", exists=True, file_type="directory", owner_uid=0, group_gid=0, mode=0o755)],
    )


def findings(snapshot, correlation):
    return [f for f in analyze_snapshot(snapshot) if f.correlation == correlation]


@pytest.mark.parametrize("mode,owner", [(0o666, 0), (0o644, 1000)])
def test_c1_privileged_and_writable_requires_review(mode, owner):
    result = findings(sample(mode, owner), "C1")
    assert len(result) == 1
    assert result[0].disposition == "needs_review"
    assert result[0].entities["permissions"] == ["/opt/demo", "/opt"]
    assert any("owner_uid=" in e and "mode=" in e for e in result[0].evidence)


def test_root_and_safe_permissions_do_not_trigger_c1():
    assert findings(sample(), "C1") == []


@pytest.mark.parametrize("change", ["nonroot", "inactive", "unrelated"])
def test_c1_negative_contexts(change):
    snapshot = sample(0o666)
    if change == "nonroot":
        snapshot.processes[1].uid = 1000
    elif change == "inactive":
        snapshot.services[0].active_state = "inactive"
    else:
        snapshot = sample()
        snapshot.permissions.append(PermissionRecord("/unrelated", exists=True, file_type="file", mode=0o777, owner_uid=1000))
    assert findings(snapshot, "C1") == []


@pytest.mark.parametrize("change", ["uid", "process", "permissions", "parent", "group", "state", "missing_file"])
def test_c1_inconclusive(change):
    snapshot = sample()
    if change == "uid":
        snapshot.processes[1].uid = None
    elif change == "process":
        snapshot.processes = []
        snapshot.services[0].configured_user = "root"
    elif change == "permissions":
        snapshot.permissions = []
    elif change == "parent":
        snapshot.permissions.pop()
    elif change == "group":
        snapshot.permissions[0].mode = 0o664
    elif change == "state":
        snapshot.services[0].active_state = None
    else:
        snapshot.permissions[0].exists = False
    assert findings(snapshot, "C1")[0].disposition == "inconclusive"


def test_c1_parent_replacement_and_sticky():
    snapshot = sample()
    snapshot.permissions[1].mode = 0o777
    assert findings(snapshot, "C1")[0].disposition == "needs_review"
    snapshot.permissions[1].mode = 0o1777
    assert findings(snapshot, "C1") == []


def test_c1_resolves_script_and_unit_context():
    snapshot = sample()
    snapshot.services[0].exec_start = "/usr/bin/python3 /opt/script.py"
    snapshot.services[0].fragment_path = "/etc/demo.service"
    snapshot.permissions.extend([
        PermissionRecord(path, exists=True, file_type="file", mode=0o666, owner_uid=0)
        for path in ["/opt/script.py", "/etc/demo.service"]
    ])
    result = findings(snapshot, "C1")[0]
    assert result.disposition == "needs_review"
    assert {"/opt/script.py", "/etc/demo.service"} <= set(result.entities["permissions"])


def test_c2_root_listener_is_only_context():
    snapshot = sample()
    snapshot.sockets = [NetworkRecord(42, "tcp", "0.0.0.0", 22, "LISTEN")]
    result = findings(snapshot, "C2")[0]
    assert result.disposition == "informational"
    assert result.entities["services"] == ["demo.service"]
    assert "0.0.0.0" in result.evidence[0]
    assert "não demonstra vulnerabilidade" in result.hypothesis


@pytest.mark.parametrize("change", ["pid", "process", "uid", "service", "address"])
def test_c2_incomplete_context(change):
    snapshot = sample()
    snapshot.sockets = [NetworkRecord(42, "tcp", "127.0.0.1", 80, "LISTEN")]
    if change == "pid":
        snapshot.sockets[0].pid = None
    elif change == "process":
        snapshot.processes = []
    elif change == "uid":
        snapshot.processes[1].uid = None
    elif change == "service":
        snapshot.services = []
    else:
        snapshot.sockets[0].local_address = None
    assert findings(snapshot, "C2")[0].disposition == "inconclusive"


def test_c2_udp_and_non_listener():
    snapshot = sample()
    snapshot.sockets = [NetworkRecord(42, "udp", "::", 53, "NONE"), NetworkRecord(42, "tcp", "::1", 80, "ESTABLISHED")]
    result = findings(snapshot, "C2")
    assert len(result) == 1
    assert "não prova função de servidor" in result[0].interpretation


def test_c3_relevant_processes_only_and_deduplicated():
    snapshot = sample()
    snapshot.processes.append(ProcessRecord(999, ppid=1, uid=0, name="malware"))
    snapshot.sockets = [NetworkRecord(42, "tcp", "::", 80, "LISTEN")]
    result = findings(snapshot, "C3")
    assert len(result) == 1
    assert result[0].entities["processes"] == ["42", "1"]
    assert result[0].disposition == "informational"


@pytest.mark.parametrize("change", ["parent", "uid", "self_parent"])
def test_c3_inconclusive(change):
    snapshot = sample()
    if change == "parent":
        snapshot.processes.pop(0)
    elif change == "uid":
        snapshot.processes[0].uid = None
    else:
        snapshot.processes[1].ppid = 42
    assert findings(snapshot, "C3")[0].disposition == "inconclusive"


def test_names_do_not_control_disposition():
    snapshot = sample()
    original = [(f.correlation, f.disposition) for f in analyze_snapshot(snapshot)]
    snapshot.processes[1].name = "malware"
    snapshot.services[0].unit = "ransomware.service"
    assert [(f.correlation, f.disposition) for f in analyze_snapshot(snapshot)] == original
    assert analyze_snapshot(Snapshot(processes=[ProcessRecord(123, name="malware", uid=0)])) == []


def test_findings_preserve_layers_and_snapshot_and_issues():
    snapshot = sample(0o666)
    snapshot.sockets = [NetworkRecord(42, "tcp", "::", 80, "LISTEN")]
    snapshot.issues = [CollectionIssue("permissions", "stat_unavailable", "Observação parcial", "/opt/demo")]
    before = snapshot.to_json()
    results = analyze_snapshot(snapshot)
    assert {f.correlation for f in results} == {"C1", "C2", "C3"}
    assert len({f.id for f in results}) == len(results)
    assert results == analyze_snapshot(Snapshot.from_json(before))
    assert snapshot.to_json() == before
    for finding in results:
        assert finding.evidence and finding.interpretation and finding.hypothesis and finding.missing_evidence
        assert Finding.from_json(finding.to_json()) == finding
    assert any("stat_unavailable" in gap for gap in results[0].missing_evidence)
