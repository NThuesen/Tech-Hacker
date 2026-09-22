import json

import pytest

from endpoint_investigator.models import (
    CollectionIssue,
    CollectionMetadata,
    Finding,
    NetworkRecord,
    PermissionRecord,
    ProcessRecord,
    ServiceRecord,
    Snapshot,
)


def test_complete_snapshot_round_trip():
    snapshot = Snapshot(
        metadata=CollectionMetadata("2026-09-22T12:00:00Z", "test-host", "Linux"),
        processes=[ProcessRecord(42, 1, "demo", "root", 0, 0, "sleeping", ["/opt/demo", "ação"], "/opt/demo")],
        services=[ServiceRecord("demo.service", "active", "running", 42, "root", "root", "/etc/systemd/system/demo.service", "/opt/demo")],
        sockets=[NetworkRecord(42, "tcp", "127.0.0.1", 8080, "LISTEN")],
        permissions=[PermissionRecord("/opt/demo", True, "file", 0, "root", 0, "root", 0o755, True, False, False, "/opt", 0o755)],
    )
    restored = Snapshot.from_json(snapshot.to_json())
    assert restored == snapshot
    assert isinstance(restored.processes[0], ProcessRecord)
    assert isinstance(restored.metadata, CollectionMetadata)
    assert restored.permissions[0].other_writable is False
    assert json.loads(snapshot.to_json())["processes"][0]["uid"] == 0


def test_partial_snapshot_preserves_unknown_and_missing_values():
    snapshot = Snapshot(
        processes=[ProcessRecord(42)],
        sockets=[NetworkRecord(protocol="udp", local_port=53)],
        permissions=[PermissionRecord("/missing", exists=False), PermissionRecord("/denied")],
        issues=[
            CollectionIssue("processes", "access_denied", "Executável inacessível", "42", "exe"),
            CollectionIssue("services", "unavailable", "systemd indisponível", severity="error"),
        ],
    )
    data = json.loads(snapshot.to_json())
    assert data["processes"][0]["exe"] is None
    assert data["permissions"][0]["exists"] is False
    assert data["permissions"][1]["exists"] is None
    assert Snapshot.from_json(snapshot.to_json()) == snapshot


def test_empty_snapshots_do_not_share_mutable_defaults():
    first, second = Snapshot(), Snapshot()
    first.processes.append(ProcessRecord(1))
    assert second.processes == []
    assert Snapshot.from_json(second.to_json()) == second


@pytest.mark.parametrize("disposition", ["informational", "needs_review", "inconclusive"])
def test_finding_round_trip_keeps_investigation_layers(disposition):
    finding = Finding(
        "test-1", "Contexto de teste", "C1", {"processes": ["42"]},
        ["UID observado: 0"], "Identidade privilegiada",
        "Contexto a investigar", ["Permissões não observadas"], disposition,
    )
    assert Finding.from_json(finding.to_json()) == finding


@pytest.mark.parametrize("data", [
    [],
    {"schema_version": 2},
    {"schema_version": True},
    {"unexpected": "ignored?"},
    {"processes": [{"pid": "42"}]},
    {"processes": [{"pid": True}]},
    {"processes": [{}]},
    {"processes": None},
    {"permissions": [{"path": "/demo", "exists": "false"}]},
    {"issues": [{"collector": "processes", "code": "error", "message": "x", "severity": "fatal"}]},
])
def test_invalid_snapshot_is_rejected(data):
    with pytest.raises(ValueError):
        Snapshot.from_json(json.dumps(data))


def test_invalid_json_is_rejected():
    with pytest.raises(ValueError):
        Snapshot.from_json("{broken")


def test_invalid_python_model_cannot_be_serialized():
    with pytest.raises(ValueError):
        Snapshot(processes=[ProcessRecord(pid="42")]).to_json()


def test_invalid_disposition_is_rejected():
    with pytest.raises(ValueError):
        Finding.from_dict(dict(
            id="x", title="x", correlation="C1", entities={}, evidence=[],
            interpretation="x", hypothesis="x", missing_evidence=[], disposition="critical",
        ))
