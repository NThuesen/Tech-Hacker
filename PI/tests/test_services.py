from pathlib import Path
import subprocess
from unittest.mock import Mock

import pytest

from endpoint_investigator import scan, system
from endpoint_investigator.collectors import services
from endpoint_investigator.models import ProcessRecord, Snapshot


FIXTURES = Path(__file__).parent / "fixtures"


def output(text, code=0):
    return subprocess.CompletedProcess([], code, text, "")


def fixture(name="systemctl_show.service.txt"):
    return (FIXTURES / name).read_text()


def test_parser_preserves_fields_and_equals():
    record, issues = services.parse_service("demo.service", fixture())
    assert not issues
    assert record.main_pid == 42
    assert record.active_state == "active"
    assert record.sub_state == "running"
    assert record.configured_user == record.configured_group == "root"
    assert record.fragment_path == "/etc/systemd/system/demo.service"
    assert "--option=a=b" in record.exec_start


def test_zero_pid_and_explicit_empty_values():
    record, issues = services.parse_service("demo.service", fixture("systemctl_show_no_pid.service.txt"))
    assert record.main_pid is None
    assert record.configured_user == ""
    assert issues[0].code == "main_pid_unavailable"


@pytest.mark.parametrize("text", ["", "MainPID=invalid", "MainPID=-1"])
def test_missing_or_invalid_pid_is_partial(text):
    record, issues = services.parse_service("demo.service", text)
    assert record.main_pid is None
    assert issues
    assert Snapshot.from_json(Snapshot(services=[record], issues=issues).to_json()).services == [record]


@pytest.mark.parametrize("text", ["not properties", "MainPID=42\nMainPID=43"])
def test_malformed_properties_rejected(text):
    with pytest.raises(ValueError):
        services.parse_service("demo.service", text)


def test_collect_and_associate_without_risk_interpretation(monkeypatch):
    runner = Mock(side_effect=[output("demo.service loaded active running Demo\n"), output(fixture())])
    monkeypatch.setattr(system, "run_systemctl", runner)
    process = ProcessRecord(42, uid=0)
    records, issues = services.collect_services([process])
    assert not issues
    assert services.associated_process(records[0], [process]) is process
    assert runner.call_args.args[-2:] == ("--", "demo.service")


def test_unobserved_main_pid(monkeypatch):
    monkeypatch.setattr(system, "run_systemctl", Mock(side_effect=[output("demo.service loaded active running Demo"), output(fixture())]))
    records, issues = services.collect_services([])
    assert records[0].main_pid == 42
    assert issues[0].code == "process_unavailable"


@pytest.mark.parametrize("failure", [FileNotFoundError(), PermissionError(), subprocess.TimeoutExpired("systemctl", 10), output("", 1)])
def test_without_systemd_snapshot_stays_valid(monkeypatch, failure):
    runner = Mock(side_effect=failure) if isinstance(failure, Exception) else Mock(return_value=failure)
    monkeypatch.setattr(system, "run_systemctl", runner)
    monkeypatch.setattr(scan, "collect_processes", lambda: ([ProcessRecord(42)], []))
    monkeypatch.setattr(scan, "collect_network", lambda: ([], []))
    snapshot = scan.collect_snapshot()
    assert snapshot.services == []
    assert snapshot.processes[0].pid == 42
    assert snapshot.issues[0].code == "unavailable"
    assert Snapshot.from_json(snapshot.to_json()) == snapshot


@pytest.mark.parametrize("failure", [output("", 1), output("malformed"), subprocess.TimeoutExpired("systemctl", 10)])
def test_one_unit_failure_keeps_next_service(monkeypatch, failure):
    monkeypatch.setattr(system, "run_systemctl", Mock(side_effect=[
        output("first.service loaded active running First\nsecond.service loaded active running Second"),
        failure, output(fixture()),
    ]))
    records, issues = services.collect_services([ProcessRecord(42)])
    assert len(records) == 2
    assert records[0].main_pid is None
    assert records[1].main_pid == 42
    assert issues[0].code == "properties_unavailable"


def test_empty_running_list_is_valid(monkeypatch):
    monkeypatch.setattr(system, "run_systemctl", Mock(return_value=output("")))
    assert services.collect_services([]) == ([], [])


def test_unexpected_listing_is_not_silently_clean(monkeypatch):
    monkeypatch.setattr(system, "run_systemctl", Mock(return_value=output("unexpected output")))
    records, issues = services.collect_services([])
    assert not records
    assert issues[0].code == "invalid_listing"


def test_wrapper_is_bounded_and_does_not_use_shell(monkeypatch):
    runner = Mock(return_value=output(""))
    monkeypatch.setattr(system.subprocess, "run", runner)
    system.run_systemctl("show", "--", "demo.service")
    args, kwargs = runner.call_args
    assert args[0] == ["systemctl", "--no-pager", "--no-ask-password", "show", "--", "demo.service"]
    assert kwargs.get("shell", False) is False
    assert kwargs["timeout"] == 10
    assert kwargs["env"]["LC_ALL"] == "C"
    with pytest.raises(ValueError):
        system.run_systemctl("restart", "demo.service")
    assert runner.call_count == 1
