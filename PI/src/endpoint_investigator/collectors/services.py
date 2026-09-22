"""Serviços systemd e vínculo observado MainPID -> processo."""

import subprocess

from .. import system
from ..models import CollectionIssue, ProcessRecord, ServiceRecord


PROPERTIES = {
    "ActiveState": "active_state", "SubState": "sub_state",
    "MainPID": "main_pid", "User": "configured_user",
    "Group": "configured_group", "FragmentPath": "fragment_path",
    "ExecStart": "exec_start",
}


def parse_service(unit: str, text: str) -> tuple[ServiceRecord, list[CollectionIssue]]:
    record = ServiceRecord(unit=unit)
    issues = []
    values = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        key, separator, value = line.partition("=")
        if not separator or key in values:
            raise ValueError("Propriedades systemd malformadas ou duplicadas")
        values[key] = value
    for key, field in PROPERTIES.items():
        if key not in values:
            issues.append(CollectionIssue("services", "missing_property", "Propriedade não retornada.", unit, field))
            continue
        value = values[key]
        if key == "MainPID":
            if not value or value == "0":
                value = None
                issues.append(CollectionIssue("services", "main_pid_unavailable", "Serviço sem MainPID observado.", unit, field))
            elif value.isascii() and value.isdecimal():
                value = int(value)
            else:
                value = None
                issues.append(CollectionIssue("services", "invalid_property", "MainPID inválido.", unit, field))
        setattr(record, field, value)
    return record, issues


def associated_process(service: ServiceRecord, processes: list[ProcessRecord]) -> ProcessRecord | None:
    """Vínculo por PID; não garante identidade temporal entre coletas."""
    return next((item for item in processes if item.pid == service.main_pid), None)


def collect_services(processes: list[ProcessRecord]) -> tuple[list[ServiceRecord], list[CollectionIssue]]:
    records, issues = [], []
    try:
        result = system.run_systemctl(
            "list-units", "--type=service", "--state=running", "--plain", "--no-legend", "--full",
        )
        if result.returncode:
            raise OSError("systemctl indisponível")
    except (OSError, subprocess.TimeoutExpired):
        return [], [CollectionIssue("services", "unavailable", "Não foi possível listar serviços systemd.", severity="error")]
    units = []
    for line in result.stdout.splitlines():
        if not line.strip():
            continue
        columns = line.split()
        if len(columns) < 4 or not columns[0].endswith(".service") or columns[1:4] != ["loaded", "active", "running"]:
            issues.append(CollectionIssue("services", "invalid_listing", "Linha inesperada na listagem de serviços."))
            continue
        if columns[0] not in units:
            units.append(columns[0])
    for unit in units:
        try:
            result = system.run_systemctl("show", "--all", "--property=" + ",".join(PROPERTIES), "--", unit)
            if result.returncode:
                raise OSError("Falha ao consultar unit")
            record, partial = parse_service(unit, result.stdout)
            issues.extend(partial)
        except (OSError, subprocess.TimeoutExpired, ValueError):
            record = ServiceRecord(unit=unit)
            issues.append(CollectionIssue("services", "properties_unavailable", "Não foi possível obter propriedades válidas do serviço.", unit))
        records.append(record)
        if record.main_pid is not None and associated_process(record, processes) is None:
            issues.append(CollectionIssue("services", "process_unavailable", "MainPID não encontrado nos processos observados.", unit, "main_pid"))
    return records, issues
