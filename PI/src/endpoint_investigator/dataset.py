"""Normalização offline do formato do generator da disciplina, sem coleta."""

import csv
import io
import json
from pathlib import Path, PurePosixPath
import re
import shlex

from .models import (
    CollectionIssue, PermissionRecord, ProcessRecord, ServiceRecord, Snapshot,
)


def _rows(text: str, columns: list[str], source: str) -> list[dict[str, str]]:
    try:
        reader = csv.DictReader(io.StringIO(text), strict=True)
        if reader.fieldnames != columns:
            raise ValueError(f"{source}: cabeçalho inválido")
        rows = list(reader)
    except csv.Error as error:
        raise ValueError(f"{source}: CSV inválido") from error
    for number, row in enumerate(rows, 2):
        if None in row or any(value is None or not value.strip() for value in row.values()):
            raise ValueError(f"{source}:{number}: linha incompleta ou inválida")
    return rows


def _number(value: str, minimum: int, source: str) -> int:
    if not re.fullmatch(r"[0-9]+", value) or int(value) < minimum:
        raise ValueError(f"{source}: PID/PPID inválido")
    return int(value)


def parse_dataset(processes: str, permissions: str, services: str, metadata: str) -> Snapshot:
    """Converte somente textos fornecidos. Entradas estruturais inválidas são rejeitadas."""
    context = json.loads(metadata)
    if not isinstance(context, dict) or context.get("dataset_type") != "synthetic_training":
        raise ValueError("metadata.json: dataset_type deve ser synthetic_training")
    for field in ("level", "scenario", "generated_at", "warning"):
        if not isinstance(context.get(field), str) or not context[field]:
            raise ValueError(f"metadata.json: {field} inválido")
    if "seed" not in context or (context["seed"] is not None and type(context["seed"]) is not int):
        raise ValueError("metadata.json: seed inválido")
    snapshot = Snapshot()

    def issue(source, code, message, entity=None, field=None):
        snapshot.issues.append(CollectionIssue(source, code, message, entity, field))

    issue("dataset", "synthetic_source", f"Fonte sintética: scenario={context['scenario']!r}, "
          f"level={context['level']!r}, seed={context['seed']!r}, generated_at={context['generated_at']!r}. "
          "Data de geração não é data de coleta; hostname/platform não informados. "
          "journal.log e README.txt não analisados.")
    issue("network", "source_unavailable", "Dataset não fornece sockets; comandos e logs não comprovam escuta.")
    issue("permissions", "dataset_scope", "Somente metadados POSIX do dataset; sem consulta ao host, "
          "ACLs, capabilities, mounts, symlinks ou membros de grupos.")
    commands: dict[str, list[int]] = {}
    seen_pids = set()
    for row in _rows(processes, ["timestamp", "pid", "ppid", "user", "stat", "cmd"], "processes.csv"):
        pid = _number(row["pid"], 1, "processes.csv")
        if pid in seen_pids:
            raise ValueError(f"processes.csv: PID duplicado {pid}")
        seen_pids.add(pid)
        try:
            argv = shlex.split(row["cmd"])
        except ValueError:
            argv = None
        # Não interpretar expansões/shell ou resolver comandos relativos pelo PATH.
        exe = (argv[0] if argv and argv[0].startswith("/")
               and not any(c in row["cmd"] for c in "\x00\n\\$`|;&<>()") else None)
        process = ProcessRecord(pid=pid, ppid=_number(row["ppid"], 0, "processes.csv"),
                                username=row["user"], uid=0 if row["user"] == "root" else None,
                                status=row["stat"], cmdline=argv, exe=exe)
        snapshot.processes.append(process)
        commands.setdefault(row["cmd"], []).append(pid)
        if exe is None:
            issue("processes", "unresolved_command", "Executável não resolvido; cmd não foi executado.", str(pid), "exe")
        if process.uid is None:
            issue("processes", "identity_unresolved", "Nome preservado; UID desconhecido sem consulta ao host.", str(pid), "uid")
    issue("processes", "dataset_identity", "Somente user literal root é normalizado para UID 0; "
          "GID e nome do processo não informados. cmdline é tokenização textual, sem execução.")

    records = {}
    for row in _rows(permissions, ["path", "type", "owner", "group", "mode", "mtime"], "permissions.csv"):
        path = row["path"]
        if not path.startswith("/") or "\x00" in path or path in records:
            raise ValueError("permissions.csv: caminho inválido ou duplicado")
        if row["type"] not in ("file", "directory") or not re.fullmatch(r"[0-7]{3,4}", row["mode"]):
            raise ValueError("permissions.csv: tipo ou modo inválido")
        mode = int(row["mode"], 8)
        record = PermissionRecord(path=path, exists=True, file_type=row["type"],
                                  owner_name=row["owner"], owner_uid=0 if row["owner"] == "root" else None,
                                  group_name=row["group"], group_gid=0 if row["group"] == "root" else None,
                                  mode=mode, owner_writable=bool(mode & 0o200),
                                  group_writable=bool(mode & 0o020), other_writable=bool(mode & 0o002))
        records[path] = record
        if record.owner_uid is None or record.group_gid is None:
            issue("permissions", "identity_unresolved", "Owner/group nominais preservados; somente root recebe ID 0.", path)
    for path, record in records.items():
        parent = records.get(str(PurePosixPath(path).parent))
        if parent is not None and parent.path != path and parent.file_type == "directory":
            record.parent_path, record.parent_mode = parent.path, parent.mode
        else:
            issue("permissions", "parent_unavailable", "Diretório pai não informado no dataset.", path, "parent_path")
    snapshot.permissions = list(records.values())

    lines = services.splitlines()
    if not lines or lines[0].split() != ["UNIT", "ACTIVE", "USER", "EXECSTART"]:
        raise ValueError("services.txt: cabeçalho inválido")
    seen_units = set()
    for number, line in enumerate(lines[1:], 2):
        parts = line.split(maxsplit=3)
        if len(parts) != 4 or not parts[0].endswith(".service") or parts[0] in seen_units:
            raise ValueError(f"services.txt:{number}: linha inválida ou unit duplicada")
        unit, state, user, command = parts
        seen_units.add(unit)
        matches = commands.get(command, [])
        service = ServiceRecord(unit=unit, active_state="active" if state == "running" else None,
                                sub_state=state, configured_user=user, exec_start=command,
                                main_pid=matches[0] if len(matches) == 1 else None)
        snapshot.services.append(service)
        if service.main_pid is None:
            issue("services", "main_pid_unresolved", "ExecStart sem correspondência única e exata com cmd no dataset.", unit, "main_pid")
        else:
            issue("services", "main_pid_inferred", "MainPID inferido por correspondência textual única e exata "
                  f"ExecStart/cmd com PID {service.main_pid}; não observado via systemd.", unit, "main_pid")
        if service.active_state is None:
            issue("services", "state_unresolved", "Somente running é normalizado como active.", unit, "active_state")
        issue("services", "dataset_fields", "FragmentPath e grupo configurado não informados pelo dataset.", unit)
    return snapshot


def import_dataset(directory: str | Path) -> Snapshot:
    """Lê somente os quatro arquivos de entrada; nunca os caminhos descritos neles."""
    directory = Path(directory)
    texts = [(directory / name).read_text(encoding="utf-8") for name in
             ("processes.csv", "permissions.csv", "services.txt", "metadata.json")]
    return parse_dataset(*texts)
