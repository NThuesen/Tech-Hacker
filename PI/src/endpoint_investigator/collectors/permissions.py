"""Seleção contextual e observação de permissões, sem classificação de risco."""

import grp
import os
import pwd
import re
import shlex
import stat

from ..models import CollectionIssue, PermissionRecord, ProcessRecord, ServiceRecord


def _absolute(path: str | None) -> bool:
    return bool(path and path.startswith("/") and "\x00" not in path and not path.endswith(" (deleted)"))


def _exec_paths(text: str) -> list[str]:
    """Aceita somente formas simples; nunca expande shell, variáveis ou escapes."""
    if any(char in text for char in ("\\", "$", "%", "`", "\n")):
        raise ValueError("ExecStart requer resolução adicional")
    if text.startswith("{"):
        blocks = re.findall(r"\{ path=([^;{}]+) ; argv\[\]=([^;{}]+) ; [^{}]*\}", text)
        if len(blocks) != text.count("{") or not blocks:
            raise ValueError("Formato ExecStart não suportado")
        commands = [(path.strip(), shlex.split(argv)) for path, argv in blocks]
    else:
        argv = shlex.split(text)
        commands = [(argv[0], argv)] if argv else []
    paths = []
    for executable, argv in commands:
        if not _absolute(executable):
            raise ValueError("Executável sem caminho absoluto")
        paths.append(executable)
        # Apenas script absoluto como primeiro argumento de interpretador conhecido.
        interpreter = os.path.basename(executable)
        if re.fullmatch(r"(?:python(?:\d+(?:\.\d+)*)?|bash|sh|dash|perl|ruby|node)", interpreter):
            if len(argv) > 1:
                if not _absolute(argv[1]):
                    raise ValueError("Script/expressão não resolvido com segurança")
                paths.append(argv[1])
    return paths


def select_paths(processes: list[ProcessRecord], services: list[ServiceRecord]) -> tuple[list[str], list[CollectionIssue]]:
    paths: set[str] = set()
    issues = []

    def add(path, entity):
        if path is None or path == "":
            return
        if _absolute(path):
            paths.add(path)
        else:
            issues.append(CollectionIssue("permissions", "unresolved_path", "Caminho não resolvido com segurança.", entity))

    for process in processes:
        add(process.exe, str(process.pid))
    for service in services:
        add(service.fragment_path, service.unit)
        if service.exec_start:
            try:
                for path in _exec_paths(service.exec_start):
                    add(path, service.unit)
            except ValueError:
                issues.append(CollectionIssue("permissions", "unresolved_exec_start", "ExecStart requer resolução adicional; nenhum comando foi executado.", service.unit, "exec_start"))
    return sorted(paths), issues


def collect_permissions(paths: list[str]) -> tuple[list[PermissionRecord], list[CollectionIssue]]:
    """Stat apenas dos recursos selecionados e de seus pais imediatos, deduplicados."""
    issues = []
    resources = {path for path in paths if _absolute(path)}
    for path in set(paths) - resources:
        issues.append(CollectionIssue("permissions", "unresolved_path", "Caminho inválido ou não absoluto.", path))
    parents = {path: os.path.dirname(path.rstrip("/")) or "/" for path in resources}
    records = {}
    for path in sorted(resources | set(parents.values())):
        record = PermissionRecord(path=path)
        records[path] = record
        try:
            observed = os.stat(path)
        except (FileNotFoundError, NotADirectoryError):
            record.exists = False
            issues.append(CollectionIssue("permissions", "not_found", "Recurso ou componente do caminho ausente.", path))
            continue
        except OSError:
            issues.append(CollectionIssue("permissions", "stat_unavailable", "Não foi possível observar o recurso.", path))
            continue
        record.exists = True
        record.file_type = "file" if stat.S_ISREG(observed.st_mode) else "directory" if stat.S_ISDIR(observed.st_mode) else "other"
        record.owner_uid, record.group_gid = observed.st_uid, observed.st_gid
        record.mode = stat.S_IMODE(observed.st_mode)
        record.owner_writable = bool(record.mode & stat.S_IWUSR)
        record.group_writable = bool(record.mode & stat.S_IWGRP)
        record.other_writable = bool(record.mode & stat.S_IWOTH)
        for field, lookup, identifier, name in (
            ("owner_name", pwd.getpwuid, record.owner_uid, "pw_name"),
            ("group_name", grp.getgrgid, record.group_gid, "gr_name"),
        ):
            try:
                setattr(record, field, getattr(lookup(identifier), name))
            except (KeyError, OSError):
                issues.append(CollectionIssue("permissions", "identity_unresolved", "Nome da identidade indisponível; ID numérico preservado.", path, field))
    for path, parent in parents.items():
        records[path].parent_path = parent
        records[path].parent_mode = records[parent].mode
    if resources:
        issues.append(CollectionIssue(
            "permissions", "posix_scope", "Somente bits POSIX: ACLs, capabilities, flags de mount, namespaces, symlinks e alterações entre observações limitam a conclusão.",
        ))
    return list(records.values()), issues
