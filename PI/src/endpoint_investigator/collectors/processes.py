"""Observação de processos com falhas isoladas por campo/PID."""

import psutil

from ..models import CollectionIssue, ProcessRecord


def collect_processes() -> tuple[list[ProcessRecord], list[CollectionIssue]]:
    records, issues = [], []
    try:
        for process in psutil.process_iter():
            record = ProcessRecord(pid=process.pid)
            try:
                if not process.is_running():
                    raise psutil.NoSuchProcess(process.pid)
                for field, method in (
                    ("ppid", "ppid"), ("name", "name"),
                    ("username", "username"), ("uid", "uids"),
                    ("gid", "gids"), ("status", "status"),
                    ("cmdline", "cmdline"), ("exe", "exe"),
                ):
                    try:
                        value = getattr(process, method)()
                        if field in ("uid", "gid"):
                            value = value.effective
                        if field == "status":
                            value = str(value)
                        if field == "exe" and not value:
                            value = None
                            issues.append(CollectionIssue(
                                "processes", "unavailable", "Executável não informado pela fonte.",
                                str(process.pid), field,
                            ))
                        setattr(record, field, value)
                    except psutil.ZombieProcess:
                        issues.append(CollectionIssue(
                            "processes", "zombie_process", "Campo indisponível em processo zombie.",
                            str(process.pid), field,
                        ))
                    except (psutil.AccessDenied, OSError) as error:
                        issues.append(CollectionIssue(
                            "processes", "access_denied" if isinstance(error, (psutil.AccessDenied, PermissionError)) else "os_error",
                            "Não foi possível observar o campo.", str(process.pid), field,
                        ))
                if not process.is_running():
                    raise psutil.NoSuchProcess(process.pid)
            except psutil.NoSuchProcess:
                # Descarta campos que poderiam pertencer a um PID reutilizado.
                record = ProcessRecord(pid=process.pid)
                issues.append(CollectionIssue(
                    "processes", "process_disappeared", "Processo terminou ou PID foi reutilizado durante a coleta.",
                    str(process.pid),
                ))
            except (psutil.AccessDenied, OSError):
                record = ProcessRecord(pid=process.pid)
                issues.append(CollectionIssue(
                    "processes", "identity_unavailable", "Não foi possível verificar a identidade do processo.",
                    str(process.pid),
                ))
            records.append(record)
    except (psutil.Error, OSError):
        issues.append(CollectionIssue(
            "processes", "enumeration_failed", "Listagem de processos interrompida; coleta parcial.",
            severity="error",
        ))
    return records, issues
