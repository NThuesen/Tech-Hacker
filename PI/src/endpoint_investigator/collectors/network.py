"""Sockets locais: TCP LISTEN e UDP vinculado sem peer remoto."""

import os
import socket

import psutil

from ..models import CollectionIssue, NetworkRecord


def normalize_listener(connection) -> NetworkRecord | None:
    if connection.family not in (socket.AF_INET, socket.AF_INET6) or not connection.laddr:
        return None
    if connection.type == socket.SOCK_STREAM:
        if connection.status != psutil.CONN_LISTEN:
            return None
        protocol = "tcp"
    elif connection.type == socket.SOCK_DGRAM:
        if connection.raddr:
            return None
        protocol = "udp"
    else:
        return None
    return NetworkRecord(
        pid=connection.pid, protocol=protocol,
        local_address=connection.laddr.ip, local_port=connection.laddr.port,
        status=str(connection.status),
    )


def collect_network() -> tuple[list[NetworkRecord], list[CollectionIssue]]:
    records, issues = [], []
    if os.geteuid() != 0:
        issues.append(CollectionIssue(
            "network", "visibility_limited", "Sem privilégios, o SO pode omitir sockets silenciosamente.",
        ))
    try:
        for connection in psutil.net_connections(kind="inet"):
            record = normalize_listener(connection)
            if record is not None:
                records.append(record)
                if record.pid is None:
                    issues.append(CollectionIssue(
                        "network", "pid_unavailable", "Socket sem PID informado pela fonte.",
                        f"{record.protocol}://{record.local_address}:{record.local_port}", "pid",
                    ))
    except (psutil.Error, OSError) as error:
        issues.append(CollectionIssue(
            "network", "access_denied" if isinstance(error, (psutil.AccessDenied, PermissionError)) else "collection_failed",
            "Não foi possível completar a coleta de sockets.", severity="error",
        ))
    return records, issues
