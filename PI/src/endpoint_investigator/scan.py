"""Composição do snapshot disponível em B3, sem findings."""

import platform
import socket
from datetime import datetime, timezone

from .collectors.network import collect_network
from .collectors.processes import collect_processes
from .collectors.services import collect_services
from .collectors.permissions import collect_permissions, select_paths
from .models import CollectionMetadata, Snapshot


def collect_snapshot() -> Snapshot:
    metadata = CollectionMetadata(
        collected_at=datetime.now(timezone.utc).isoformat(),
        hostname=socket.gethostname(), platform=platform.system(),
    )
    processes, process_issues = collect_processes()
    sockets, network_issues = collect_network()
    services, service_issues = collect_services(processes)
    paths, path_issues = select_paths(processes, services)
    permissions, permission_issues = collect_permissions(paths)
    return Snapshot(
        metadata=metadata, processes=processes, sockets=sockets, services=services,
        permissions=permissions,
        issues=process_issues + network_issues + service_issues + path_issues + permission_issues,
    )
