"""Correlações puras sobre um snapshot; nenhuma coleta ou alteração do host."""

from .collectors.permissions import select_paths
from .models import Finding, PermissionRecord, ProcessRecord, ServiceRecord, Snapshot
from .permissions import assess_permissions


TEMPORAL_GAP = "Snapshot não atômico: confirmar identidade temporal dos PIDs e recursos."
MEMBERSHIP_GAP = "Membership systemd não verificado: cgroups, units .socket, socket activation e PID namespaces/containers fora do escopo."


def _service_associations(
    pid: int | None, processes: dict[int, ProcessRecord], services: list[ServiceRecord],
) -> tuple[list[tuple[ServiceRecord, str, list[int]]], str | None]:
    """Resolve vínculos contextuais, preservando todas as units alcançadas.

    Um MainPID direto independe da presença do ProcessRecord (C2 permanece
    inconclusiva nesse caso). Descendência exige todos os processos da cadeia,
    inclusive o MainPID. Nenhuma lacuna autoriza completar a árvore.
    """
    chain = []
    seen = set()
    current = pid
    gap = None
    while current is not None:
        if current in seen:
            gap = f"Cadeia PPID interrompida por self-parent ou ciclo no PID {current}."
            break
        process = processes.get(current)
        if process is None:
            gap = f"Cadeia PPID interrompida: processo PID {current} não observado."
            break
        seen.add(current)
        chain.append(current)
        current = process.ppid
    if current is None:
        gap = "Cadeia PPID encerrada em PID/PPID não informado."
    positions = {ancestor: index for index, ancestor in enumerate(chain)}
    associations = []
    for service in services:
        if pid is not None and service.main_pid == pid:
            associations.append((service, "direct_main_pid", [pid]))
        elif service.main_pid in positions:
            end = positions[service.main_pid] + 1
            associations.append((service, "descendant_of_main_pid", chain[:end]))
    return associations, gap


def _permission_evidence(record: PermissionRecord) -> str:
    mode = oct(record.mode) if record.mode is not None else None
    return (f"permissions[{record.path!r}]: exists={record.exists}, type={record.file_type}, "
            f"owner_uid={record.owner_uid}, group_gid={record.group_gid}, mode={mode}.")


def _issues(snapshot: Snapshot, sources: set[str], entities: set[str]) -> list[str]:
    return [f"Coleta {i.collector}/{i.code}: {i.message} (entidade={i.entity!r}, campo={i.field!r})."
            for i in snapshot.issues if i.collector in sources and (i.entity is None or i.entity in entities)]


def analyze_snapshot(snapshot: Snapshot) -> list[Finding]:
    """Produz C1/C2/C3 determinísticas sem alterar o snapshot ou gerar scores."""
    processes = {p.pid: p for p in snapshot.processes}
    permissions = {p.path: p for p in snapshot.permissions}
    findings = []
    relevant = set()

    for index, service in enumerate(snapshot.services):
        process = processes.get(service.main_pid)
        if process is not None:
            relevant.add(process.pid)
        if service.active_state not in (None, "active"):
            continue
        if process is not None and process.uid is not None and process.uid != 0:
            continue
        evidence = [f"services[{service.unit!r}]: active_state={service.active_state!r}, MainPID={service.main_pid}."]
        gaps = [TEMPORAL_GAP, "Não há prova de alteração ou exploração; verificar logs e integridade histórica."]
        confirmed = service.active_state == "active" and process is not None and process.uid == 0
        if service.active_state is None:
            gaps.append("Estado ativo do serviço não observado.")
        if process is None or process.uid is None:
            gaps.append("Processo/UID efetivo do MainPID não observado; configuração User não confirma privilégio efetivo.")
        if process is not None:
            evidence.append(f"processes[{process.pid}]: uid={process.uid}, exe={process.exe!r}.")
        paths, path_issues = select_paths([process] if process else [], [service])
        uncertain = not paths or bool(path_issues)
        if not paths:
            gaps.append("Nenhum recurso do serviço pôde ser resolvido.")
        gaps.extend(f"Seleção {issue.code}: {issue.message}" for issue in path_issues)
        modifiable = []
        observed_paths = []
        for path in paths:
            record = permissions.get(path)
            if record is None:
                uncertain = True
                gaps.append(f"Permissões não observadas: {path}.")
                continue
            observed_paths.append(path)
            evidence.append(_permission_evidence(record))
            parent = permissions.get(record.parent_path)
            if parent is not None:
                observed_paths.append(parent.path)
                evidence.append(_permission_evidence(parent))
            assessment = assess_permissions(record, parent)
            gaps.extend(assessment.missing_evidence)
            if assessment.direct_write is True:
                modifiable.append(f"{path}: bits sugerem escrita direta por não-root")
            if assessment.replacement is True:
                modifiable.append(f"{path}: bits do pai sugerem substituição por não-root")
            if assessment.direct_write is None or assessment.replacement is None:
                uncertain = True
                gaps.append(f"Escrita/substituição não determinada integralmente: {path}.")
        if not modifiable and not uncertain and confirmed:
            continue
        entities = {"services": [service.unit], "processes": [str(process.pid)] if process else [],
                    "permissions": list(dict.fromkeys(observed_paths))}
        gaps.extend(_issues(snapshot, {"processes", "services", "permissions"},
                            set(paths) | set(observed_paths) | {service.unit, str(service.main_pid)}))
        findings.append(Finding(
            id=f"C1:{index}", title="Contexto de privilégio e recursos do serviço", correlation="C1",
            entities=entities, evidence=list(dict.fromkeys(evidence)),
            interpretation=("; ".join(modifiable) + "." if modifiable else "Dados insuficientes para determinar a relação de escrita/privilégio."),
            hypothesis="Pode existir uma relação de privilégio insegura após alteração do recurso ou reinício; exploração não demonstrada.",
            missing_evidence=list(dict.fromkeys(gaps)), disposition="needs_review" if confirmed and modifiable else "inconclusive",
        ))

    for index, listener in enumerate(snapshot.sockets):
        if not ((listener.protocol == "tcp" and listener.status == "LISTEN")
                or (listener.protocol == "udp" and listener.status == "NONE")):
            continue
        process = processes.get(listener.pid)
        associations, ancestry_gap = _service_associations(listener.pid, processes, snapshot.services)
        services = [s for s, _, _ in associations]
        associated_pids = list(dict.fromkeys(pid for _, _, chain in associations for pid in chain))
        if process is not None:
            relevant.add(process.pid)
        gaps = [TEMPORAL_GAP, MEMBERSHIP_GAP, "Confirmar intenção da configuração, firewall, origens permitidas, autenticação e necessidade de negócio."]
        complete = (process is not None and process.uid is not None and bool(services)
                    and listener.local_address is not None and listener.local_port is not None)
        evidence = [f"sockets[{index}]: protocol={listener.protocol}, address={listener.local_address!r}, port={listener.local_port}, status={listener.status}, pid={listener.pid}."]
        if process is None:
            gaps.append("Processo do socket não observado ou PID não informado.")
        else:
            evidence.append(f"processes[{process.pid}]: uid={process.uid}, username={process.username!r}.")
            if process.uid is None:
                gaps.append("UID efetivo do processo não observado.")
        if not services:
            gaps.append("Serviço associado ao PID não observado; o processo pode não pertencer a um serviço systemd.")
            if ancestry_gap:
                gaps.append(ancestry_gap)
        if listener.local_address is None or listener.local_port is None:
            gaps.append("Endereço/porta local incompleto.")
        for service, provenance, chain in associations:
            evidence.append(f"services[{service.unit!r}]: MainPID={service.main_pid}, active_state={service.active_state!r}, association={provenance}.")
            if provenance == "descendant_of_main_pid":
                evidence.append(f"Cadeia PPID observada para {service.unit!r}: " + " -> ".join(map(str, chain)) + ".")
        gaps.extend(_issues(snapshot, {"network", "processes", "services"},
                            {str(listener.pid)} | {str(pid) for pid in associated_pids} | {s.unit for s in services}))
        findings.append(Finding(
            id=f"C2:{index}", title="Contexto de socket local", correlation="C2",
            entities={"sockets": [str(index)], "processes": [str(pid) for pid in associated_pids if pid in processes] or ([str(process.pid)] if process else []), "services": [s.unit for s in services]},
            evidence=evidence,
            interpretation=("Socket TCP em estado de escuta observado; exposição efetiva depende do contexto de rede."
                            if listener.protocol == "tcp" else "Socket UDP vinculado observado; UDP não tem LISTEN e o registro não prova função de servidor.")
                            + (" Associação por ancestralidade PPID é contexto observado, não prova de membership da unit."
                               if any(kind == "descendant_of_main_pid" for _, kind, _ in associations) else ""),
            hypothesis="Se a exposição for inesperada, o processo/serviço merece investigação; a escuta isolada não demonstra vulnerabilidade.",
            missing_evidence=gaps, disposition="informational" if complete else "inconclusive",
        ))

    for pid in sorted(relevant):
        process = processes[pid]
        parent = processes.get(process.ppid) if process.ppid != pid else None
        evidence = [f"processes[{pid}]: ppid={process.ppid}, uid={process.uid}, username={process.username!r}."]
        gaps = [TEMPORAL_GAP, "Confirmar histórico e intenção da execução; a relação PPID não demonstra ação maliciosa."]
        if parent is None:
            gaps.append("Processo pai não observado ou PPID inválido/indisponível.")
        else:
            evidence.append(f"processes[{parent.pid}]: uid={parent.uid}, username={parent.username!r}.")
        if process.uid is None or (parent is not None and parent.uid is None):
            gaps.append("Identidade efetiva do processo ou de seu pai não observada.")
        gaps.extend(_issues(snapshot, {"processes"}, {str(pid), str(process.ppid)}))
        findings.append(Finding(
            id=f"C3:{pid}", title="Contexto de origem do processo", correlation="C3",
            entities={"processes": [str(pid)] + ([str(parent.pid)] if parent else [])}, evidence=evidence,
            interpretation="Relação de origem indicada pelo PPID e identidades observadas; diferenças de UID não provam escalada.",
            hypothesis="O contexto pode corresponder a uma inicialização legítima; investigar se a origem for inesperada.",
            missing_evidence=gaps,
            disposition="informational" if parent is not None and parent.uid is not None and process.uid is not None else "inconclusive",
        ))
    return findings
