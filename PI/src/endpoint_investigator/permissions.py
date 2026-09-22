"""Indicação POSIX conservadora, separada dos fatos coletados e dos findings."""

import stat
from dataclasses import dataclass, field

from .models import PermissionRecord


@dataclass
class PermissionAssessment:
    direct_write: bool | None
    replacement: bool | None
    missing_evidence: list[str] = field(default_factory=lambda: [
        "ACLs e capabilities não observadas.",
        "Flags de mount, atributos imutáveis e namespaces não observados.",
        "Travessia dos ancestrais e resolução de symlinks não verificadas.",
        "Membros e grupos suplementares das identidades não observados.",
    ])


def _writer(record: PermissionRecord, directory: bool = False) -> bool | None:
    if record.exists is not True or record.mode is None or record.owner_uid is None:
        return None
    owner = stat.S_IWUSR | (stat.S_IXUSR if directory else 0)
    group = stat.S_IWGRP | (stat.S_IXGRP if directory else 0)
    other = stat.S_IWOTH | (stat.S_IXOTH if directory else 0)
    if record.owner_uid != 0 and record.mode & owner == owner:
        return True
    if record.mode & other == other:
        return True
    if record.mode & group == group:
        return None  # Até o grupo root pode ter membros não-root.
    return False


def assess_permissions(resource: PermissionRecord, parent: PermissionRecord | None = None) -> PermissionAssessment:
    """True indica possibilidade pelos bits, False ausência desse sinal, None lacuna."""
    direct = _writer(resource) if resource.file_type == "file" else None
    replacement = None
    if (parent is not None and resource.parent_path == parent.path
            and parent.file_type == "directory" and parent.exists is True
            and resource.exists is True and resource.path != parent.path):
        replacement = _writer(parent, directory=True)
        if parent.mode is not None and parent.mode & stat.S_ISVTX:
            # Sticky permite remover apenas ao dono do arquivo/diretório (ou root).
            if parent.owner_uid not in (None, 0) and parent.mode & 0o300 == 0o300:
                replacement = True
            elif resource.owner_uid == 0 and parent.owner_uid == 0:
                replacement = False
            elif replacement is not False:
                replacement = None
    return PermissionAssessment(direct, replacement)
