"""Contrato JSON v1. Valores desconhecidos permanecem None, sem inferências."""

import json
import types
from dataclasses import asdict, dataclass, field, fields, is_dataclass
from typing import Literal, Self, get_args, get_origin, get_type_hints


def _decode(value: object, expected: object, path: str) -> object:
    """Valida dados importados e reconstrói apenas os tipos do contrato."""
    origin = get_origin(expected)
    args = get_args(expected)
    if origin is types.UnionType:
        for candidate in args:
            try:
                return _decode(value, candidate, path)
            except ValueError:
                pass
        raise ValueError(f"{path}: valor incompatível com {expected}")
    if origin is Literal:
        if any(type(value) is type(item) and value == item for item in args):
            return value
    elif origin is list and isinstance(value, list):
        return [_decode(item, args[0], f"{path}[{i}]") for i, item in enumerate(value)]
    elif origin is dict and isinstance(value, dict):
        return {
            _decode(key, args[0], path): _decode(item, args[1], f"{path}.{key}")
            for key, item in value.items()
        }
    elif is_dataclass(expected) and isinstance(value, dict):
        allowed = {item.name for item in fields(expected)}
        if value.keys() - allowed:
            raise ValueError(f"{path}: campos desconhecidos")
        hints = get_type_hints(expected)
        decoded = {key: _decode(item, hints[key], f"{path}.{key}") for key, item in value.items()}
        try:
            return expected(**decoded)
        except TypeError as error:
            raise ValueError(f"{path}: campos obrigatórios ausentes") from error
    elif origin is None and type(value) is expected:
        return value
    raise ValueError(f"{path}: valor incompatível com {expected}")


class JsonModel:
    """Conversão JSON sem coleta, correlação ou interpretação."""

    def to_dict(self) -> dict:
        data = asdict(self)
        # Também valida objetos construídos diretamente em Python.
        type(self).from_dict(data)
        return data

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2, allow_nan=False)

    @classmethod
    def from_dict(cls, data: dict) -> Self:
        return _decode(data, cls, cls.__name__)

    @classmethod
    def from_json(cls, text: str) -> Self:
        return cls.from_dict(json.loads(text))


@dataclass
class ProcessRecord(JsonModel):
    pid: int
    ppid: int | None = None
    name: str | None = None
    username: str | None = None
    uid: int | None = None
    gid: int | None = None
    status: str | None = None
    cmdline: list[str] | None = None
    exe: str | None = None


@dataclass
class ServiceRecord(JsonModel):
    unit: str
    active_state: str | None = None
    sub_state: str | None = None
    main_pid: int | None = None
    configured_user: str | None = None
    configured_group: str | None = None
    fragment_path: str | None = None
    exec_start: str | None = None


@dataclass
class NetworkRecord(JsonModel):
    pid: int | None = None
    protocol: str | None = None
    local_address: str | None = None
    local_port: int | None = None
    status: str | None = None


@dataclass
class PermissionRecord(JsonModel):
    path: str
    exists: bool | None = None
    file_type: str | None = None
    owner_uid: int | None = None
    owner_name: str | None = None
    group_gid: int | None = None
    group_name: str | None = None
    mode: int | None = None
    owner_writable: bool | None = None
    group_writable: bool | None = None
    other_writable: bool | None = None
    parent_path: str | None = None
    parent_mode: int | None = None


@dataclass
class CollectionMetadata(JsonModel):
    collected_at: str | None = None
    hostname: str | None = None
    platform: str | None = None


@dataclass
class CollectionIssue(JsonModel):
    collector: str
    code: str
    message: str
    entity: str | None = None
    field: str | None = None
    severity: Literal["warning", "error"] = "warning"


@dataclass
class Snapshot(JsonModel):
    schema_version: Literal[1] = 1
    metadata: CollectionMetadata = field(default_factory=CollectionMetadata)
    processes: list[ProcessRecord] = field(default_factory=list)
    services: list[ServiceRecord] = field(default_factory=list)
    sockets: list[NetworkRecord] = field(default_factory=list)
    permissions: list[PermissionRecord] = field(default_factory=list)
    issues: list[CollectionIssue] = field(default_factory=list)


@dataclass
class Finding(JsonModel):
    id: str
    title: str
    correlation: str
    entities: dict[str, list[str]]
    evidence: list[str]
    interpretation: str
    hypothesis: str
    missing_evidence: list[str]
    disposition: Literal["informational", "needs_review", "inconclusive"]
