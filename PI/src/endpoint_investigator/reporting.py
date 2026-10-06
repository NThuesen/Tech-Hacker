"""Apresentação dos resultados, sem regras de investigação."""

import json

from .models import Finding, Snapshot


def build_report(snapshot: Snapshot, findings: list[Finding]) -> dict:
    return {
        "report_version": 1,
        "snapshot": snapshot.to_dict(),
        "summary": {
            "collection_status": "partial_or_limited" if snapshot.issues else "no_reported_issues",
            "counts": {key: len(getattr(snapshot, key)) for key in
                       ("processes", "services", "sockets", "permissions", "issues")},
            "findings": {kind: sum(f.disposition == kind for f in findings)
                         for kind in ("informational", "needs_review", "inconclusive")},
        },
        "findings": [finding.to_dict() for finding in findings],
    }


def render_json(report: dict) -> str:
    return json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False)


def render_text(report: dict) -> str:
    summary = report["summary"]
    lines = ["Endpoint Investigator", "Coleta: " + (
        "parcial ou com limitações" if summary["collection_status"] == "partial_or_limited"
        else "sem avisos registrados (não comprova cobertura completa)"),
        "Registros: " + ", ".join(f"{key}={value}" for key, value in summary["counts"].items()),
        "Findings: " + ", ".join(f"{key}={value}" for key, value in summary["findings"].items()),
        "Dispositions são estados da investigação/evidência, não níveis de risco:",
        "  informational: contexto observável útil; não afirma vulnerabilidade.",
        "  inconclusive: faltam evidências necessárias para avaliar a relação investigada.",
        "  needs_review: evidência concreta sustenta uma relação potencialmente insegura; requer revisão humana, sem provar alteração, exploração ou comprometimento.",
        "IDs como C1:1 são identificadores técnicos, não níveis de risco.",
    ]
    for issue in report["snapshot"]["issues"]:
        lines.append(f"Aviso [{issue['collector']}/{issue['code']}, {issue['severity']}]: {issue['message']} (entidade={issue['entity']!r}, campo={issue['field']!r})")
    if not report["findings"]:
        lines.append("Nenhum finding produzido; isso não comprova ausência de problemas.")
    for finding in report["findings"]:
        primary_kind = {"C1": "services", "C2": "sockets", "C3": "processes"}.get(finding["correlation"])
        primary = finding["entities"].get(primary_kind, [])
        lines.extend([
            "", finding["title"],
            "ID técnico: " + finding["id"],
            "Correlação: " + finding["correlation"],
            "Entidade principal: " + (f"{primary_kind}={primary[0]}" if primary else "não informada"),
            "Disposition: " + finding["disposition"],
            "Entidades: " + json.dumps(finding["entities"], ensure_ascii=False),
            "Evidência:", *[f"  - {item}" for item in finding["evidence"]],
            "Interpretação: " + finding["interpretation"],
            "Hipótese: " + finding["hypothesis"],
            "Evidência ausente:", *[f"  - {item}" for item in finding["missing_evidence"]],
        ])
    return "\n".join(lines)
