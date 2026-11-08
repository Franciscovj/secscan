"""Modelo de dados dos achados de segurança.

Cada check retorna uma lista de `Finding`. O achado nasce estruturado, com
severidade, confianca, evidencia e remediacao. E isso que torna o relatorio
confiavel e a saida consumivel por outra ferramenta ou por uma IA.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Gravidade do achado, do mais grave ao informativo."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        order = {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFO: 1,
        }
        return order[self]

    @property
    def rotulo(self) -> str:
        return {
            Severity.CRITICAL: "Critico",
            Severity.HIGH: "Alto",
            Severity.MEDIUM: "Medio",
            Severity.LOW: "Baixo",
            Severity.INFO: "Info",
        }[self]


class Confidence(str, Enum):
    """Quao certo o check esta do achado. Separa 'confirmado' de 'suspeito'."""

    CONFIRMED = "confirmed"
    FIRM = "firm"
    TENTATIVE = "tentative"

    @property
    def rotulo(self) -> str:
        return {
            Confidence.CONFIRMED: "Confirmado",
            Confidence.FIRM: "Provavel",
            Confidence.TENTATIVE: "Suspeito",
        }[self]


@dataclass
class Finding:
    """Um achado de seguranca."""

    check: str
    title: str
    severity: Severity
    confidence: Confidence
    url: str = ""
    description: str = ""
    evidence: str = ""
    remediation: str = ""
    cwe: str | None = None
    owasp: str | None = None
    references: list[str] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = dataclasses.asdict(self)
        d["severity"] = self.severity.value
        d["confidence"] = self.confidence.value
        return d

    def linha(self) -> str:
        """Uma linha compacta para log/terminal."""
        marca = {
            Severity.CRITICAL: "[CRIT]",
            Severity.HIGH: "[ALTO]",
            Severity.MEDIUM: "[MED]",
            Severity.LOW: "[BAIXO]",
            Severity.INFO: "[INFO]",
        }[self.severity]
        base = f"{marca} {self.check}: {self.title}"
        if self.url:
            base += f" -- {self.url}"
        return base
