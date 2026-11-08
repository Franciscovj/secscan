"""Classe-base de todos os checks.

Um check recebe o Target e o HttpClient e implementa `executar()` devolvendo
uma lista de Finding. Nada de print: quem exibe/salva e o runner e os reporters.
Helpers comuns (achado, log de progresso) ficam aqui para os checks ficarem curtos.
"""

from __future__ import annotations

from typing import Callable

from ..core.finding import Confidence, Finding, Severity
from ..core.http_client import HttpClient
from ..core.target import Target


class Check:
    #: preenchidos pelo decorator @registrar
    id: str = "base"
    titulo: str = "Check base"

    def __init__(
        self,
        target: Target,
        http: HttpClient,
        on_log: Callable[[str], None] | None = None,
        opcoes: dict | None = None,
    ) -> None:
        self.target = target
        self.http = http
        self._on_log = on_log
        #: configuracao extra vinda da CLI (ex.: wordlists, max_tentativas)
        self.opcoes = opcoes or {}

    # ---- helpers ----------------------------------------------------------
    def log(self, msg: str) -> None:
        if self._on_log:
            self._on_log(f"  {self.id}: {msg}")

    def achado(
        self,
        title: str,
        severity: Severity,
        confidence: Confidence,
        url: str | None = None,
        description: str = "",
        evidence: str = "",
        remediation: str = "",
        cwe: str | None = None,
        owasp: str | None = None,
        references: list[str] | None = None,
        extra: dict | None = None,
    ) -> Finding:
        return Finding(
            check=self.id,
            title=title,
            severity=severity,
            confidence=confidence,
            url=url if url is not None else self.target.url,
            description=description,
            evidence=evidence,
            remediation=remediation,
            cwe=cwe,
            owasp=owasp,
            references=references or [],
            extra=extra or {},
        )

    # ---- contrato ---------------------------------------------------------
    def executar(self) -> list[Finding]:  # pragma: no cover - abstrato
        raise NotImplementedError
