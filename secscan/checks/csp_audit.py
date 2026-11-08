"""Auditoria da Content-Security-Policy (passivo).

Se a CSP existe, procura configuracoes que anulam sua protecao:
'unsafe-inline', 'unsafe-eval' e origem curinga. A ausencia da CSP e tratada
pelo check `headers`.
"""

from __future__ import annotations

from ..core.finding import Confidence, Severity
from ..core.registry import Categoria, registrar
from .base import Check

REMEDIACAO = (
    "Remova 'unsafe-inline' e 'unsafe-eval', use nonces ou hashes para scripts "
    "e estilos necessarios e restrinja as origens a dominios conhecidos."
)


@registrar("csp_audit", "Content-Security-Policy fraca", Categoria.PASSIVO)
class CspAuditCheck(Check):
    def executar(self):
        achados = []
        self.log("lendo Content-Security-Policy da home")
        try:
            r = self.http.get(self.target.url)
        except Exception as e:
            self.log(f"falha ao buscar: {e}")
            return achados
        csp = r.headers.get("Content-Security-Policy", "")
        if not csp.strip():
            return achados

        diretivas = {}
        for parte in csp.split(";"):
            tokens = parte.split()
            if tokens:
                diretivas.setdefault(tokens[0].lower(), tokens[1:])

        def achar(titulo, descricao, diretiva, valores):
            return self.achado(
                title=titulo,
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                url=self.target.url,
                description=descricao,
                evidence=f"{diretiva} {' '.join(valores)}",
                remediation=REMEDIACAO,
                cwe="CWE-693",
                owasp="A05:2021 Security Misconfiguration",
            )

        for diretiva in ("script-src", "style-src", "default-src"):
            valores = diretivas.get(diretiva)
            if valores and "'unsafe-inline'" in valores:
                achados.append(achar(
                    "CSP permite 'unsafe-inline'",
                    "'unsafe-inline' permite scripts/estilos inline e enfraquece "
                    "a protecao contra XSS.",
                    diretiva, valores))
                break

        for diretiva, valores in diretivas.items():
            if "'unsafe-eval'" in valores:
                achados.append(achar(
                    "CSP permite 'unsafe-eval'",
                    "'unsafe-eval' permite eval() e similares, facilitando "
                    "execucao de codigo injetado.",
                    diretiva, valores))
                break

        for diretiva in ("default-src", "script-src"):
            valores = diretivas.get(diretiva)
            if valores and "*" in valores:
                achados.append(achar(
                    "CSP com origem curinga (*)",
                    "A origem curinga permite carregar recursos de qualquer "
                    "dominio, anulando a restricao da politica.",
                    diretiva, valores))
                break
        return achados
