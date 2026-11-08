"""Verifica configuracao de CORS (passivo).

Envia a home com um header Origin de um dominio controlado e observa como o
servidor responde em Access-Control-Allow-Origin/Credentials. Nao envia
payload de ataque, apenas observa o comportamento normal do servidor.
"""

from __future__ import annotations

from ..core.finding import Confidence, Severity
from ..core.registry import Categoria, registrar
from .base import Check

ORIGEM_HOSTIL = "https://evil.example"


@registrar("cors", "CORS mal configurado", Categoria.PASSIVO)
class CorsCheck(Check):
    def executar(self):
        achados = []
        self.log("testando reflexo de Origin hostil")
        try:
            r = self.http.get(self.target.url, headers={"Origin": ORIGEM_HOSTIL})
        except Exception as e:
            self.log(f"falha ao buscar: {e}")
            return achados

        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "").lower()

        if not acao:
            return achados

        if acao == "*" and acac == "true":
            achados.append(
                self.achado(
                    title="CORS invalido: wildcard com credenciais",
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    description="O servidor envia Access-Control-Allow-Origin: * "
                    "junto com Access-Control-Allow-Credentials: true, uma "
                    "combinacao invalida/perigosa (navegadores modernos bloqueiam "
                    "isso, mas indica configuracao sem cuidado).",
                    evidence=f"Origin enviado: {ORIGEM_HOSTIL}; "
                    f"Access-Control-Allow-Origin: {acao}; "
                    f"Access-Control-Allow-Credentials: {acac}",
                    remediation="Nunca combine wildcard com credenciais. Use uma "
                    "allowlist de origens confiaveis.",
                    cwe="CWE-942",
                    owasp="A05:2021 Security Misconfiguration",
                )
            )
        elif acao == ORIGEM_HOSTIL:
            achados.append(
                self.achado(
                    title="CORS reflete qualquer origem (incluindo hostil)",
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    description="O servidor reflete de volta exatamente a Origin "
                    "enviada, mesmo sendo um dominio arbitrario e nao confiavel, "
                    "o que permite que qualquer site leia respostas autenticadas "
                    "via CORS.",
                    evidence=f"Origin enviado: {ORIGEM_HOSTIL}; "
                    f"Access-Control-Allow-Origin: {acao}; "
                    f"Access-Control-Allow-Credentials: {acac or 'ausente'}",
                    remediation="Valide a Origin contra uma allowlist no servidor "
                    "antes de refleti-la no header.",
                    cwe="CWE-942",
                    owasp="A05:2021 Security Misconfiguration",
                )
            )
        elif acao == "*":
            achados.append(
                self.achado(
                    title="CORS liberado para qualquer origem",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CONFIRMED,
                    description="O servidor envia Access-Control-Allow-Origin: * "
                    "para qualquer requisicao, permitindo que qualquer site leia "
                    "respostas publicas via CORS.",
                    evidence=f"Access-Control-Allow-Origin: {acao}",
                    remediation="Restrinja Access-Control-Allow-Origin a uma "
                    "allowlist de dominios confiaveis.",
                    cwe="CWE-942",
                    owasp="A05:2021 Security Misconfiguration",
                )
            )
        return achados
