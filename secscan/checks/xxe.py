"""Detecta XXE (XML External Entity) de forma segura (intrusivo).

Usa SOMENTE entidade interna (eco de um token), NUNCA payload de leitura de
arquivo (SYSTEM "file://...") nem de rede. O objetivo e so detectar se o
parser processa entidades DTD, sem explorar nada: se uma entidade interna e
expandida, um parser mal configurado tambem expandiria uma entidade externa
perigosa.
"""

from __future__ import annotations

import secrets

from ..core.finding import Confidence, Severity
from ..core.registry import Categoria, registrar
from .base import Check

ROTAS = ["/api/xml", "", "/api", "/xml", "/upload", "/soap"]


@registrar("xxe", "XXE (XML External Entity)", Categoria.INTRUSIVO)
class XxeCheck(Check):
    def executar(self):
        achados = []

        for rota in ROTAS:
            base = self.target.url if not rota else self.target.caminho(rota)
            token = "xxe" + secrets.token_hex(4)
            ent = "secx"
            payload = (
                f'<?xml version="1.0"?>'
                f'<!DOCTYPE foo [<!ENTITY {ent} "{token}">]>'
                f'<data>&{ent};</data>'
            )
            try:
                r = self.http.post(
                    base, data=payload, headers={"Content-Type": "application/xml"}
                )
            except Exception:
                continue
            if token in r.text and f"&{ent};" not in r.text:
                achados.append(
                    self.achado(
                        title="Processamento de entidade externa XML (XXE)",
                        severity=Severity.HIGH,
                        confidence=Confidence.FIRM,
                        url=base,
                        description="O endpoint aceita XML e expande entidades "
                        "definidas via DTD. Em um parser configurado assim, uma "
                        "entidade externa (SYSTEM) pode ser usada para ler "
                        "arquivos locais ou forcar o servidor a fazer "
                        "requisicoes a outros hosts (SSRF).",
                        evidence=f"entidade interna '&{ent};' com valor "
                        f"{token!r} foi expandida no corpo da resposta (nao "
                        "voltou crua), confirmando que o DTD foi processado.",
                        remediation="Desabilite o processamento de DTD e de "
                        "entidades externas no parser XML (ex.: defusedxml, ou "
                        "resolve_entities=False/FEATURE_SECURE_PROCESSING no "
                        "parser nativo).",
                        cwe="CWE-611",
                        owasp="A05:2021 Security Misconfiguration",
                    )
                )
                return achados
        return achados
