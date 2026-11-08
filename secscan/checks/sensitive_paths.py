"""Procura arquivos/caminhos sensiveis expostos (ativo)."""

from __future__ import annotations

from ..core.finding import Confidence, Severity
from ..core.registry import Categoria, registrar
from .base import Check

CAMINHOS = {
    "/.env": (Severity.HIGH, "Arquivo de variaveis de ambiente (segredos)."),
    "/config.json": (Severity.MEDIUM, "Arquivo de configuracao."),
    "/settings.py": (Severity.HIGH, "Configuracao Django (pode conter SECRET_KEY)."),
    "/wp-config.php": (Severity.HIGH, "Configuracao WordPress."),
    "/.htpasswd": (Severity.HIGH, "Credenciais de autenticacao basica."),
    "/phpinfo.php": (Severity.MEDIUM, "Expoe configuracao do PHP."),
    "/.ssh/id_rsa": (Severity.CRITICAL, "Chave privada SSH."),
    "/server-status": (Severity.MEDIUM, "Status do Apache (mod_status)."),
    "/.DS_Store": (Severity.LOW, "Metadados do macOS, revela nomes de arquivos."),
}


def _parece_pagina_de_erro(texto: str) -> bool:
    t = texto.lower()
    return ("not found" in t or "404" in t or "<title>erro" in t) and len(texto) < 1500


@registrar("sensitive_paths", "Arquivos/caminhos sensiveis expostos", Categoria.ATIVO)
class SensitivePathsCheck(Check):
    def executar(self):
        achados = []
        for caminho, (sev, desc) in CAMINHOS.items():
            url = self.target.caminho(caminho)
            try:
                r = self.http.get(url)
            except Exception:
                continue
            if r.status_code == 200 and r.content and not _parece_pagina_de_erro(r.text):
                achados.append(
                    self.achado(
                        title=f"Caminho sensivel acessivel: {caminho}",
                        severity=sev,
                        confidence=Confidence.FIRM,
                        url=url,
                        description=desc,
                        evidence=f"HTTP 200, {len(r.content)} bytes.",
                        remediation="Bloqueie o acesso publico a este arquivo/rota.",
                        cwe="CWE-538",
                        owasp="A05:2021 Security Misconfiguration",
                    )
                )
        return achados
