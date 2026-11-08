"""Procura arquivos de backup/temporarios expostos (ativo)."""

from __future__ import annotations

from ..core.finding import Confidence, Severity
from ..core.registry import Categoria, registrar
from .base import Check

NOMES_FIXOS = {
    "/backup.zip": Severity.HIGH,
    "/backup.tar.gz": Severity.HIGH,
    "/db.sql": Severity.HIGH,
    "/dump.sql": Severity.HIGH,
    "/database.sql": Severity.HIGH,
    "/site.old": Severity.MEDIUM,
    "/index.php.bak": Severity.MEDIUM,
    "/config.php.bak": Severity.HIGH,
    "/.env.bak": Severity.HIGH,
    "/www.zip": Severity.HIGH,
    "/app.zip": Severity.HIGH,
}


def _parece_pagina_de_erro(texto: str) -> bool:
    t = texto.lower()
    return ("not found" in t or "404" in t or "<title>erro" in t or "<html" in t) and len(texto) < 1500


@registrar("backup_files", "Arquivos de backup/temporarios expostos", Categoria.ATIVO)
class BackupFilesCheck(Check):
    def executar(self):
        achados = []
        caminhos = dict(NOMES_FIXOS)
        host = self.target.host
        caminhos[f"/{host}.zip"] = Severity.MEDIUM
        caminhos[f"/{host}.sql"] = Severity.HIGH

        for caminho, sev in caminhos.items():
            url = self.target.caminho(caminho)
            try:
                r = self.http.get(url)
            except Exception:
                continue
            if r.status_code != 200:
                continue
            tamanho = len(r.content or b"")
            if tamanho <= 100:
                continue
            content_type = r.headers.get("Content-Type", "").lower()
            if "html" in content_type and _parece_pagina_de_erro(r.text):
                continue
            achados.append(
                self.achado(
                    title=f"Arquivo de backup exposto: {caminho}",
                    severity=sev,
                    confidence=Confidence.FIRM,
                    url=url,
                    description="Um arquivo de backup/dump acessivel publicamente "
                    "pode conter codigo-fonte, credenciais ou dados de banco.",
                    evidence=f"HTTP 200, {tamanho} bytes, Content-Type: "
                    f"{content_type or 'desconhecido'}",
                    remediation="Remova o arquivo do diretorio publico ou "
                    "bloqueie o acesso a ele via configuracao do servidor.",
                    cwe="CWE-530",
                    owasp="A05:2021 Security Misconfiguration",
                )
            )
        return achados
