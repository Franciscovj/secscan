"""Detecta listagem de diretorio habilitada (ativo)."""

from __future__ import annotations

from ..core.finding import Confidence, Severity
from ..core.registry import Categoria, registrar
from .base import Check

DIRS = ["/uploads/", "/files/", "/static/", "/assets/", "/images/", "/backup/",
        "/tmp/", "/download/", "/media/"]

MARCAS = ("index of /", "<title>index of", "directory listing for",
          "[to parent directory]")


@registrar("directory_listing", "Listagem de diretorio exposta", Categoria.ATIVO)
class DirectoryListingCheck(Check):
    def executar(self):
        achados = []
        for d in DIRS:
            url = self.target.caminho(d)
            try:
                r = self.http.get(url)
            except Exception:
                continue
            if r.status_code == 200:
                baixo = r.text.lower()
                if any(m in baixo for m in MARCAS):
                    achados.append(
                        self.achado(
                            title=f"Listagem de diretorio habilitada: {d}",
                            severity=Severity.MEDIUM,
                            confidence=Confidence.FIRM,
                            url=url,
                            description="O servidor lista o conteudo do diretorio, "
                            "expondo arquivos que nao deveriam ser enumerados.",
                            evidence="Pagina contem indice de diretorio.",
                            remediation="Desative o autoindex/directory listing "
                            "no servidor web.",
                            cwe="CWE-548",
                            owasp="A05:2021 Security Misconfiguration",
                        )
                    )
        return achados
