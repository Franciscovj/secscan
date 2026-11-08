"""Detecta diretorio de controle de versao exposto: /.git, /.svn, /.hg (ativo)."""

from __future__ import annotations

from ..core.finding import Confidence, Severity
from ..core.registry import Categoria, registrar
from .base import Check

ALVOS = {
    "/.git/HEAD": ("ref:", "Repositorio Git exposto — o codigo-fonte pode ser baixado."),
    "/.git/config": ("[core]", "Config do Git exposta."),
    "/.svn/entries": ("", "Metadados Subversion expostos."),
    "/.hg/requires": ("", "Metadados Mercurial expostos."),
}


@registrar("git_exposure", "Diretorio de versionamento exposto (.git/.svn)", Categoria.ATIVO)
class GitExposureCheck(Check):
    def executar(self):
        achados = []
        for caminho, (marca, desc) in ALVOS.items():
            url = self.target.caminho(caminho)
            try:
                r = self.http.get(url)
            except Exception:
                continue
            if r.status_code == 200 and (marca == "" or marca in r.text[:200]):
                achados.append(
                    self.achado(
                        title=f"Versionamento exposto: {caminho}",
                        severity=Severity.HIGH,
                        confidence=Confidence.CONFIRMED,
                        url=url,
                        description=desc,
                        evidence=f"HTTP 200, inicio: {r.text[:60]!r}",
                        remediation="Negue acesso publico a .git/.svn/.hg no servidor "
                        "web e nao publique esses diretorios.",
                        cwe="CWE-527",
                        owasp="A05:2021 Security Misconfiguration",
                    )
                )
        return achados
