"""Detecta redirecionamento aberto em parametros comuns (ativo).

Envia um destino externo controlado em parametros tipicos (next, url, redirect)
e verifica se o servidor responde com um 3xx apontando para esse destino.
"""

from __future__ import annotations

from urllib.parse import urlparse

from ..core.finding import Confidence, Severity
from ..core.registry import Categoria, registrar
from .base import Check

PARAMS = ["next", "url", "redirect", "redirect_url", "return", "returnTo",
          "dest", "destination", "continue", "r", "u"]
CANARIO = "https://example.org/secscan-canary"


@registrar("open_redirect", "Redirecionamento aberto (open redirect)", Categoria.ATIVO)
class OpenRedirectCheck(Check):
    def executar(self):
        achados = []
        rotas = ["", "/redir", "/redirect", "/login", "/logout", "/go"]
        testados = set()
        for rota in rotas:
            base = self.target.caminho(rota) if rota else self.target.url
            for p in PARAMS:
                chave = (base, p)
                if chave in testados:
                    continue
                testados.add(chave)
                try:
                    r = self.http.get(
                        base, params={p: CANARIO}, allow_redirects=False
                    )
                except Exception:
                    continue
                if r.status_code in (301, 302, 303, 307, 308):
                    loc = r.headers.get("Location", "")
                    host_loc = urlparse(loc).netloc
                    if host_loc == "example.org":
                        achados.append(
                            self.achado(
                                title=f"Redirecionamento aberto via '{p}'",
                                severity=Severity.MEDIUM,
                                confidence=Confidence.CONFIRMED,
                                url=f"{base}?{p}={CANARIO}",
                                description="O parametro controla o destino do "
                                "redirecionamento sem validar o dominio, util para "
                                "phishing.",
                                evidence=f"HTTP {r.status_code}, Location: {loc}",
                                remediation="Valide o destino contra uma lista de "
                                "dominios permitidos ou use caminhos relativos.",
                                cwe="CWE-601",
                                owasp="A01:2021 Broken Access Control",
                            )
                        )
        return achados
