"""Detecta SSRF (Server-Side Request Forgery) em parametros com cara de URL (intrusivo).

Deteccao best-effort baseada em canario refletido: enviamos uma URL com um
token unico e verificamos se o token volta no corpo da resposta, o que indica
que o servidor processou/buscou o destino. Isso NAO confirma SSRF cego: uma
confirmacao real exige um listener out-of-band (OOB) recebendo a requisicao de
fato. Por isso a confianca aqui e TENTATIVE, salvo quando ha reflexo claro do
token na resposta.
"""

from __future__ import annotations

import secrets

from ..core.finding import Confidence, Severity
from ..core.registry import Categoria, registrar
from .base import Check

PARAMS = [
    "url", "uri", "link", "src", "dest", "destination", "redirect", "fetch",
    "load", "image", "img", "file", "path", "callback", "webhook", "proxy",
    "feed", "host", "domain", "continue", "next", "open", "view", "site",
    "target", "to", "out",
]
ROTAS = ["", "/fetch", "/proxy", "/api/fetch", "/redirect"]


@registrar("ssrf", "SSRF (Server-Side Request Forgery)", Categoria.INTRUSIVO)
class SsrfCheck(Check):
    def executar(self):
        achados = []
        vistos = set()

        for rota in ROTAS:
            base = self.target.url if not rota else self.target.caminho(rota)
            for param in PARAMS:
                if param in vistos:
                    continue
                token = "ssrf" + secrets.token_hex(4)
                valor = f"http://{token}.secscan.invalid/probe"
                try:
                    r = self.http.get(base, params={param: valor})
                except Exception:
                    continue
                if token in r.text:
                    vistos.add(param)
                    achados.append(
                        self.achado(
                            title=f"Possivel SSRF via parametro '{param}'",
                            severity=Severity.MEDIUM,
                            confidence=Confidence.TENTATIVE,
                            url=f"{base}?{param}={valor}",
                            description="O parametro aceita uma URL e o servidor "
                            "parece busca-la ou refleti-la, o que pode permitir "
                            "forcar o servidor a fazer requisicoes a destinos "
                            "internos ou arbitrarios (SSRF).",
                            evidence=f"param={param!r}: o token canario "
                            f"{token!r} enviado em {valor!r} voltou no corpo da "
                            "resposta, indicando que o servidor processou a URL.",
                            remediation="Valide o destino contra uma allowlist de "
                            "hosts/esquemas permitidos, bloqueie IPs internos e de "
                            "metadata (169.254.169.254, 127.0.0.1, ranges privados) "
                            "e nao siga redirecionamentos sem revalidar.",
                            cwe="CWE-918",
                            owasp="A10:2021 Server-Side Request Forgery",
                        )
                    )
        return achados
