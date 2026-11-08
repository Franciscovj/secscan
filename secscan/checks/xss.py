"""Detecta XSS refletido (intrusivo).

Injeta um canario UNICO (token aleatorio + tag HTML) em parametros comuns via
GET e em campos de formulario (via html.parser), e verifica se o canario
volta refletido sem escape no HTML da resposta. O token unico por execucao
evita falso positivo com conteudo que por acaso parece o payload.
"""

from __future__ import annotations

import random
import string
from html.parser import HTMLParser

from ..core.finding import Confidence, Severity
from ..core.registry import Categoria, registrar
from .base import Check

PARAMS = ["q", "search", "id", "page", "query", "s", "keyword"]


def _token() -> str:
    sufixo = "".join(random.choices(string.ascii_lowercase + string.digits, k=5))
    return f"sxsk{sufixo}"


class _FormParser(HTMLParser):
    """Extrai forms (action, method) e seus campos <input name=...>."""

    def __init__(self) -> None:
        super().__init__()
        self.forms: list[dict] = []
        self._atual: dict | None = None

    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        if tag == "form":
            self._atual = {
                "action": d.get("action", ""),
                "method": (d.get("method") or "get").lower(),
                "campos": [],
            }
            self.forms.append(self._atual)
        elif tag == "input" and self._atual is not None:
            nome = d.get("name")
            if nome:
                self._atual["campos"].append(nome)

    def handle_endtag(self, tag):
        if tag == "form":
            self._atual = None


@registrar("xss", "XSS refletido", Categoria.INTRUSIVO)
class XssCheck(Check):
    def _reflete_sem_escape(self, texto: str, payload: str) -> bool:
        return payload in texto

    def executar(self):
        achados = []
        vistos = set()

        self.log("testando parametros comuns via GET")
        for param in PARAMS:
            token = _token()
            payload = f"<svg/onload={token}>"
            try:
                r = self.http.get(self.target.url, params={param: payload})
            except Exception:
                continue
            if self._reflete_sem_escape(r.text, payload) and param not in vistos:
                vistos.add(param)
                achados.append(
                    self.achado(
                        title=f"XSS refletido no parametro '{param}'",
                        severity=Severity.HIGH,
                        confidence=Confidence.FIRM,
                        url=f"{self.target.url}?{param}={payload}",
                        description="O valor do parametro volta no HTML sem escape, "
                        "permitindo injetar script/markup executavel no navegador "
                        "da vitima.",
                        evidence=f"payload={payload!r} refletido literalmente na resposta",
                        remediation="Faca escape de saida (HTML entities) de acordo "
                        "com o contexto e valide a entrada.",
                        cwe="CWE-79",
                        owasp="A03:2021 Injection",
                    )
                )

        self.log("extraindo formularios da home")
        try:
            r = self.http.get(self.target.url)
        except Exception as e:
            self.log(f"falha ao buscar home: {e}")
            return achados

        parser = _FormParser()
        try:
            parser.feed(r.text)
        except Exception:
            return achados

        for form in parser.forms:
            action = form["action"] or self.target.url
            url_form = action if action.startswith("http") else self.target.caminho(action)
            metodo = form["method"]
            for campo in form["campos"]:
                chave = (url_form, metodo, campo)
                if chave in vistos:
                    continue
                token = _token()
                payload = f"<svg/onload={token}>"
                try:
                    if metodo == "post":
                        resp = self.http.post(url_form, data={campo: payload})
                    else:
                        resp = self.http.get(url_form, params={campo: payload})
                except Exception:
                    continue
                if self._reflete_sem_escape(resp.text, payload):
                    vistos.add(chave)
                    achados.append(
                        self.achado(
                            title=f"XSS refletido no campo de formulario '{campo}'",
                            severity=Severity.HIGH,
                            confidence=Confidence.FIRM,
                            url=url_form,
                            description="O valor enviado pelo formulario volta no "
                            "HTML sem escape, permitindo injetar markup/script.",
                            evidence=f"campo={campo} metodo={metodo.upper()} "
                            f"payload={payload!r} refletido literalmente",
                            remediation="Faca escape de saida (HTML entities) de "
                            "acordo com o contexto e valide a entrada.",
                            cwe="CWE-79",
                            owasp="A03:2021 Injection",
                        )
                    )
        return achados
