"""Detecta ausencia de proteção CSRF em formularios POST (ativo).

Busca a home, extrai formularios com html.parser e verifica se cada form
POST tem algum campo com cara de token anti-CSRF. Formularios GET nao sao
acusados (GET nao deveria causar efeito colateral, entao nao e alvo de CSRF
classico).
"""

from __future__ import annotations

from html.parser import HTMLParser

from ..core.finding import Confidence, Severity
from ..core.registry import Categoria, registrar
from .base import Check

NOMES_TOKEN = ("csrf", "token", "authenticity", "_token", "csrfmiddlewaretoken", "xsrf")


class _FormParser(HTMLParser):
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


def _tem_token(campos: list[str]) -> bool:
    for c in campos:
        cl = c.lower()
        if any(n in cl for n in NOMES_TOKEN):
            return True
    return False


@registrar("csrf", "Ausencia de protecao CSRF", Categoria.ATIVO)
class CsrfCheck(Check):
    def executar(self):
        achados = []
        self.log("buscando formularios POST na home")
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
            if form["method"] != "post":
                continue
            if _tem_token(form["campos"]):
                continue
            action = form["action"] or self.target.url
            url_form = action if action.startswith("http") else self.target.caminho(action)
            achados.append(
                self.achado(
                    title="Formulario POST sem token anti-CSRF aparente",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.TENTATIVE,
                    url=url_form,
                    description="O formulario envia POST mas nenhum campo tem "
                    "nome que indique um token anti-CSRF, sugerindo que a acao "
                    "pode ser forjada a partir de outro site.",
                    evidence=f"campos encontrados: {form['campos']!r}",
                    remediation="Gere um token CSRF por sessao/formulario e "
                    "valide-o no servidor antes de processar o POST.",
                    cwe="CWE-352",
                    owasp="A01:2021 Broken Access Control",
                )
            )
        return achados
