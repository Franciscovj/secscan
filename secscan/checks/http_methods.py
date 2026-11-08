"""Detecta metodos HTTP perigosos habilitados via OPTIONS (ativo)."""

from __future__ import annotations

from ..core.finding import Confidence, Severity
from ..core.registry import Categoria, registrar
from .base import Check

# metodo -> (titulo, cwe, descricao)
PERIGOSOS = {
    "TRACE": ("Metodo TRACE habilitado (risco de XST)", "CWE-693",
              "TRACE devolve a requisicao ao cliente e pode ser usado em "
              "Cross-Site Tracing para roubar cabecalhos sensiveis."),
    "PUT": ("Metodo PUT habilitado", "CWE-650",
            "PUT pode permitir criar ou sobrescrever recursos no servidor."),
    "DELETE": ("Metodo DELETE habilitado", "CWE-650",
               "DELETE pode permitir remover recursos no servidor."),
    "CONNECT": ("Metodo CONNECT habilitado", "CWE-650",
                "CONNECT pode permitir uso do servidor como proxy/tunel."),
}


@registrar("http_methods", "Metodos HTTP perigosos habilitados", Categoria.ATIVO)
class HttpMethodsCheck(Check):
    def executar(self):
        achados = []
        self.log("enviando OPTIONS")
        try:
            r = self.http.options(self.target.url)
        except Exception as e:
            self.log(f"falha no OPTIONS: {e}")
            return achados
        allow = r.headers.get("Allow", "")
        if not allow.strip():
            return achados
        metodos = {m.strip().upper() for m in allow.split(",") if m.strip()}

        for metodo, (titulo, cwe, descricao) in PERIGOSOS.items():
            if metodo in metodos:
                achados.append(
                    self.achado(
                        title=titulo,
                        severity=Severity.MEDIUM,
                        confidence=Confidence.FIRM,
                        url=self.target.url,
                        description=descricao,
                        evidence=f"Allow: {allow}",
                        remediation="Desabilite no servidor/aplicacao os "
                        "metodos HTTP que nao sao usados.",
                        cwe=cwe,
                        owasp="A05:2021 Security Misconfiguration",
                    )
                )
        return achados
