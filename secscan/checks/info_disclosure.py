"""Procura vazamento de informacao no conteudo servido (passivo)."""

from __future__ import annotations

import re

from ..core.finding import Confidence, Severity
from ..core.registry import Categoria, registrar
from .base import Check

LIMITE_POR_TIPO = 10

RE_EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
RE_IP_PRIVADO = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b"
)
RE_AWS = re.compile(r"AKIA[0-9A-Z]{16}")
CHAVES_PRIVADAS = ("BEGIN RSA PRIVATE KEY", "BEGIN PRIVATE KEY")

# tipo -> (titulo, severidade, descricao)
TIPOS = {
    "email": ("E-mail exposto no conteudo", Severity.LOW,
              "Endereco de e-mail visivel no conteudo servido."),
    "ip": ("IP privado exposto no conteudo", Severity.LOW,
           "Endereco IP de rede interna visivel no conteudo servido."),
    "aws": ("Chave de acesso AWS exposta", Severity.HIGH,
            "Possivel chave de acesso AWS (AKIA...) no conteudo servido."),
    "chave": ("Chave privada exposta", Severity.HIGH,
              "Marcador de chave privada no conteudo servido."),
}


@registrar("info_disclosure", "Vazamento de informacao no conteudo", Categoria.PASSIVO)
class InfoDisclosureCheck(Check):
    def executar(self):
        achados = []
        self.log("varrendo o conteudo da home")
        try:
            r = self.http.get(self.target.url)
            texto = r.text or ""
        except Exception as e:
            self.log(f"falha ao buscar: {e}")
            return achados

        def unicos(valores):
            vistos = []
            for v in valores:
                if v not in vistos:
                    vistos.append(v)
            return vistos[:LIMITE_POR_TIPO]

        encontrados = {
            "email": unicos(RE_EMAIL.findall(texto)),
            "ip": unicos(RE_IP_PRIVADO.findall(texto)),
            "aws": unicos(RE_AWS.findall(texto)),
            "chave": [m for m in CHAVES_PRIVADAS if m in texto],
        }

        for tipo, valores in encontrados.items():
            titulo, sev, descricao = TIPOS[tipo]
            for valor in valores:
                achados.append(
                    self.achado(
                        title=titulo,
                        severity=sev,
                        confidence=Confidence.FIRM,
                        url=self.target.url,
                        description=descricao,
                        evidence=valor[:80],
                        remediation="Remova dados internos do HTML/JS servido "
                        "e revogue/rotacione credenciais expostas.",
                        cwe="CWE-200",
                        owasp="A01:2021 Broken Access Control",
                    )
                )
        return achados
