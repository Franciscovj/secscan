"""Representa e normaliza o alvo do scan (URL + host)."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass
class Target:
    """Alvo normalizado.

    url:  URL base, sempre com esquema e sem barra final dupla.
    host: nome do host (sem esquema, sem barra, sem porta).
    port: porta explicita da URL, ou None.
    scheme: 'http' ou 'https'.
    """

    url: str
    host: str
    scheme: str
    port: int | None = None

    @classmethod
    def parse(cls, entrada: str) -> "Target":
        bruto = (entrada or "").strip()
        if not bruto:
            raise ValueError("Alvo vazio.")
        if "://" not in bruto:
            bruto = "http://" + bruto
        p = urlparse(bruto)
        if not p.hostname:
            raise ValueError(f"Nao consegui extrair o host de: {entrada!r}")
        scheme = p.scheme.lower() if p.scheme else "http"
        if scheme not in ("http", "https"):
            raise ValueError(f"Esquema nao suportado: {scheme}")
        url = f"{scheme}://{p.netloc}{p.path}".rstrip("/")
        if not url:
            url = f"{scheme}://{p.netloc}"
        return cls(url=url, host=p.hostname, scheme=scheme, port=p.port)

    def caminho(self, path: str) -> str:
        """Junta um caminho a URL base de forma segura."""
        return self.url.rstrip("/") + "/" + path.lstrip("/")
