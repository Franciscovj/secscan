"""Enumeracao de subdominios por DNS (ativo, alvo = host).

Resolve uma lista de subdominios comuns sob o dominio do alvo via DNS e reporta
os que existem. E reconhecimento: nao bate no servidor web do alvo, so faz
consultas de DNS. Cada subdominio encontrado vira um achado INFO (superficie de
ataque a mapear). Falha de rede e tratada: devolve lista vazia sem derrubar.
"""

from __future__ import annotations

import os
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..core.finding import Confidence, Severity
from ..core.registry import Categoria, TipoAlvo, registrar
from .base import Check

MAX_WORKERS = 20


def _dominio_base(host: str) -> str:
    """Remove um 'www.' inicial para enumerar sob o dominio raiz."""
    h = (host or "").strip().lower().rstrip(".")
    if h.startswith("www."):
        h = h[4:]
    return h


def _carregar_subs() -> list[str]:
    caminho = os.path.join(os.path.dirname(__file__), "..", "wordlists", "subdomains.txt")
    try:
        with open(caminho, "r", encoding="utf-8") as f:
            return [l.strip() for l in f if l.strip() and not l.startswith("#")]
    except OSError:
        return []


@registrar("subdomain_enum", "Enumeracao de subdominios (DNS)", Categoria.ATIVO,
           TipoAlvo.HOST)
class SubdomainEnumCheck(Check):
    def _resolve(self, fqdn: str) -> tuple[str, list[str]] | None:
        try:
            infos = socket.getaddrinfo(fqdn, None)
            ips = sorted({i[4][0] for i in infos})
            return fqdn, ips
        except (socket.gaierror, socket.timeout, OSError):
            return None

    def executar(self):
        achados = []
        base = _dominio_base(self.target.host)
        # alvo e um IP cru -> nao da para enumerar subdominio
        if not base or base.replace(".", "").isdigit():
            self.log("alvo sem dominio para enumerar")
            return achados

        subs = _carregar_subs()
        if not subs:
            self.log("wordlist de subdominios vazia")
            return achados

        self.log(f"resolvendo {len(subs)} subdominios sob {base}")
        encontrados: list[tuple[str, list[str]]] = []
        socket.setdefaulttimeout(3.0)
        try:
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
                futuros = [pool.submit(self._resolve, f"{s}.{base}") for s in subs]
                for fut in as_completed(futuros):
                    r = fut.result()
                    if r:
                        encontrados.append(r)
        finally:
            socket.setdefaulttimeout(None)

        for fqdn, ips in sorted(encontrados):
            achados.append(
                self.achado(
                    title=f"Subdominio ativo: {fqdn}",
                    severity=Severity.INFO,
                    confidence=Confidence.CONFIRMED,
                    url=fqdn,
                    description="Subdominio que resolve em DNS — faz parte da "
                    "superficie de ataque e deve ser auditado tambem.",
                    evidence=f"{fqdn} -> {', '.join(ips)}",
                    remediation="Confirme que este subdominio deve existir e esta "
                    "atualizado; remova registros DNS orfaos (risco de takeover).",
                    cwe="CWE-200",
                    owasp="A05:2021 Security Misconfiguration",
                    extra={"ips": ips},
                )
            )
        return achados
