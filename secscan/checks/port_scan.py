"""Varre portas abertas no host (ativo, alvo = host).

Reescreve o antigo `port_scanner` usando socket + ThreadPoolExecutor para
testar um conjunto de portas comuns em paralelo, com timeout curto por porta.
Portas associadas a servicos sensiveis (bancos, acesso remoto, paineis)
geram achado de severidade mais alta.
"""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..core.finding import Confidence, Severity
from ..core.registry import Categoria, registrar, TipoAlvo
from .base import Check

PORTAS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995,
    1433, 1521, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 8888,
    9000, 9200, 27017,
]

PORTAS_ALTO_RISCO = {21, 22, 23, 3389, 5432, 3306, 1433, 6379, 9200, 27017, 5900}

TIMEOUT = 1.0
MAX_WORKERS = 20


def _nome_servico(porta: int) -> str:
    try:
        return socket.getservbyport(porta)
    except OSError:
        return "desconhecido"


@registrar("port_scan", "Portas abertas", Categoria.ATIVO, TipoAlvo.HOST)
class PortScanCheck(Check):
    def _testar_porta(self, porta: int) -> bool:
        try:
            with socket.create_connection((self.target.host, porta), timeout=TIMEOUT):
                return True
        except Exception:
            return False

    def executar(self):
        achados = []
        self.log(f"testando {len(PORTAS)} portas em {self.target.host}")
        abertas = []
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
            futuros = {pool.submit(self._testar_porta, p): p for p in PORTAS}
            for fut in as_completed(futuros):
                porta = futuros[fut]
                try:
                    if fut.result():
                        abertas.append(porta)
                except Exception:
                    continue

        for porta in sorted(abertas):
            servico = _nome_servico(porta)
            if porta in PORTAS_ALTO_RISCO:
                achados.append(
                    self.achado(
                        title=f"Porta de servico sensivel exposta: {porta} ({servico})",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.CONFIRMED,
                        url=self.target.host,
                        description="A porta esta aberta e corresponde a um "
                        "servico tipicamente administrativo ou de banco de "
                        "dados, que nao deveria ficar acessivel publicamente.",
                        evidence=f"porta {porta}/tcp aberta, servico: {servico}",
                        remediation="Restrinja o acesso a esta porta por "
                        "firewall/VPN, ou desative o servico se nao for "
                        "necessario expo-lo.",
                        cwe="CWE-200",
                        owasp="A05:2021 Security Misconfiguration",
                    )
                )
            else:
                achados.append(
                    self.achado(
                        title=f"Porta aberta: {porta} ({servico})",
                        severity=Severity.INFO,
                        confidence=Confidence.CONFIRMED,
                        url=self.target.host,
                        description="A porta respondeu a conexao TCP.",
                        evidence=f"porta {porta}/tcp aberta, servico: {servico}",
                        remediation="Confirme que o servico precisa estar "
                        "exposto publicamente.",
                        cwe="CWE-200",
                        owasp="A05:2021 Security Misconfiguration",
                    )
                )
        return achados
