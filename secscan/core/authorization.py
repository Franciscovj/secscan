"""Trava de autorizacao.

Checks intrusivos (injecao, forca bruta) so rodam contra alvos que o usuario
confirmou ter permissao para testar. Escanear sistema de terceiro sem
autorizacao e ilegal em muitos lugares; a ferramenta nao deve facilitar isso.

Como se autoriza (qualquer um basta):
  - flag --autorizo na CLI;
  - variavel de ambiente SECSCAN_AUTORIZADO=1;
  - confirmacao interativa (digitar o host), quando houver terminal.
"""

from __future__ import annotations

import os
import sys


class AutorizacaoNegada(Exception):
    pass


def host_privado_ou_local(host: str) -> bool:
    """Alvos locais/privados sao sempre liberados (laboratorio, selftest)."""
    h = (host or "").lower()
    if h in ("localhost", "127.0.0.1", "::1"):
        return True
    if h.endswith(".localhost") or h.endswith(".test") or h.endswith(".local"):
        return True
    if h.startswith("10.") or h.startswith("192.168."):
        return True
    if h.startswith("172."):
        try:
            segundo = int(h.split(".")[1])
            if 16 <= segundo <= 31:
                return True
        except (IndexError, ValueError):
            pass
    return False


def garantir_autorizacao(
    host: str,
    autorizo_flag: bool,
    interativo: bool = True,
) -> None:
    """Levanta AutorizacaoNegada se o alvo intrusivo nao estiver autorizado."""
    if host_privado_ou_local(host):
        return
    if autorizo_flag:
        return
    if os.environ.get("SECSCAN_AUTORIZADO") in ("1", "true", "sim"):
        return
    if interativo and sys.stdin and sys.stdin.isatty():
        print(
            "\n[AUTORIZACAO] Checks intrusivos (injecao, forca bruta) so devem "
            "rodar em alvos que voce possui ou tem permissao escrita para testar."
        )
        resposta = input(
            f"Digite o host '{host}' para confirmar que esta autorizado "
            f"(ou Enter para pular os intrusivos): "
        ).strip()
        if resposta == host:
            return
        raise AutorizacaoNegada(
            "Autorizacao nao confirmada: checks intrusivos serao pulados."
        )
    raise AutorizacaoNegada(
        "Alvo externo sem autorizacao. Use --autorizo (ou SECSCAN_AUTORIZADO=1) "
        "apenas em alvos seus ou com permissao escrita."
    )
