"""Camada de aparencia da CLI: cores ANSI, banner e ajudinhas visuais.

As cores saem so quando faz sentido (terminal de verdade, sem NO_COLOR). Em
pipe/arquivo ou com NO_COLOR, tudo vira texto puro — assim a saida JSON nunca
e suja por codigos de cor. No Windows, habilita o processamento ANSI do
console (VT) quando possivel.
"""

from __future__ import annotations

import os
import sys

from .core.finding import Severity

# ---- deteccao de suporte a cor -------------------------------------------

def _habilita_vt_windows() -> bool:
    if os.name != "nt":
        return True
    try:
        import ctypes

        k = ctypes.windll.kernel32
        # ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004, handle stdout = -11
        h = k.GetStdHandle(-11)
        modo = ctypes.c_uint32()
        if not k.GetConsoleMode(h, ctypes.byref(modo)):
            return False
        return bool(k.SetConsoleMode(h, modo.value | 0x0004))
    except Exception:
        return False


def suporta_cor(stream=None) -> bool:
    stream = stream or sys.stderr
    if os.environ.get("NO_COLOR") is not None:
        return False
    if os.environ.get("SECSCAN_NO_COLOR"):
        return False
    if not hasattr(stream, "isatty") or not stream.isatty():
        return False
    return _habilita_vt_windows()


# ---- paleta ---------------------------------------------------------------

_CODIGOS = {
    "reset": "0",
    "bold": "1",
    "dim": "2",
    "vermelho": "31",
    "verde": "32",
    "amarelo": "33",
    "azul": "34",
    "magenta": "35",
    "ciano": "36",
    "cinza": "90",
    "vermelho_claro": "91",
    "verde_claro": "92",
    "amarelo_claro": "93",
}

_COR_SEVERIDADE = {
    Severity.CRITICAL: "magenta",
    Severity.HIGH: "vermelho",
    Severity.MEDIUM: "amarelo",
    Severity.LOW: "azul",
    Severity.INFO: "cinza",
}


class Estilo:
    """Fabrica de texto colorido; vira no-op quando cor nao e suportada."""

    def __init__(self, ativo: bool) -> None:
        self.ativo = ativo

    def c(self, texto: str, *cores: str) -> str:
        if not self.ativo or not cores:
            return texto
        prefixo = "".join(f"\033[{_CODIGOS[x]}m" for x in cores if x in _CODIGOS)
        return f"{prefixo}{texto}\033[0m"

    def severidade(self, sev: Severity, texto: str | None = None) -> str:
        return self.c(texto if texto is not None else sev.rotulo,
                      _COR_SEVERIDADE[sev], "bold")


def banner(estilo: Estilo, versao: str) -> str:
    arte = r"""
  ___ ___ ___ ___ ___ __ _ _ _
 / __| __/ __/ __/ __/ _` | ' \
 \__ \ _| (__\__ \ (_| (_| | || |
 |___/___\___|___/___\__,_|_||_|"""
    linhas = arte.strip("\n").split("\n")
    pintado = "\n".join(estilo.c(l, "ciano", "bold") for l in linhas)
    sub = estilo.c(f"  auditoria de seguranca web · v{versao} · uso autorizado",
                   "cinza")
    return f"{pintado}\n{sub}\n"


def regua(estilo: Estilo, largura: int = 60) -> str:
    return estilo.c("─" * largura, "cinza")
