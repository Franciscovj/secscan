"""Detecta modo debug/stacktrace exposto (ativo).

Acessa uma rota inexistente (aleatoria) para tentar forcar um erro e procura
marcadores fortes de paginas de debug dos frameworks mais comuns. So acusa
com marcadores fortes, para evitar falso positivo com uma pagina de erro
generica.
"""

from __future__ import annotations

import random
import string

from ..core.finding import Confidence, Severity
from ..core.registry import Categoria, registrar
from .base import Check

MARCADORES = {
    "Django": ["traceback", "exception value", "request method", "django"],
    "Flask/Werkzeug": ["werkzeug debugger", "traceback (most recent call last)"],
    "Rails": ["actioncontroller::routingerror", "rails.root"],
    "Laravel": ["whoops", "stack trace"],
    "ASP.NET": ["server error in"],
}


def _rota_aleatoria() -> str:
    sufixo = "".join(random.choices(string.ascii_lowercase + string.digits, k=10))
    return f"/secscan-nao-existe-{sufixo}"


@registrar("debug_mode", "Modo debug ativo", Categoria.ATIVO)
class DebugModeCheck(Check):
    def executar(self):
        achados = []
        url = self.target.caminho(_rota_aleatoria())
        self.log(f"forcando erro em {url}")
        try:
            r = self.http.get(url)
        except Exception as e:
            self.log(f"falha ao buscar: {e}")
            return achados

        corpo = r.text.lower()
        for framework, marcadores in MARCADORES.items():
            if framework == "Django":
                # Django precisa dos tres marcadores juntos para ser forte
                if all(m in corpo for m in marcadores[:3]) and "django" in corpo:
                    achados.append(self._achado_framework(framework, url, corpo))
                continue
            if all(m in corpo for m in marcadores):
                achados.append(self._achado_framework(framework, url, corpo))
        return achados

    def _achado_framework(self, framework: str, url: str, corpo: str):
        return self.achado(
            title=f"Modo debug ativo ({framework})",
            severity=Severity.HIGH,
            confidence=Confidence.FIRM,
            url=url,
            description="Uma rota invalida gerou uma pagina de debug com "
            "stacktrace, revelando caminhos internos, versoes e, em alguns "
            "frameworks, permitindo execucao de codigo pelo proprio debugger.",
            evidence=f"marcadores de {framework} encontrados na resposta de erro",
            remediation="Desative o modo debug em producao e use uma pagina "
            "de erro generica.",
            cwe="CWE-489",
            owasp="A05:2021 Security Misconfiguration",
        )
