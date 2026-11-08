"""Check de SQL Injection (intrusivo).

Melhorias sobre a versao antiga:
  - compara com uma LINHA DE BASE: a assinatura de erro so conta se aparecer
    com o payload e NAO aparecer na resposta benigna (corta falso-positivo);
  - time-based mede o tempo da resposta benigna antes e exige um atraso bem
    acima dele, com uma segunda confirmacao, para nao acusar site lento.

So roda sob autorizacao (categoria intrusiva).
"""

from __future__ import annotations

import re
import time

from ..core.finding import Confidence, Severity
from ..core.registry import Categoria, registrar
from .base import Check

PARAMS = ["id", "user", "search", "q", "page", "cat", "item", "pid"]

PAYLOADS_ERRO = ["'", "\"", "')", "';"]

ASSINATURAS = [
    r"you have an error in your sql syntax",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"sql syntax.*mysql",
    r"warning.*\bmysqli?_",
    r"ora-\d{5}",
    r"postgresql.*error",
    r"pg_query\(\)",
    r"sqlite3?::",
    r"sqlstate\[",
    r"microsoft (ole db|sql)",
    r"odbc sql server driver",
    r"incorrect syntax near",
    r"npgsql\.",
    r"system\.data\.sqlclient",
]
_RX = [re.compile(s, re.IGNORECASE) for s in ASSINATURAS]


def _assinatura(texto: str):
    for rx in _RX:
        if rx.search(texto):
            return rx.pattern
    return None


@registrar("sql_injection", "SQL Injection (erro e tempo)", Categoria.INTRUSIVO)
class SqlInjectionCheck(Check):
    def _baseline(self, param):
        """(texto_benigno, tempo_benigno) para o parametro."""
        try:
            t0 = time.time()
            r = self.http.get(self.target.url, params={param: "1"})
            return r.text, time.time() - t0
        except Exception:
            return "", 0.0

    def executar(self):
        achados = []
        vistos = set()

        self.log("injecao baseada em erro")
        for param in PARAMS:
            base_txt, _ = self._baseline(param)
            base_sig = _assinatura(base_txt)
            for payload in PAYLOADS_ERRO:
                try:
                    r = self.http.get(self.target.url, params={param: "1" + payload})
                except Exception:
                    continue
                sig = _assinatura(r.text)
                if sig and sig != base_sig and param not in vistos:
                    vistos.add(param)
                    achados.append(
                        self.achado(
                            title=f"SQL Injection baseada em erro no parametro '{param}'",
                            severity=Severity.HIGH,
                            confidence=Confidence.FIRM,
                            url=self.target.url,
                            description="Enviar um caractere de aspa no parametro "
                            "provoca uma mensagem de erro de banco, indicando que a "
                            "entrada chega a consulta sem tratamento.",
                            evidence=f"param={param} payload={payload!r} "
                            f"assinatura={sig!r}",
                            remediation="Use consultas parametrizadas (prepared "
                            "statements) e nunca concatene entrada na query.",
                            cwe="CWE-89",
                            owasp="A03:2021 Injection",
                        )
                    )
                    break

        self.log("injecao baseada em tempo")
        for param in ("id", "user"):
            if param in vistos:
                continue
            _, base_t = self._baseline(param)
            limite = max(4.0, base_t * 2 + 3.0)
            payload = "1' AND (SELECT 1 FROM (SELECT SLEEP(4))x)-- -"
            try:
                t0 = time.time()
                self.http.get(self.target.url, params={param: payload}, timeout=15)
                dt = time.time() - t0
            except Exception:
                continue
            if dt >= limite:
                # confirma uma vez para descartar lentidao pontual
                try:
                    t1 = time.time()
                    self.http.get(self.target.url, params={param: payload}, timeout=15)
                    dt2 = time.time() - t1
                except Exception:
                    dt2 = 0.0
                if dt2 >= limite:
                    achados.append(
                        self.achado(
                            title=f"SQL Injection baseada em tempo no parametro '{param}'",
                            severity=Severity.HIGH,
                            confidence=Confidence.FIRM,
                            url=self.target.url,
                            description="Um payload que pede atraso no banco faz a "
                            "resposta demorar de forma consistente, indicando injecao "
                            "cega baseada em tempo.",
                            evidence=f"param={param} atraso={dt:.1f}s e {dt2:.1f}s "
                            f"(base {base_t:.1f}s, limite {limite:.1f}s)",
                            remediation="Use consultas parametrizadas; valide e "
                            "restrinja a entrada.",
                            cwe="CWE-89",
                            owasp="A03:2021 Injection",
                        )
                    )
        return achados
