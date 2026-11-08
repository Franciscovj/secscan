"""Testa credenciais fracas em formularios de login (intrusivo).

Versao segura e educada da antiga `brute_force`: usa as wordlists do pacote,
mas com um LIMITE RIGIDO de tentativas (no maximo 25 no total, respeitando o
rate limit do HttpClient) para nao se tornar uma ferramenta de abuso. Serve
para confirmar que a aplicacao recusa as senhas mais obvias, nao para
quebrar senha de verdade.
"""

from __future__ import annotations

import os

from ..core.finding import Confidence, Severity
from ..core.registry import Categoria, registrar
from .base import Check

LIMITE_TENTATIVAS = 25

CAMINHOS_LOGIN = ["/login", "/admin/login", "/admin/login/", "/user/login", "/auth"]


def _carregar(nome: str) -> list[str]:
    caminho = os.path.join(os.path.dirname(__file__), "..", "wordlists", nome)
    try:
        with open(caminho, "r", encoding="utf-8") as f:
            return [linha.strip() for linha in f if linha.strip()]
    except OSError:
        return []


def _login_sucesso(r) -> bool:
    if r.status_code in (301, 302):
        cookie = r.headers.get("Set-Cookie", "").lower()
        if any(marca in cookie for marca in ("session", "sid", "auth")):
            return True
    corpo = r.text.lower()
    if "logout" in corpo or "sair" in corpo:
        return True
    return False


@registrar("weak_login", "Credenciais fracas em login", Categoria.INTRUSIVO)
class WeakLoginCheck(Check):
    def executar(self):
        achados = []
        usuarios = _carregar("users.txt")
        senhas = _carregar("passwords.txt")
        if not usuarios or not senhas:
            self.log("wordlists vazias ou nao encontradas")
            return achados

        login_url = None
        for caminho in CAMINHOS_LOGIN:
            url = self.target.caminho(caminho)
            try:
                r = self.http.get(url)
            except Exception:
                continue
            if r.status_code != 404:
                login_url = url
                break

        if login_url is None:
            self.log("nenhum formulario de login encontrado (tudo 404)")
            return achados

        self.log(f"testando no maximo {LIMITE_TENTATIVAS} combinacoes em {login_url}")
        tentativas = 0
        for usuario in usuarios:
            if tentativas >= LIMITE_TENTATIVAS:
                break
            for senha in senhas:
                if tentativas >= LIMITE_TENTATIVAS:
                    break
                tentativas += 1
                try:
                    r = self.http.post(
                        login_url,
                        data={"username": usuario, "password": senha},
                        allow_redirects=False,
                    )
                except Exception:
                    continue
                if _login_sucesso(r):
                    achados.append(
                        self.achado(
                            title="Credenciais fracas aceitas no login",
                            severity=Severity.HIGH,
                            confidence=Confidence.FIRM,
                            url=login_url,
                            description="O formulario de login aceitou uma "
                            "combinacao de usuario/senha presente em listas "
                            "publicas de credenciais comuns.",
                            evidence=f"usuario:senha = {usuario}:{senha}",
                            remediation="Exija senhas fortes, bloqueie apos "
                            "tentativas repetidas (rate limit/lockout) e use "
                            "autenticacao multifator.",
                            cwe="CWE-521",
                            owasp="A07:2021 Identification and Authentication Failures",
                        )
                    )
                    return achados
        self.log(f"nenhuma credencial fraca funcionou ({tentativas} tentativas)")
        return achados
