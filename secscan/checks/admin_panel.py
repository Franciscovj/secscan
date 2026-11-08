"""Verifica exposicao de painel administrativo (ativo).

Reescreve o antigo `admin_check`: testa uma lista de caminhos comuns de
painel e classifica o resultado (exposto sem protecao, protegido por auth,
ou redirecionado para login) em vez de simplesmente acusar tudo que responde.
No maximo um achado por caminho, para nao gerar ruido.
"""

from __future__ import annotations

from ..core.finding import Confidence, Severity
from ..core.registry import Categoria, registrar
from .base import Check

CAMINHOS = [
    "/admin",
    "/admin/",
    "/administrator",
    "/wp-admin",
    "/cpanel",
    "/manage",
    "/dashboard",
    "/phpmyadmin",
]

PALAVRAS_LOGIN = ("login", "senha", "password", "username", "usuário", "usuario", "entrar", "sign in")


@registrar("admin_panel", "Painel administrativo exposto", Categoria.ATIVO)
class AdminPanelCheck(Check):
    def executar(self):
        achados = []
        for caminho in CAMINHOS:
            url = self.target.caminho(caminho)
            try:
                r = self.http.get(url, allow_redirects=False)
            except Exception:
                continue

            if r.status_code in (401, 403):
                achados.append(
                    self.achado(
                        title=f"Painel administrativo protegido: {caminho}",
                        severity=Severity.INFO,
                        confidence=Confidence.FIRM,
                        url=url,
                        description="O caminho existe mas exige autenticacao "
                        "HTTP, o que e o comportamento esperado.",
                        evidence=f"HTTP {r.status_code}",
                        remediation="Nenhuma acao necessaria; continue exigindo "
                        "autenticacao.",
                        cwe="CWE-200",
                    )
                )
                continue

            if r.status_code in (301, 302, 303, 307, 308):
                destino = r.headers.get("Location", "").lower()
                if "login" in destino or "auth" in destino:
                    achados.append(
                        self.achado(
                            title=f"Painel administrativo redireciona para login: {caminho}",
                            severity=Severity.INFO,
                            confidence=Confidence.FIRM,
                            url=url,
                            description="O caminho existe e redireciona para "
                            "uma tela de autenticacao, o que e o comportamento "
                            "esperado.",
                            evidence=f"HTTP {r.status_code} -> {destino}",
                            remediation="Nenhuma acao necessaria.",
                            cwe="CWE-200",
                        )
                    )
                continue

            if r.status_code == 200:
                corpo = r.text.lower()
                if any(p in corpo for p in PALAVRAS_LOGIN):
                    achados.append(
                        self.achado(
                            title=f"Painel administrativo exposto: {caminho}",
                            severity=Severity.LOW,
                            confidence=Confidence.TENTATIVE,
                            url=url,
                            description="O caminho responde 200 com uma tela "
                            "que parece de login, indicando que o painel "
                            "administrativo e acessivel publicamente (mesmo "
                            "que ainda exija credenciais para entrar).",
                            evidence="HTTP 200 com termos de login no corpo",
                            remediation="Restrinja o acesso ao painel por IP/VPN "
                            "quando possivel, e evite expor o caminho padrao.",
                            cwe="CWE-200",
                        )
                    )
        return achados
