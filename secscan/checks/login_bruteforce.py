"""Forca bruta de login / credenciais fracas (intrusivo).

Sucessor do antigo `weak_login`, agora de verdade:

1. **Descobre o formulario** — procura a pagina de login, le o formulario real
   (campos de usuario e senha pelos nomes/tipos, inclusive `email`), a URL de
   acao e eventuais campos ocultos, como o **token CSRF**, que sao reenviados.
2. **Detecta sucesso por baseline** — primeiro envia uma credencial que
   sabidamente falha e guarda a "cara" da falha (status, redirecionamento,
   cookie de sessao). Uma tentativa so e considerada sucesso quando foge dessa
   linha de base de um jeito coerente com login (redireciona para fora da tela
   de login, ou cria um cookie de sessao que a falha nao criava).
3. **Wordlist** — usa as listas embutidas por padrao, ou as que o usuario passar
   em `--users` / `--passwords` (ex.: SecLists/rockyou).

E capacidade ofensiva real, por isso e **intrusivo**: so roda em alvo local ou
com `--autorizo`. O teto de tentativas (`--max-tentativas`) existe para o uso ser
responsavel; aumente-o so no seu proprio alvo.
"""

from __future__ import annotations

import os
from html.parser import HTMLParser
from urllib.parse import urljoin

from ..core.finding import Confidence, Severity
from ..core.registry import Categoria, registrar
from .base import Check

TETO_PADRAO = 40
CAMINHOS_LOGIN = [
    "", "/login", "/admin/login", "/admin/login/", "/user/login", "/auth",
    "/signin", "/entrar", "/accounts/login/", "/wp-login.php", "/admin",
]
NOMES_USER = ("user", "username", "login", "email", "e-mail", "usuario",
              "usuário", "uid", "account", "conta")
NOMES_TOKEN = ("csrf", "token", "authenticity", "_token", "csrfmiddlewaretoken",
               "xsrf", "nonce")
MARCAS_FALHA = ("senha incorreta", "usuario ou senha", "credenciais invalidas",
                "invalid", "incorrect", "failed", "erro ao")


class _FormParser(HTMLParser):
    """Coleta formularios e seus inputs (name, type, value)."""

    def __init__(self) -> None:
        super().__init__()
        self.forms: list[dict] = []
        self._atual: dict | None = None

    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        if tag == "form":
            self._atual = {
                "action": d.get("action", ""),
                "method": (d.get("method") or "get").lower(),
                "inputs": [],
            }
            self.forms.append(self._atual)
        elif tag == "input" and self._atual is not None:
            self._atual["inputs"].append({
                "name": d.get("name", ""),
                "type": (d.get("type") or "text").lower(),
                "value": d.get("value", ""),
            })

    def handle_endtag(self, tag):
        if tag == "form":
            self._atual = None


def _carregar(caminho: str | None, nome_padrao: str) -> list[str]:
    if caminho:
        try:
            with open(caminho, "r", encoding="utf-8", errors="ignore") as f:
                return [l.strip() for l in f if l.strip()]
        except OSError:
            return []
    bundled = os.path.join(os.path.dirname(__file__), "..", "wordlists", nome_padrao)
    try:
        with open(bundled, "r", encoding="utf-8") as f:
            return [l.strip() for l in f if l.strip()]
    except OSError:
        return []


def _assinatura(r) -> tuple:
    cookie = r.headers.get("Set-Cookie", "").lower()
    sessao = any(m in cookie for m in ("session", "sid", "auth", "token"))
    return (r.status_code, r.headers.get("Location", "").lower(), sessao)


def _eh_login(form: dict) -> dict | None:
    """Se o form tem campo de senha, devolve {action, method, user, senha, ocultos}."""
    campo_senha = next((i for i in form["inputs"] if i["type"] == "password"), None)
    if not campo_senha or not campo_senha["name"]:
        return None
    campo_user = None
    for i in form["inputs"]:
        if i is campo_senha or i["type"] in ("password", "submit", "hidden"):
            continue
        if any(n in i["name"].lower() for n in NOMES_USER):
            campo_user = i
            break
    if campo_user is None:
        campo_user = next(
            (i for i in form["inputs"]
             if i is not campo_senha and i["type"] in ("text", "email", "")
             and i["name"]),
            None,
        )
    if campo_user is None or not campo_user["name"]:
        return None
    ocultos = {i["name"]: i["value"] for i in form["inputs"]
               if i["type"] == "hidden" and i["name"]}
    tem_token = any(any(t in n.lower() for t in NOMES_TOKEN) for n in ocultos)
    return {
        "action": form["action"],
        "method": form["method"],
        "user": campo_user["name"],
        "senha": campo_senha["name"],
        "ocultos": ocultos,
        "tem_token": tem_token,
    }


@registrar("login_bruteforce", "Forca bruta de login (credenciais fracas)",
           Categoria.INTRUSIVO)
class LoginBruteforceCheck(Check):
    def _descobrir(self) -> tuple[str, dict] | None:
        """Acha a URL de login e os campos do formulario."""
        for caminho in CAMINHOS_LOGIN:
            url = self.target.url if not caminho else self.target.caminho(caminho)
            try:
                r = self.http.get(url)
            except Exception:
                continue
            if r.status_code >= 400:
                continue
            parser = _FormParser()
            try:
                parser.feed(r.text)
            except Exception:
                continue
            for form in parser.forms:
                info = _eh_login(form)
                if info:
                    acao = urljoin(url, info["action"]) if info["action"] else url
                    return acao, info
        return None

    def _refrescar_token(self, url_pagina: str, info: dict) -> dict:
        """Re-busca a pagina para pegar token/cookie novos (apps que rotacionam)."""
        try:
            r = self.http.get(url_pagina)
            parser = _FormParser()
            parser.feed(r.text)
            for form in parser.forms:
                novo = _eh_login(form)
                if novo:
                    return novo["ocultos"]
        except Exception:
            pass
        return info["ocultos"]

    def _tentar(self, url_acao, info, usuario, senha, ocultos):
        data = dict(ocultos)
        data[info["user"]] = usuario
        data[info["senha"]] = senha
        if info["method"] == "get":
            return self.http.get(url_acao, params=data, allow_redirects=False)
        return self.http.post(url_acao, data=data, allow_redirects=False)

    @staticmethod
    def _sucesso(base: tuple, r) -> bool:
        assn = _assinatura(r)
        # redirecionou para fora da tela de login (a falha nao redirecionava assim)
        if r.status_code in (301, 302, 303, 307, 308):
            loc = r.headers.get("Location", "").lower()
            fora_login = not any(x in loc for x in ("login", "auth", "signin"))
            if fora_login and (base[0] not in (301, 302, 303, 307, 308)
                               or loc != base[1]):
                return True
        # criou cookie de sessao que a falha nao criava
        if assn[2] and not base[2]:
            return True
        return False

    def executar(self):
        achados = []
        alvo = self._descobrir()
        if not alvo:
            self.log("nenhum formulario de login encontrado")
            return achados
        url_acao, info = alvo
        # a pagina onde o form vive (para refrescar token), aproximada pela acao
        url_pagina = url_acao

        usuarios = _carregar(self.opcoes.get("usuarios_arquivo"), "users.txt")
        senhas = _carregar(self.opcoes.get("senhas_arquivo"), "passwords.txt")
        if not usuarios or not senhas:
            self.log("wordlists vazias")
            return achados

        teto = int(self.opcoes.get("max_tentativas") or TETO_PADRAO)

        # linha de base: credencial que sabidamente falha
        try:
            ocultos0 = (self._refrescar_token(url_pagina, info)
                        if info["tem_token"] else info["ocultos"])
            rb = self._tentar(url_acao, info, "secscan_nao_existe_zzz",
                              "secscan_senha_errada_zzz", ocultos0)
            base = _assinatura(rb)
        except Exception as e:
            self.log(f"falha ao medir baseline: {e}")
            return achados

        self.log(f"forca bruta em {url_acao} (ate {teto} tentativas)")
        tentativas = 0
        for usuario in usuarios:
            if tentativas >= teto:
                break
            for senha in senhas:
                if tentativas >= teto:
                    break
                tentativas += 1
                try:
                    ocultos = (self._refrescar_token(url_pagina, info)
                               if info["tem_token"] else info["ocultos"])
                    r = self._tentar(url_acao, info, usuario, senha, ocultos)
                except Exception:
                    continue
                corpo = (r.text or "").lower()
                if self._sucesso(base, r) and not any(m in corpo for m in MARCAS_FALHA):
                    achados.append(
                        self.achado(
                            title="Credenciais fracas aceitas no login",
                            severity=Severity.HIGH,
                            confidence=Confidence.FIRM,
                            url=url_acao,
                            description="O formulario de login aceitou uma "
                            "combinacao de usuario/senha de listas publicas de "
                            "credenciais comuns — qualquer um entra por forca "
                            "bruta simples.",
                            evidence=f"campo usuario={info['user']!r} senha="
                            f"{info['senha']!r}; funcionou com {usuario}:{senha}",
                            remediation="Exija senhas fortes, aplique bloqueio "
                            "apos tentativas (rate limit/lockout) e use MFA.",
                            cwe="CWE-307",
                            owasp="A07:2021 Identification and Authentication Failures",
                            extra={"usuario": usuario, "senha": senha,
                                   "tentativas": tentativas},
                        )
                    )
                    return achados
        self.log(f"nenhuma credencial fraca funcionou ({tentativas} tentativas)")
        return achados
