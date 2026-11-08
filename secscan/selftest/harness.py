"""Alvo de mentira (mock) e validacao dos checks — o `secscan selftest`.

Sobe um servidor HTTP local que expoe, de proposito, varias falhas controladas:
headers de seguranca ausentes, cookie sem flags, parametro refletido, /.env e
/.git/HEAD acessiveis, listagem de diretorio, redirecionamento aberto, uma
mensagem de erro de banco simulada e um formulario sem token CSRF.

Depois roda o scanner contra esse alvo e confere que cada check esperado
disparou. Isso deixa a ferramenta se auto-validar, sem bater em site real e
sem gastar tokens em verificacao manual.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from ..core.http_client import HttpClient, HttpConfig
from ..core.registry import todos
from ..core.runner import Runner
from ..core.target import Target


def _expandir_entidades(xml: str) -> str:
    """Parser de mentira: expande UMA entidade interna declarada no DOCTYPE.

    Reproduz o comportamento vulneravel (processar entidades definidas pelo
    usuario) de forma controlada e segura, sem ler arquivo nem rede.
    """
    import re

    m = re.search(r'<!ENTITY\s+(\w+)\s+"([^"]*)"\s*>', xml)
    if not m:
        return "<resposta>sem entidade</resposta>"
    nome, valor = m.group(1), m.group(2)
    return xml.replace(f"&{nome};", valor)


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # silencia o log do servidor
        pass

    def _send(self, code=200, body=b"", ctype="text/html; charset=utf-8",
              headers=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        p = urlparse(self.path)
        rota = p.path
        q = parse_qs(p.query)

        # Falha: cookie sem Secure/HttpOnly/SameSite (home)
        if rota in ("/", "/index.html"):
            # SQLi baseada em erro de proposito: aspa no 'id' gera erro de banco
            id_val = q.get("id", [""])[0]
            if "'" in id_val or '"' in id_val:
                self._send(code=500,
                           body=b"You have an error in your SQL syntax near ''",
                           headers={"Set-Cookie": "sid=abc123; Path=/"})
                return
            refletido = q.get("q", [""])[0]  # XSS refletido de proposito
            corpo = (
                "<html><body><h1>App de teste</h1>"
                f"<div>busca: {refletido}</div>"
                "<!-- contato: suporte@exemplo-interno.local -->"  # info disclosure
                "<form method='post' action='/login'>"
                "<input name='username'><input name='password' type='password'>"
                "</form></body></html>"
            ).encode()
            self._send(body=corpo, headers={
                "Set-Cookie": "sid=abc123; Path=/",
                # CSP fraca de proposito (unsafe-inline/eval + wildcard)
                "Content-Security-Policy":
                    "default-src *; script-src 'unsafe-inline' 'unsafe-eval' *",
            })
            return

        # Falha: /.env acessivel
        if rota == "/.env":
            self._send(body=b"SECRET_KEY=exemplo\nDB_PASSWORD=exemplo\n",
                       ctype="text/plain")
            return

        # Falha: /.git/HEAD acessivel
        if rota == "/.git/HEAD":
            self._send(body=b"ref: refs/heads/main\n", ctype="text/plain")
            return

        # Falha: listagem de diretorio
        if rota == "/uploads/":
            self._send(body=b"<html><head><title>Index of /uploads</title></head>"
                            b"<body><h1>Index of /uploads</h1><ul>"
                            b"<li><a href='a.txt'>a.txt</a></li></ul></body></html>")
            return

        # Falha: redirecionamento aberto
        if rota == "/redir":
            destino = q.get("next", [q.get("url", [""])[0]])[0]
            self._send(code=302, body=b"", headers={"Location": destino})
            return

        # Falha: erro de banco simulado ao receber aspa
        if rota == "/produto":
            val = q.get("id", [""])[0]
            if "'" in val:
                self._send(code=500,
                           body=b"You have an error in your SQL syntax near ''")
                return
            self._send(body=b"<html><body>produto ok</body></html>")
            return

        # Painel admin de mentira
        if rota in ("/admin", "/admin/"):
            self._send(body=b"<html><body><h1>login</h1>"
                            b"<input name='username'></body></html>")
            return

        # Falha: SSRF — o servidor "busca" a URL do parametro e devolve o conteudo
        if rota in ("/fetch", "/proxy"):
            alvo = q.get("url", [q.get("uri", [""])[0]])[0]
            if alvo:
                self._send(body=f"RESPOSTA REMOTA (fetch) de: {alvo}".encode())
                return
            self._send(body=b"informe ?url=")
            return

        self._send(code=404, body=b"<html><body>nao encontrado</body></html>")

    def do_OPTIONS(self):
        # Falha: expoe metodos perigosos (TRACE habilitado -> XST)
        self._send(code=200, body=b"",
                   headers={"Allow": "GET, POST, OPTIONS, TRACE, PUT"})

    def do_POST(self):
        tam = int(self.headers.get("Content-Length", 0) or 0)
        corpo = self.rfile.read(tam) if tam else b""
        ctype = self.headers.get("Content-Type", "").lower()

        # Falha: XXE — expande entidade interna do XML (parser inseguro de mentira)
        if urlparse(self.path).path == "/api/xml" and "xml" in ctype:
            texto = corpo.decode("utf-8", "replace")
            expandido = _expandir_entidades(texto)
            self._send(body=expandido.encode(), ctype="application/xml")
            return

        self._send(code=401, body=b"<html><body>nao autorizado</body></html>")


class AlvoDeMentira:
    """Context manager que sobe/derruba o servidor de teste."""

    def __init__(self, porta: int = 0) -> None:
        self._srv = ThreadingHTTPServer(("127.0.0.1", porta), _Handler)
        self.porta = self._srv.server_address[1]
        self.url = f"http://127.0.0.1:{self.porta}"
        self._thread: threading.Thread | None = None

    def __enter__(self) -> "AlvoDeMentira":
        self._thread = threading.Thread(target=self._srv.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self._srv.shutdown()
        self._srv.server_close()


# checks que, no minimo, devem disparar contra o alvo de mentira
ESPERADOS = {
    "headers",
    "cookies",
    "sensitive_paths",
    "git_exposure",
    "directory_listing",
    "open_redirect",
    "sql_injection",
    "ssrf",
    "xxe",
    "http_methods",
    "csp_audit",
    "info_disclosure",
}


def rodar_selftest(verboso: bool = True) -> tuple[bool, dict]:
    """Roda o scanner contra o alvo de mentira e valida os checks esperados.

    Retorna (ok, detalhes). `ok` e True se todos os checks esperados dispararam
    e nenhum check quebrou com erro.
    """
    log = (lambda m: print(m)) if verboso else (lambda m: None)
    from .. import checks  # noqa: F401  garante que todos os checks registrem
    with AlvoDeMentira() as alvo:
        target = Target.parse(alvo.url)
        http = HttpClient(HttpConfig(timeout=5, req_por_seg=0, verificar_tls=False))
        runner = Runner(target, http, on_log=log, threads=8,
                        autorizo=True, interativo=False)
        result = runner.executar()

    disparou = {f.check for f in result.findings}
    faltando = sorted(ESPERADOS - disparou)
    registrados = set(todos().keys())
    esperados_validos = ESPERADOS & registrados

    detalhes = {
        "checks_registrados": sorted(registrados),
        "checks_dispararam": sorted(disparou),
        "esperados_faltando": faltando,
        "erros": result.erros,
        "total_achados": len(result.findings),
    }
    ok = not faltando and not result.erros and esperados_validos == ESPERADOS
    return ok, detalhes
