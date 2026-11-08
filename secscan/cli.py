"""Interface de linha de comando do secscan.

Subcomandos:
  scan <alvo>     roda a auditoria
  checks          lista os checks disponiveis
  selftest        auto-teste contra um alvo de mentira local

Rodar `secscan` sem argumento abre um menu interativo colorido.

Exemplos:
  secscan scan https://meusite.com
  secscan scan meusite.com --only headers,tls,cookies --format json
  secscan scan https://meusite.com --autorizo --format html -o relatorios/
  secscan checks
  secscan selftest
"""

from __future__ import annotations

import argparse
import os
import sys

#: pasta fixa onde os relatorios caem quando o usuario nao passa -o.
#: sempre a mesma, nao importa de onde o comando foi rodado.
DIR_PADRAO = os.path.join(os.path.expanduser("~"), "secscan-relatorios")

from . import __version__
from . import ui
from .core.finding import Severity
from .core.http_client import HttpClient, HttpConfig
from .core.registry import Categoria, todos
from .core.runner import Runner
from .core.target import Target
from .report import FORMATOS, gerar, salvar

# importa para registrar todos os checks
from . import checks  # noqa: F401,E402

PERFIS = {
    "rapido": {"categorias": {Categoria.PASSIVO}},
    "padrao": {"categorias": {Categoria.PASSIVO, Categoria.ATIVO}},
    "completo": {"categorias": {Categoria.PASSIVO, Categoria.ATIVO, Categoria.INTRUSIVO}},
}

_COR_CATEGORIA = {
    Categoria.PASSIVO: "verde",
    Categoria.ATIVO: "amarelo",
    Categoria.INTRUSIVO: "vermelho",
}


def _est(stream) -> ui.Estilo:
    return ui.Estilo(ui.suporta_cor(stream))


def _lista_checks(est: ui.Estilo | None = None) -> int:
    est = est or _est(sys.stdout)
    print(ui.banner(est, __version__))
    print(est.c("Checks disponiveis:", "bold") + "\n")
    metas = sorted(todos().values(), key=lambda m: (m.categoria.value, m.id))
    atual = None
    for m in metas:
        if m.categoria != atual:
            atual = m.categoria
            cor = _COR_CATEGORIA[m.categoria]
            print(est.c(f"[{m.categoria.value.upper()}]", cor, "bold"))
        print(f"  {est.c(f'{m.id:<18}', 'ciano')} {m.titulo}")
    print()
    print(est.c("passivo", "verde") + " so observa  ·  "
          + est.c("ativo", "amarelo") + " sonda  ·  "
          + est.c("intrusivo", "vermelho") + " envia payloads (exige --autorizo)")
    return 0


def _parse_lista(s: str | None) -> list[str] | None:
    if not s:
        return None
    return [x.strip() for x in s.split(",") if x.strip()]


def _log_colorido(est: ui.Estilo):
    def _log(m: str) -> None:
        if m.startswith("[ERRO]"):
            print(est.c(m, "vermelho"), file=sys.stderr)
        elif m.startswith("[+]"):
            print(est.c(m, "cinza"), file=sys.stderr)
        else:
            print(m, file=sys.stderr)
    return _log


def _resumo_colorido(est: ui.Estilo, r: dict, dur: float) -> str:
    partes = [
        est.c(f"crit {r['critical']}", "magenta"),
        est.c(f"alto {r['high']}", "vermelho"),
        est.c(f"med {r['medium']}", "amarelo"),
        est.c(f"baixo {r['low']}", "azul"),
        est.c(f"info {r['info']}", "cinza"),
    ]
    total = est.c(str(r["total"]), "bold")
    return (f"{est.c('[FIM]', 'verde', 'bold')} {total} achados  "
            + "  ".join(partes) + f"  em {dur:.1f}s")


def _cmd_scan(args) -> int:
    est = _est(sys.stderr)
    try:
        target = Target.parse(args.alvo)
    except ValueError as e:
        print(est.c(f"[ERRO] alvo invalido: {e}", "vermelho"), file=sys.stderr)
        return 2

    only = _parse_lista(args.only)
    skip = _parse_lista(args.skip)

    if not only and args.perfil in PERFIS:
        cats = PERFIS[args.perfil]["categorias"]
        only = [cid for cid, m in todos().items() if m.categoria in cats]

    http = HttpClient(
        HttpConfig(
            timeout=args.timeout,
            req_por_seg=args.rate,
            verificar_tls=not args.sem_tls,
            user_agent=args.user_agent,
            proxy=args.proxy,
        )
    )
    opcoes = {}
    if getattr(args, "users", None):
        opcoes["usuarios_arquivo"] = args.users
    if getattr(args, "passwords", None):
        opcoes["senhas_arquivo"] = args.passwords
    if getattr(args, "max_tentativas", None):
        opcoes["max_tentativas"] = args.max_tentativas

    runner = Runner(
        target,
        http,
        on_log=_log_colorido(est) if not args.silencioso else None,
        threads=args.threads,
        autorizo=args.autorizo,
        interativo=not args.sem_interacao,
        opcoes=opcoes,
    )

    if not args.silencioso:
        print(ui.banner(est, __version__), file=sys.stderr)
    print(f"{est.c('alvo:', 'bold')} {est.c(target.url, 'ciano')}", file=sys.stderr)
    print(ui.regua(est), file=sys.stderr)
    result = runner.executar(only=only, skip=skip)
    http.fechar()

    # Para onde vai o relatorio:
    #  - com -o: a pasta que o usuario pediu;
    #  - sem -o, rodando num terminal (humano): SEMPRE a pasta fixa DIR_PADRAO,
    #    nao importa de onde o comando foi chamado;
    #  - sem -o, em pipe (outra ferramenta/IA lendo): imprime no stdout.
    if args.output:
        destino_dir = args.output
    elif sys.stdout.isatty():
        destino_dir = DIR_PADRAO
    else:
        destino_dir = None

    if args.format and args.format != "all":
        formatos = [args.format]
    elif args.format == "all":
        formatos = list(FORMATOS)
    else:
        formatos = None  # decidido pelo destino abaixo

    if destino_dir:
        for fmt in (formatos or ["html"]):  # arquivo p/ humano: HTML por padrao
            caminho = salvar(result, fmt, destino_dir)
            print(est.c(f"[OK] relatorio salvo: {caminho}", "verde", "bold"),
                  file=sys.stderr)
    else:
        # pipe/IA: relatorio puro no stdout (JSON por padrao)
        print(gerar(result, (formatos or ["json"])[0]))

    r = result.resumo()
    print(ui.regua(est), file=sys.stderr)
    print(_resumo_colorido(est, r, result.duracao_s), file=sys.stderr)
    if args.falhar_se_achar and (r["critical"] or r["high"]):
        return 1
    return 0


def _cmd_selftest(args) -> int:
    from .selftest import rodar_selftest

    est = _est(sys.stdout)
    ok, detalhes = rodar_selftest(verboso=not args.silencioso)
    print("\n" + est.c("=== selftest ===", "bold"))
    print(f"checks registrados: {len(detalhes['checks_registrados'])}")
    print(f"checks que dispararam: {len(detalhes['checks_dispararam'])}")
    print(f"total de achados: {detalhes['total_achados']}")
    if detalhes["esperados_faltando"]:
        print(est.c(f"[FALHOU] nao dispararam: {detalhes['esperados_faltando']}",
                    "vermelho"))
    if detalhes["erros"]:
        print(est.c(f"[FALHOU] checks com erro: {detalhes['erros']}", "vermelho"))
    print("RESULTADO:",
          est.c("OK", "verde", "bold") if ok else est.c("FALHOU", "vermelho", "bold"))
    return 0 if ok else 1


# ---- menu interativo ------------------------------------------------------

def _menu() -> int:
    est = _est(sys.stdout)
    if not (sys.stdin and sys.stdin.isatty()):
        # sem terminal: menu nao faz sentido, mostra ajuda
        construir_parser().print_help()
        return 0
    print(ui.banner(est, __version__))
    opcoes = {
        "1": "Escanear um alvo (scan)",
        "2": "Listar os checks",
        "3": "Auto-teste (selftest)",
        "4": "Ajuda",
        "0": "Sair",
    }
    while True:
        print()
        for k, v in opcoes.items():
            print(f"  {est.c(k, 'ciano', 'bold')}  {v}")
        try:
            esc = input(est.c("\nescolha> ", "verde")).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if esc == "0":
            return 0
        if esc == "1":
            try:
                alvo = input("  alvo (URL ou host): ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                return 0
            if not alvo:
                continue
            perfil = input("  perfil [rapido/padrao/completo] (padrao): ").strip() \
                or "padrao"
            autorizo = False
            if perfil == "completo":
                resp = input(est.c(
                    "  checks intrusivos exigem autorizacao. "
                    "voce tem permissao para testar este alvo? [s/N]: ", "amarelo"))
                autorizo = resp.strip().lower() in ("s", "sim", "y")
            args = argparse.Namespace(
                alvo=alvo, only=None, skip=None, perfil=perfil, format="txt",
                output=None, threads=8, timeout=10.0, rate=10.0, proxy=None,
                user_agent=HttpConfig().user_agent, sem_tls=False,
                autorizo=autorizo, sem_interacao=False, silencioso=False,
                falhar_se_achar=False, users=None, passwords=None,
                max_tentativas=None,
            )
            _cmd_scan(args)
        elif esc == "2":
            _lista_checks(est)
        elif esc == "3":
            _cmd_selftest(argparse.Namespace(silencioso=True))
        elif esc == "4":
            construir_parser().print_help()
        else:
            print(est.c("  opcao invalida", "vermelho"))


def construir_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="secscan",
        description="Auditoria de seguranca web (uso autorizado apenas).",
    )
    p.add_argument("--version", action="version", version=f"secscan {__version__}")
    sub = p.add_subparsers(dest="cmd")

    s = sub.add_parser("scan", help="roda a auditoria em um alvo")
    s.add_argument("alvo", help="URL ou host (ex.: https://site.com)")
    s.add_argument("--only", help="so estes checks (ex.: headers,tls)")
    s.add_argument("--skip", help="pular estes checks")
    s.add_argument("--perfil", choices=list(PERFIS), default="padrao",
                   help="rapido=passivo, padrao=+ativo, completo=+intrusivo")
    s.add_argument("--format", choices=list(FORMATOS) + ["all"], default=None,
                   help="formato (padrao: html quando salva em arquivo, "
                   "json quando sai em pipe)")
    s.add_argument("-o", "--output", help="diretorio de saida (salva arquivo)")
    s.add_argument("--threads", type=int, default=8)
    s.add_argument("--timeout", type=float, default=10.0)
    s.add_argument("--rate", type=float, default=10.0,
                   help="requisicoes por segundo (0 = sem limite)")
    s.add_argument("--proxy", help="proxy http(s), ex.: http://127.0.0.1:8080")
    s.add_argument("--user-agent", default=HttpConfig().user_agent)
    s.add_argument("--sem-tls", action="store_true",
                   help="nao verificar certificado TLS")
    s.add_argument("--users", help="arquivo de usuarios para login_bruteforce "
                   "(uma por linha; ex.: wordlist do SecLists)")
    s.add_argument("--passwords", help="arquivo de senhas para login_bruteforce "
                   "(uma por linha; ex.: rockyou.txt do SecLists)")
    s.add_argument("--max-tentativas", type=int, dest="max_tentativas",
                   help="teto de tentativas do login_bruteforce (so vale com "
                   "--autorizo; padrao conservador)")
    s.add_argument("--autorizo", action="store_true",
                   help="confirmo que tenho permissao para testar este alvo")
    s.add_argument("--sem-interacao", action="store_true",
                   help="nunca perguntar (CI); sem --autorizo, pula intrusivos")
    s.add_argument("--silencioso", action="store_true", help="sem log de progresso")
    s.add_argument("--falhar-se-achar", action="store_true",
                   help="codigo de saida 1 se houver achado alto/critico")
    s.set_defaults(func=_cmd_scan)

    c = sub.add_parser("checks", help="lista os checks disponiveis")
    c.set_defaults(func=lambda a: _lista_checks())

    t = sub.add_parser("selftest", help="auto-teste contra alvo de mentira local")
    t.add_argument("--silencioso", action="store_true")
    t.set_defaults(func=_cmd_selftest)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = construir_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "cmd", None):
        return _menu()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
