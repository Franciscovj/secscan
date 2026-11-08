"""Interface de linha de comando do secscan.

Subcomandos:
  scan <alvo>     roda a auditoria
  checks          lista os checks disponiveis
  selftest        auto-teste contra um alvo de mentira local

Exemplos:
  secscan scan https://meusite.com
  secscan scan meusite.com --only headers,tls,cookies --format json
  secscan scan https://meusite.com --autorizo --format html -o relatorios/
  secscan checks
  secscan selftest
"""

from __future__ import annotations

import argparse
import sys

from . import __version__
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


def _lista_checks() -> int:
    metas = sorted(todos().values(), key=lambda m: (m.categoria.value, m.id))
    print(f"secscan {__version__} — checks disponiveis:\n")
    atual = None
    for m in metas:
        if m.categoria != atual:
            atual = m.categoria
            print(f"[{m.categoria.value.upper()}]")
        print(f"  {m.id:<20} {m.titulo}")
    print("\nCategorias: passivo (so observa), ativo (sonda), "
          "intrusivo (envia payloads — exige --autorizo).")
    return 0


def _parse_lista(s: str | None) -> list[str] | None:
    if not s:
        return None
    return [x.strip() for x in s.split(",") if x.strip()]


def _cmd_scan(args) -> int:
    try:
        target = Target.parse(args.alvo)
    except ValueError as e:
        print(f"[ERRO] alvo invalido: {e}", file=sys.stderr)
        return 2

    only = _parse_lista(args.only)
    skip = _parse_lista(args.skip)

    # perfil filtra por categoria, a menos que --only seja explicito
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
    runner = Runner(
        target,
        http,
        on_log=(lambda m: print(m, file=sys.stderr)) if not args.silencioso else None,
        threads=args.threads,
        autorizo=args.autorizo,
        interativo=not args.sem_interacao,
    )

    print(f"secscan {__version__} — alvo: {target.url}", file=sys.stderr)
    result = runner.executar(only=only, skip=skip)
    http.fechar()

    formatos = [args.format] if args.format != "all" else list(FORMATOS)
    if args.output:
        for fmt in formatos:
            caminho = salvar(result, fmt, args.output)
            print(f"[OK] {fmt}: {caminho}", file=sys.stderr)
    else:
        # sem -o: imprime no stdout o primeiro formato (json por padrao e util p/ IA)
        print(gerar(result, formatos[0]))

    r = result.resumo()
    print(
        f"[FIM] {r['total']} achados "
        f"(crit {r['critical']} / alto {r['high']} / med {r['medium']} / "
        f"baixo {r['low']} / info {r['info']}) em {result.duracao_s:.1f}s",
        file=sys.stderr,
    )
    # codigo de saida util para CI: !=0 se houver achado alto/critico
    if args.falhar_se_achar and (r["critical"] or r["high"]):
        return 1
    return 0


def _cmd_selftest(args) -> int:
    from .selftest import rodar_selftest

    ok, detalhes = rodar_selftest(verboso=not args.silencioso)
    print("\n=== selftest ===")
    print(f"checks registrados: {len(detalhes['checks_registrados'])}")
    print(f"checks que dispararam: {len(detalhes['checks_dispararam'])}")
    print(f"total de achados: {detalhes['total_achados']}")
    if detalhes["esperados_faltando"]:
        print(f"[FALHOU] esperados que nao dispararam: {detalhes['esperados_faltando']}")
    if detalhes["erros"]:
        print(f"[FALHOU] checks com erro: {detalhes['erros']}")
    print("RESULTADO:", "OK" if ok else "FALHOU")
    return 0 if ok else 1


def construir_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="secscan",
        description="Auditoria de seguranca web (uso autorizado apenas).",
    )
    p.add_argument("--version", action="version", version=f"secscan {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="roda a auditoria em um alvo")
    s.add_argument("alvo", help="URL ou host (ex.: https://site.com)")
    s.add_argument("--only", help="so estes checks (ex.: headers,tls)")
    s.add_argument("--skip", help="pular estes checks")
    s.add_argument("--perfil", choices=list(PERFIS), default="padrao",
                   help="rapido=passivo, padrao=+ativo, completo=+intrusivo")
    s.add_argument("--format", choices=list(FORMATOS) + ["all"], default="json")
    s.add_argument("-o", "--output", help="diretorio de saida (salva arquivo)")
    s.add_argument("--threads", type=int, default=8)
    s.add_argument("--timeout", type=float, default=10.0)
    s.add_argument("--rate", type=float, default=10.0,
                   help="requisicoes por segundo (0 = sem limite)")
    s.add_argument("--proxy", help="proxy http(s), ex.: http://127.0.0.1:8080")
    s.add_argument("--user-agent", default=HttpConfig().user_agent)
    s.add_argument("--sem-tls", action="store_true",
                   help="nao verificar certificado TLS")
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
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
