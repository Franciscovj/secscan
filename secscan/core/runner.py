"""Orquestra a execucao dos checks e agrega os achados.

- resolve a selecao de checks (only/skip);
- aplica a trava de autorizacao nos intrusivos;
- roda em paralelo com um pool de threads;
- coleta Findings, erros e metricas num ScanResult.
"""

from __future__ import annotations

import concurrent.futures
import time
from dataclasses import dataclass, field
from typing import Callable

from .authorization import AutorizacaoNegada, garantir_autorizacao
from .finding import Finding, Severity
from .http_client import HttpClient
from .registry import Categoria, CheckMeta, TipoAlvo, selecionar
from .target import Target


@dataclass
class ScanResult:
    target: str
    host: str
    iniciado_em: str
    duracao_s: float
    findings: list[Finding] = field(default_factory=list)
    checks_rodados: list[str] = field(default_factory=list)
    checks_pulados: dict[str, str] = field(default_factory=dict)
    erros: dict[str, str] = field(default_factory=dict)
    total_requisicoes: int = 0

    def resumo(self) -> dict[str, int]:
        r = {s.value: 0 for s in Severity}
        for f in self.findings:
            r[f.severity.value] += 1
        r["total"] = len(self.findings)
        return r

    def ordenados(self) -> list[Finding]:
        return sorted(
            self.findings,
            key=lambda f: (-f.severity.rank, f.check),
        )


class Runner:
    def __init__(
        self,
        target: Target,
        http: HttpClient,
        on_log: Callable[[str], None] | None = None,
        threads: int = 8,
        autorizo: bool = False,
        interativo: bool = True,
        opcoes: dict | None = None,
    ) -> None:
        self.target = target
        self.http = http
        self.on_log = on_log or (lambda m: None)
        self.threads = max(1, threads)
        self.autorizo = autorizo
        self.interativo = interativo
        #: config extra repassada a cada check (wordlists, max_tentativas...)
        self.opcoes = opcoes or {}

    def _permitido_intrusivo(self) -> tuple[bool, str]:
        try:
            garantir_autorizacao(self.target.host, self.autorizo, self.interativo)
            return True, ""
        except AutorizacaoNegada as e:
            return False, str(e)

    def _calibrar_catchall(self) -> dict | None:
        """Aprende a 'cara do nao-existe'.

        Muitos sites (SPAs, catch-all) respondem a QUALQUER caminho com a mesma
        pagina (200), o que engana checks que procuram arquivos por caminho. Aqui
        pedimos caminhos aleatorios: se vierem iguais e 200, guardamos essa
        assinatura (status + tamanho) para os checks ignorarem o que bater com ela.
        """
        import secrets
        assinaturas = []
        for _ in range(2):
            alvo = self.target.caminho("/secscan-" + secrets.token_hex(8))
            try:
                r = self.http.get(alvo)
                assinaturas.append((r.status_code, len(r.content or b"")))
            except Exception:
                return None
        (s1, l1), (s2, l2) = assinaturas
        if s1 == s2 == 200 and abs(l1 - l2) <= max(64, int(0.05 * max(l1, l2, 1))):
            self.on_log(f"[i] alvo responde igual a caminhos inexistentes "
                        f"(catch-all {s1}, ~{(l1 + l2) // 2}b) — calibrando")
            return {"status": s1, "tamanho": (l1 + l2) // 2}
        return None

    def executar(
        self, only: list[str] | None = None, skip: list[str] | None = None
    ) -> ScanResult:
        metas = selecionar(only, skip)
        inicio = time.time()
        # calibra o catch-all uma vez e repassa a todos os checks via opcoes
        self.opcoes.setdefault("catchall", self._calibrar_catchall())
        result = ScanResult(
            target=self.target.url,
            host=self.target.host,
            iniciado_em=time.strftime("%Y-%m-%d %H:%M:%S"),
            duracao_s=0.0,
        )

        # so checa autorizacao se ha algum check intrusivo selecionado — nao faz
        # sentido pedir permissao numa varredura leve (perfil rapido/padrao)
        tem_intrusivo = any(m.categoria == Categoria.INTRUSIVO for m in metas)
        if tem_intrusivo:
            intrusivo_ok, motivo = self._permitido_intrusivo()
        else:
            intrusivo_ok, motivo = True, ""
        a_rodar: list[CheckMeta] = []
        for meta in metas:
            if meta.categoria == Categoria.INTRUSIVO and not intrusivo_ok:
                result.checks_pulados[meta.id] = motivo
                continue
            a_rodar.append(meta)

        def _roda(meta: CheckMeta) -> tuple[str, list[Finding], str | None]:
            try:
                check = meta.fabrica(self.target, self.http, self.on_log,
                                     self.opcoes)
                self.on_log(f"[+] {meta.id} ({meta.categoria.value})")
                achados = check.executar() or []
                return meta.id, achados, None
            except Exception as e:  # nunca deixa um check derrubar o scan
                return meta.id, [], f"{type(e).__name__}: {e}"

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            futuros = [ex.submit(_roda, m) for m in a_rodar]
            for fut in concurrent.futures.as_completed(futuros):
                cid, achados, erro = fut.result()
                result.checks_rodados.append(cid)
                if erro:
                    result.erros[cid] = erro
                    self.on_log(f"[ERRO] {cid}: {erro}")
                result.findings.extend(achados)

        result.duracao_s = time.time() - inicio
        result.total_requisicoes = self.http.total_requisicoes
        return result
