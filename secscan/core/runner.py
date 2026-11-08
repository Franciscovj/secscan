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

    def executar(
        self, only: list[str] | None = None, skip: list[str] | None = None
    ) -> ScanResult:
        metas = selecionar(only, skip)
        inicio = time.time()
        result = ScanResult(
            target=self.target.url,
            host=self.target.host,
            iniciado_em=time.strftime("%Y-%m-%d %H:%M:%S"),
            duracao_s=0.0,
        )

        intrusivo_ok, motivo = self._permitido_intrusivo()
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
