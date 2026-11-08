"""Reporters: transformam um ScanResult em texto, JSON, HTML, Markdown ou SARIF.

O JSON e a fonte de verdade e e o formato pensado para consumo por outra
ferramenta ou por uma IA: estavel, com severidade, confianca, evidencia,
remediacao e CWE por achado.
"""

from __future__ import annotations

import html as _html
import json
import os
from datetime import datetime, timezone

from ..core.finding import Severity
from ..core.runner import ScanResult

FORMATOS = ("txt", "json", "html", "md", "sarif")


def _dados(result: ScanResult) -> dict:
    return {
        "ferramenta": "secscan",
        "alvo": result.target,
        "host": result.host,
        "iniciado_em": result.iniciado_em,
        "duracao_s": round(result.duracao_s, 2),
        "total_requisicoes": result.total_requisicoes,
        "resumo": result.resumo(),
        "checks_rodados": sorted(result.checks_rodados),
        "checks_pulados": result.checks_pulados,
        "erros": result.erros,
        "achados": [f.to_dict() for f in result.ordenados()],
    }


def _txt(result: ScanResult) -> str:
    L: list[str] = []
    r = result.resumo()
    L.append("=" * 64)
    L.append(f"  Relatorio secscan - {result.target}")
    L.append(f"  {result.iniciado_em}  |  {result.duracao_s:.1f}s  |  "
             f"{result.total_requisicoes} requisicoes")
    L.append("=" * 64)
    L.append(
        f"Total: {r['total']}  |  Critico: {r['critical']}  Alto: {r['high']}  "
        f"Medio: {r['medium']}  Baixo: {r['low']}  Info: {r['info']}"
    )
    L.append("")
    if not result.findings:
        L.append("Nenhum achado.")
    for f in result.ordenados():
        L.append(f"[{f.severity.rotulo.upper()}] {f.title}  ({f.confidence.rotulo})")
        L.append(f"    check: {f.check}   {f.cwe or ''} {f.owasp or ''}".rstrip())
        if f.url:
            L.append(f"    url: {f.url}")
        if f.description:
            L.append(f"    o que e: {f.description}")
        if f.evidence:
            L.append(f"    evidencia: {f.evidence}")
        if f.remediation:
            L.append(f"    correcao: {f.remediation}")
        L.append("")
    if result.checks_pulados:
        L.append("Checks pulados:")
        for cid, motivo in result.checks_pulados.items():
            L.append(f"    {cid}: {motivo}")
    if result.erros:
        L.append("Erros:")
        for cid, err in result.erros.items():
            L.append(f"    {cid}: {err}")
    return "\n".join(L)


def _json(result: ScanResult) -> str:
    return json.dumps(_dados(result), indent=2, ensure_ascii=False)


def _md(result: ScanResult) -> str:
    r = result.resumo()
    L = [
        f"# Relatorio de seguranca — {result.target}",
        "",
        f"- Data: {result.iniciado_em}",
        f"- Duracao: {result.duracao_s:.1f}s ({result.total_requisicoes} requisicoes)",
        f"- Achados: **{r['total']}** "
        f"(Critico {r['critical']} · Alto {r['high']} · Medio {r['medium']} · "
        f"Baixo {r['low']} · Info {r['info']})",
        "",
        "| Severidade | Check | Titulo | Confianca | URL |",
        "|---|---|---|---|---|",
    ]
    for f in result.ordenados():
        url = (f.url or "").replace("|", "%7C")
        L.append(
            f"| {f.severity.rotulo} | {f.check} | {f.title} | "
            f"{f.confidence.rotulo} | {url} |"
        )
    return "\n".join(L)


_SARIF_NIVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def _sarif(result: ScanResult) -> str:
    regras: dict[str, dict] = {}
    resultados = []
    for f in result.ordenados():
        regras.setdefault(
            f.check,
            {
                "id": f.check,
                "name": f.check,
                "shortDescription": {"text": f.title},
                "properties": {"cwe": f.cwe, "owasp": f.owasp},
            },
        )
        resultados.append(
            {
                "ruleId": f.check,
                "level": _SARIF_NIVEL[f.severity],
                "message": {"text": f"{f.title}. {f.description}".strip()},
                "locations": [
                    {"physicalLocation": {"artifactLocation": {"uri": f.url}}}
                ]
                if f.url
                else [],
                "properties": {
                    "severity": f.severity.value,
                    "confidence": f.confidence.value,
                    "evidence": f.evidence,
                    "remediation": f.remediation,
                },
            }
        )
    doc = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "secscan",
                        "informationUri": "https://github.com/Franciscovj/secscan",
                        "rules": list(regras.values()),
                    }
                },
                "results": resultados,
            }
        ],
    }
    return json.dumps(doc, indent=2, ensure_ascii=False)


_CORES = {
    Severity.CRITICAL: "#b10f2e",
    Severity.HIGH: "#e74c3c",
    Severity.MEDIUM: "#f39c12",
    Severity.LOW: "#3498db",
    Severity.INFO: "#7f8c8d",
}


def _html_report(result: ScanResult) -> str:
    r = result.resumo()
    linhas = []
    for f in result.ordenados():
        cor = _CORES[f.severity]
        linhas.append(
            f'<div class="card" style="border-left-color:{cor}">'
            f'<div class="sev" style="color:{cor}">{_html.escape(f.severity.rotulo)}'
            f' · {_html.escape(f.confidence.rotulo)}</div>'
            f"<h3>{_html.escape(f.title)}</h3>"
            f'<div class="meta">{_html.escape(f.check)} '
            f"{_html.escape(f.cwe or '')} {_html.escape(f.owasp or '')}</div>"
            + (f'<div class="url">{_html.escape(f.url)}</div>' if f.url else "")
            + (f"<p>{_html.escape(f.description)}</p>" if f.description else "")
            + (f'<pre>{_html.escape(f.evidence)}</pre>' if f.evidence else "")
            + (f'<p class="fix"><b>Correcao:</b> {_html.escape(f.remediation)}</p>'
               if f.remediation else "")
            + "</div>"
        )
    corpo = "\n".join(linhas) or "<p>Nenhum achado.</p>"
    return f"""<!DOCTYPE html>
<html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>secscan — {_html.escape(result.target)}</title>
<style>
 body{{font-family:system-ui,Segoe UI,Arial,sans-serif;margin:0;background:#0f1115;color:#e6e6e6}}
 .wrap{{max-width:980px;margin:0 auto;padding:24px}}
 h1{{font-size:20px}} .sub{{color:#9aa0a6;font-size:13px}}
 .resumo{{display:flex;gap:10px;flex-wrap:wrap;margin:16px 0}}
 .chip{{background:#1a1d24;border-radius:8px;padding:8px 12px;font-size:13px}}
 .card{{background:#161922;border-left:4px solid #555;border-radius:8px;
   padding:12px 16px;margin:12px 0}}
 .card h3{{margin:4px 0;font-size:16px}} .sev{{font-size:12px;font-weight:700}}
 .meta{{color:#9aa0a6;font-size:12px}} .url{{color:#8ab4f8;font-size:13px;word-break:break-all}}
 pre{{background:#0b0d11;padding:8px;border-radius:6px;overflow:auto;font-size:12px}}
 .fix{{color:#a5d6a7;font-size:13px}}
</style></head><body><div class="wrap">
<h1>Relatorio de seguranca — {_html.escape(result.target)}</h1>
<div class="sub">{result.iniciado_em} · {result.duracao_s:.1f}s · {result.total_requisicoes} requisicoes</div>
<div class="resumo">
 <div class="chip">Total: <b>{r['total']}</b></div>
 <div class="chip" style="color:{_CORES[Severity.CRITICAL]}">Critico: {r['critical']}</div>
 <div class="chip" style="color:{_CORES[Severity.HIGH]}">Alto: {r['high']}</div>
 <div class="chip" style="color:{_CORES[Severity.MEDIUM]}">Medio: {r['medium']}</div>
 <div class="chip" style="color:{_CORES[Severity.LOW]}">Baixo: {r['low']}</div>
 <div class="chip" style="color:{_CORES[Severity.INFO]}">Info: {r['info']}</div>
</div>
{corpo}
</div></body></html>"""


_GERADORES = {
    "txt": _txt,
    "json": _json,
    "html": _html_report,
    "md": _md,
    "sarif": _sarif,
}


def gerar(result: ScanResult, formato: str) -> str:
    if formato not in _GERADORES:
        raise ValueError(f"Formato desconhecido: {formato}")
    return _GERADORES[formato](result)


def salvar(result: ScanResult, formato: str, destino_dir: str) -> str:
    os.makedirs(destino_dir, exist_ok=True)
    carimbo = datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d_%H-%M-%S")
    ext = "json" if formato == "sarif" else formato
    nome = f"scan_{carimbo}.{ 'sarif.json' if formato=='sarif' else ext}"
    caminho = os.path.join(destino_dir, nome)
    with open(caminho, "w", encoding="utf-8") as fh:
        fh.write(gerar(result, formato))
    return caminho
