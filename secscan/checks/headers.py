"""Check de headers de seguranca HTTP (passivo)."""

from __future__ import annotations

from ..core.finding import Confidence, Severity
from ..core.registry import Categoria, registrar
from .base import Check

# header -> (severidade, explicacao, correcao)
RECOMENDADOS = {
    "content-security-policy": (
        Severity.MEDIUM,
        "Sem CSP, o navegador nao restringe de onde scripts/estilos podem carregar.",
        "Defina uma Content-Security-Policy adequada ao app.",
    ),
    "strict-transport-security": (
        Severity.MEDIUM,
        "Sem HSTS, o navegador pode aceitar conexao HTTP em texto puro.",
        "Envie Strict-Transport-Security com max-age alto (so em HTTPS).",
    ),
    "x-frame-options": (
        Severity.LOW,
        "Sem X-Frame-Options/CSP frame-ancestors, a pagina pode ser embutida (clickjacking).",
        "Use X-Frame-Options: DENY ou CSP frame-ancestors.",
    ),
    "x-content-type-options": (
        Severity.LOW,
        "Sem nosniff, o navegador pode interpretar o tipo do conteudo por conta.",
        "Envie X-Content-Type-Options: nosniff.",
    ),
    "referrer-policy": (
        Severity.LOW,
        "Sem Referrer-Policy, URLs internas podem vazar no header Referer.",
        "Envie Referrer-Policy: strict-origin-when-cross-origin ou mais restrito.",
    ),
    "permissions-policy": (
        Severity.INFO,
        "Sem Permissions-Policy, recursos do navegador ficam todos liberados por padrao.",
        "Restrinja com Permissions-Policy (camera, microfone, geolocation...).",
    ),
}


@registrar("headers", "Headers de seguranca", Categoria.PASSIVO)
class HeadersCheck(Check):
    def executar(self):
        achados = []
        self.log("lendo headers da home")
        try:
            r = self.http.get(self.target.url)
        except Exception as e:
            self.log(f"falha ao buscar: {e}")
            return achados
        presentes = {k.lower() for k in r.headers}

        for header, (sev, por_que, fix) in RECOMENDADOS.items():
            if header not in presentes:
                achados.append(
                    self.achado(
                        title=f"Header ausente: {header}",
                        severity=sev,
                        confidence=Confidence.CONFIRMED,
                        description=por_que,
                        evidence=f"GET {self.target.url} nao retornou '{header}'.",
                        remediation=fix,
                        cwe="CWE-693",
                        owasp="A05:2021 Security Misconfiguration",
                    )
                )

        # banner que revela versao do servidor
        server = r.headers.get("Server", "")
        if server and any(ch.isdigit() for ch in server):
            achados.append(
                self.achado(
                    title="Banner do servidor revela versao",
                    severity=Severity.INFO,
                    confidence=Confidence.CONFIRMED,
                    description="O header Server expoe software e versao, util para um atacante.",
                    evidence=f"Server: {server}",
                    remediation="Oculte ou generalize o header Server.",
                    cwe="CWE-200",
                )
            )
        xpb = r.headers.get("X-Powered-By", "")
        if xpb:
            achados.append(
                self.achado(
                    title="X-Powered-By expoe tecnologia",
                    severity=Severity.INFO,
                    confidence=Confidence.CONFIRMED,
                    evidence=f"X-Powered-By: {xpb}",
                    remediation="Remova o header X-Powered-By.",
                    cwe="CWE-200",
                )
            )
        return achados
