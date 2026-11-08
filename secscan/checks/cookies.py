"""Check de flags de cookie: Secure, HttpOnly, SameSite (passivo)."""

from __future__ import annotations

from ..core.finding import Confidence, Severity
from ..core.registry import Categoria, registrar
from .base import Check


@registrar("cookies", "Flags de cookie (Secure/HttpOnly/SameSite)", Categoria.PASSIVO)
class CookiesCheck(Check):
    def executar(self):
        achados = []
        self.log("inspecionando Set-Cookie")
        try:
            r = self.http.get(self.target.url)
        except Exception as e:
            self.log(f"falha ao buscar: {e}")
            return achados

        # requests junta varios Set-Cookie; usamos raw quando possivel
        set_cookies = []
        try:
            set_cookies = r.raw.headers.getlist("Set-Cookie")  # type: ignore[attr-defined]
        except Exception:
            if "Set-Cookie" in r.headers:
                set_cookies = [r.headers["Set-Cookie"]]

        https = self.target.scheme == "https"
        for sc in set_cookies:
            baixo = sc.lower()
            nome = sc.split("=", 1)[0].strip()
            faltas = []
            if "httponly" not in baixo:
                faltas.append("HttpOnly")
            if https and "secure" not in baixo:
                faltas.append("Secure")
            if "samesite" not in baixo:
                faltas.append("SameSite")
            if faltas:
                sev = Severity.MEDIUM if "HttpOnly" in faltas else Severity.LOW
                achados.append(
                    self.achado(
                        title=f"Cookie '{nome}' sem flags: {', '.join(faltas)}",
                        severity=sev,
                        confidence=Confidence.CONFIRMED,
                        description="Cookies de sessao sem HttpOnly/Secure/SameSite "
                        "ficam expostos a roubo via script ou envio inseguro.",
                        evidence=f"Set-Cookie: {sc[:120]}",
                        remediation="Marque o cookie com HttpOnly, Secure (em HTTPS) "
                        "e SameSite=Lax ou Strict.",
                        cwe="CWE-614",
                        owasp="A05:2021 Security Misconfiguration",
                    )
                )
        return achados
