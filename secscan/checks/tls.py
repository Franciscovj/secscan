"""Verifica configuracao de TLS/certificado (passivo).

So roda em alvos HTTPS. Usa apenas stdlib (ssl + socket) para conectar,
negociar TLS e inspecionar o certificado e a versao do protocolo. Qualquer
falha de rede/SSL generica e tratada e o check devolve lista vazia em vez de
derrubar o scan.
"""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone

from ..core.finding import Confidence, Severity
from ..core.registry import Categoria, registrar, TipoAlvo
from .base import Check

TIMEOUT = 8.0
DIAS_ALERTA_EXPIRACAO = 15
PROTOCOLOS_OBSOLETOS = ("TLSv1", "TLSv1.1")


def _parse_data_cert(valor: str) -> datetime | None:
    # formato tipico: 'Jun  1 00:00:00 2030 GMT'
    try:
        return datetime.strptime(valor, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


@registrar("tls", "Configuracao TLS/certificado", Categoria.PASSIVO, TipoAlvo.URL)
class TlsCheck(Check):
    def executar(self):
        achados = []
        if self.target.scheme != "https":
            self.log("alvo nao e https")
            return achados

        host = self.target.host
        porta = self.target.port or 443

        contexto = ssl.create_default_context()
        try:
            with socket.create_connection((host, porta), timeout=TIMEOUT) as sock:
                with contexto.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    versao = ssock.version()
        except ssl.SSLCertVerificationError as e:
            achados.append(
                self.achado(
                    title="Certificado TLS invalido/nao confiavel",
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    description="A verificacao padrao do certificado falhou "
                    "(cadeia nao confiavel, nome incorreto ou expirado).",
                    evidence=f"{e}",
                    remediation="Use um certificado valido emitido por uma CA "
                    "confiavel e cubra todos os nomes servidos.",
                    cwe="CWE-295",
                    owasp="A02:2021 Cryptographic Failures",
                )
            )
            return achados
        except (socket.timeout, OSError, ssl.SSLError) as e:
            self.log(f"falha ao conectar/negociar TLS: {e}")
            return achados

        # validade do certificado
        not_after = cert.get("notAfter") if cert else None
        if not_after:
            data_exp = _parse_data_cert(not_after)
            if data_exp:
                dias = (data_exp - datetime.now(timezone.utc)).days
                if dias < 0:
                    achados.append(
                        self.achado(
                            title="Certificado TLS expirado",
                            severity=Severity.HIGH,
                            confidence=Confidence.CONFIRMED,
                            description="O certificado apresentado ja expirou.",
                            evidence=f"notAfter={not_after}",
                            remediation="Renove o certificado imediatamente.",
                            cwe="CWE-295",
                            owasp="A02:2021 Cryptographic Failures",
                        )
                    )
                elif dias < DIAS_ALERTA_EXPIRACAO:
                    achados.append(
                        self.achado(
                            title="Certificado TLS perto de expirar",
                            severity=Severity.MEDIUM,
                            confidence=Confidence.CONFIRMED,
                            description=f"O certificado expira em {dias} dia(s).",
                            evidence=f"notAfter={not_after}",
                            remediation="Renove o certificado antes do vencimento "
                            "(idealmente com renovacao automatica).",
                            cwe="CWE-295",
                            owasp="A02:2021 Cryptographic Failures",
                        )
                    )

        # protocolo negociado
        if versao in PROTOCOLOS_OBSOLETOS:
            achados.append(
                self.achado(
                    title="Protocolo TLS obsoleto",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CONFIRMED,
                    description="O servidor aceitou negociar uma versao antiga "
                    "de TLS, considerada insegura.",
                    evidence=f"versao negociada: {versao}",
                    remediation="Desative TLSv1.0/1.1 e exija TLSv1.2 ou "
                    "superior.",
                    cwe="CWE-326",
                    owasp="A02:2021 Cryptographic Failures",
                )
            )
        return achados
