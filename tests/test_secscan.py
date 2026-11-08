"""Testes do secscan.

Nenhum teste bate em site real: tudo roda contra o alvo de mentira local
(secscan.selftest). Rode com:  python -m pytest  (ou python -m unittest)
"""

from __future__ import annotations

import unittest

from secscan.core.finding import Confidence, Finding, Severity
from secscan.core.registry import todos
from secscan.core.target import Target
from secscan.report import FORMATOS, gerar
from secscan.core.runner import ScanResult


class TestTarget(unittest.TestCase):
    def test_parse_sem_esquema(self):
        t = Target.parse("exemplo.com/")
        self.assertEqual(t.host, "exemplo.com")
        self.assertEqual(t.scheme, "http")

    def test_parse_https_porta(self):
        t = Target.parse("https://exemplo.com:8443/app")
        self.assertEqual(t.host, "exemplo.com")
        self.assertEqual(t.port, 8443)
        self.assertEqual(t.scheme, "https")

    def test_caminho(self):
        t = Target.parse("https://exemplo.com/")
        self.assertEqual(t.caminho("/.env"), "https://exemplo.com/.env")

    def test_vazio(self):
        with self.assertRaises(ValueError):
            Target.parse("")


class TestRegistro(unittest.TestCase):
    def test_todos_os_checks_registram(self):
        import secscan.checks  # noqa: F401  (registra tudo)

        esperados = {
            "admin_panel", "backup_files", "cookies", "cors", "csp_audit",
            "csrf", "db_exposure", "debug_mode", "directory_listing",
            "git_exposure", "headers", "http_methods", "info_disclosure",
            "open_redirect", "port_scan", "sensitive_paths", "sql_injection",
            "ssrf", "subdomain_enum", "tls", "traversal", "weak_login",
            "xss", "xxe",
        }
        self.assertEqual(set(todos().keys()), esperados)


class TestReport(unittest.TestCase):
    def _result(self):
        f = Finding(
            check="headers", title="Header ausente: x", severity=Severity.MEDIUM,
            confidence=Confidence.CONFIRMED, url="http://x", description="d",
            evidence="e", remediation="r", cwe="CWE-693",
        )
        return ScanResult(
            target="http://x", host="x", iniciado_em="2025-01-01 00:00:00",
            duracao_s=1.0, findings=[f], checks_rodados=["headers"],
            total_requisicoes=3,
        )

    def test_todos_os_formatos_geram(self):
        r = self._result()
        for fmt in FORMATOS:
            saida = gerar(r, fmt)
            self.assertTrue(saida and isinstance(saida, str))

    def test_json_tem_achado(self):
        import json
        r = self._result()
        d = json.loads(gerar(r, "json"))
        self.assertEqual(d["resumo"]["total"], 1)
        self.assertEqual(d["achados"][0]["cwe"], "CWE-693")


class TestSelftest(unittest.TestCase):
    def test_selftest_passa(self):
        from secscan.selftest import rodar_selftest

        ok, detalhes = rodar_selftest(verboso=False)
        self.assertTrue(
            ok,
            msg=f"selftest falhou: faltando={detalhes['esperados_faltando']} "
                f"erros={detalhes['erros']}",
        )


if __name__ == "__main__":
    unittest.main()
