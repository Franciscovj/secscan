"""Bancos de dados e servicos expostos SEM autenticacao (ativo, por host).

Vai alem do `port_scan`: nao basta a porta estar aberta, o que importa e se da
para falar com o servico SEM credencial. MongoDB, Redis e Elasticsearch abertos
e sem senha estao entre as maiores causas de vazamento real — bots varrem a
internet, acham a porta em horas e copiam ou apagam o banco.

Este check so manda o comando de handshake/leitura leve de cada servico (ping,
listDatabases, GET /) para constatar o acesso sem autenticacao — nao extrai
registros. Tudo com socket/HTTP de stdlib, timeout curto, e cada sonda isolada
em try/except para nunca derrubar o scan.
"""

from __future__ import annotations

import socket
import struct
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..core.finding import Confidence, Severity
from ..core.registry import Categoria, TipoAlvo, registrar
from .base import Check

TIMEOUT = 1.5


# ---- BSON minimo (so o necessario para montar um comando simples) ---------

def _bson(doc: dict) -> bytes:
    partes = b""
    for nome, valor in doc.items():
        ename = nome.encode() + b"\x00"
        if isinstance(valor, bool):
            partes += b"\x08" + ename + (b"\x01" if valor else b"\x00")
        elif isinstance(valor, int):
            partes += b"\x10" + ename + struct.pack("<i", valor)
        elif isinstance(valor, str):
            v = valor.encode() + b"\x00"
            partes += b"\x02" + ename + struct.pack("<i", len(v)) + v
        else:
            raise ValueError(f"tipo nao suportado em BSON: {nome}")
    corpo = partes + b"\x00"
    return struct.pack("<i", len(corpo) + 4) + corpo


def _op_msg(doc: dict) -> bytes:
    secao = b"\x00" + _bson(doc)          # kind 0 body section
    corpo = struct.pack("<i", 0) + secao  # flagBits = 0
    header = struct.pack("<iiii", 16 + len(corpo), 1, 0, 2013)  # opCode OP_MSG
    return header + corpo


def _recv(sock: socket.socket, n: int = 65535) -> bytes:
    try:
        return sock.recv(n)
    except OSError:
        return b""


@registrar("db_exposure", "Banco/servico exposto sem autenticacao",
           Categoria.ATIVO, TipoAlvo.HOST)
class DbExposureCheck(Check):
    def executar(self):
        achados = []
        host = self.target.host
        if not host:
            return achados
        sondas = (self._mongodb, self._redis, self._elasticsearch,
                  self._couchdb, self._memcached)

        def _roda(sonda):
            try:
                return sonda(host)
            except Exception as e:
                self.log(f"{sonda.__name__}: {e}")
                return None

        # servicos sondados em paralelo: o tempo total vira ~1 timeout, nao 5
        with ThreadPoolExecutor(max_workers=len(sondas)) as pool:
            for fut in as_completed([pool.submit(_roda, s) for s in sondas]):
                f = fut.result()
                if f:
                    achados.append(f)
        return achados

    # ---- MongoDB (27017) --------------------------------------------------
    def _mongodb(self, host):
        porta = 27017
        self.log(f"sondando MongoDB em {host}:{porta}")
        try:
            with socket.create_connection((host, porta), timeout=TIMEOUT) as s:
                s.settimeout(TIMEOUT)
                # listDatabases exige autenticacao quando ha controle de acesso
                s.sendall(_op_msg({"listDatabases": 1, "nameOnly": True,
                                   "$db": "admin"}))
                resp = _recv(s)
        except OSError:
            return None
        if not resp:
            return None
        protegido = (b"requires authentication" in resp or b"not authorized" in resp
                     or b"Unauthorized" in resp
                     or (b"errmsg" in resp and b"databases" not in resp))
        if b"databases" in resp and b"errmsg" not in resp:
            return self.achado(
                title="MongoDB exposto SEM autenticacao",
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                url=f"{host}:{porta}",
                description="O MongoDB respondeu 'listDatabases' sem exigir "
                "credencial — qualquer um na rede pode ler, copiar ou apagar os "
                "bancos. E a causa classica de vazamento e ransomware de dados.",
                evidence=f"{host}:{porta} respondeu a listDatabases sem auth.",
                remediation="Habilite autenticacao (security.authorization: "
                "enabled), crie usuarios e NUNCA exponha a porta 27017 a "
                "internet (bind em 127.0.0.1 ou firewall/VPN).",
                cwe="CWE-306",
                owasp="A07:2021 Identification and Authentication Failures",
            )
        if protegido:
            return self.achado(
                title="MongoDB acessivel na rede (com autenticacao)",
                severity=Severity.LOW,
                confidence=Confidence.FIRM,
                url=f"{host}:{porta}",
                description="A porta do MongoDB responde na rede. Exige auth "
                "(bom), mas idealmente nao deveria ficar exposta publicamente.",
                evidence=f"{host}:{porta} respondeu exigindo autenticacao.",
                remediation="Restrinja a porta por firewall/VPN; exponha so se "
                "necessario.",
                cwe="CWE-668",
            )
        return None

    # ---- Redis (6379) -----------------------------------------------------
    def _redis(self, host):
        porta = 6379
        self.log(f"sondando Redis em {host}:{porta}")
        try:
            with socket.create_connection((host, porta), timeout=TIMEOUT) as s:
                s.settimeout(TIMEOUT)
                s.sendall(b"PING\r\n")
                resp = _recv(s)
        except OSError:
            return None
        if not resp:
            return None
        if resp.startswith(b"+PONG"):
            return self.achado(
                title="Redis exposto SEM autenticacao",
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                url=f"{host}:{porta}",
                description="O Redis respondeu PING sem senha — da para ler e "
                "escrever tudo, e em muitos casos executar comandos no servidor.",
                evidence=f"{host}:{porta} respondeu '+PONG' sem AUTH.",
                remediation="Defina requirepass (ou ACLs), ligue protected-mode "
                "e nao exponha a porta 6379 (bind 127.0.0.1 / firewall).",
                cwe="CWE-306",
                owasp="A07:2021 Identification and Authentication Failures",
            )
        if b"NOAUTH" in resp:
            return self.achado(
                title="Redis acessivel na rede (com senha)",
                severity=Severity.LOW,
                confidence=Confidence.FIRM,
                url=f"{host}:{porta}",
                description="A porta do Redis responde e exige senha (bom), mas "
                "nao deveria ficar exposta publicamente.",
                evidence=f"{host}:{porta} respondeu 'NOAUTH'.",
                remediation="Restrinja a porta por firewall/VPN.",
                cwe="CWE-668",
            )
        return None

    # ---- Elasticsearch (9200) --------------------------------------------
    def _elasticsearch(self, host):
        base = f"http://{host}:9200"
        self.log(f"sondando Elasticsearch em {base}")
        try:
            r = self.http.get(base + "/", timeout=TIMEOUT)
        except Exception:
            return None
        corpo = r.text or ""
        if r.status_code == 200 and ("cluster_name" in corpo
                                     or "You Know, for Search" in corpo):
            lidos = ""
            try:
                ri = self.http.get(base + "/_cat/indices", timeout=TIMEOUT)
                if ri.status_code == 200:
                    lidos = ri.text[:120]
            except Exception:
                pass
            return self.achado(
                title="Elasticsearch exposto SEM autenticacao",
                severity=Severity.CRITICAL if lidos else Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                url=base,
                description="O Elasticsearch respondeu sem credencial"
                + (" e listou indices (dados legiveis)." if lidos
                   else " (cluster acessivel)."),
                evidence=f"GET {base}/ = 200"
                + (f"; indices: {lidos!r}" if lidos else ""),
                remediation="Ative seguranca (xpack.security) com usuario/senha "
                "e nao exponha a porta 9200 a internet.",
                cwe="CWE-306",
                owasp="A07:2021 Identification and Authentication Failures",
            )
        return None

    # ---- CouchDB (5984) ---------------------------------------------------
    def _couchdb(self, host):
        base = f"http://{host}:5984"
        self.log(f"sondando CouchDB em {base}")
        try:
            r = self.http.get(base + "/", timeout=TIMEOUT)
        except Exception:
            return None
        if r.status_code == 200 and "couchdb" in (r.text or "").lower():
            aberto = False
            try:
                ra = self.http.get(base + "/_all_dbs", timeout=TIMEOUT)
                aberto = ra.status_code == 200 and ra.text.strip().startswith("[")
            except Exception:
                pass
            if aberto:
                return self.achado(
                    title="CouchDB exposto SEM autenticacao",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CONFIRMED,
                    url=base,
                    description="O CouchDB listou os bancos sem credencial.",
                    evidence=f"GET {base}/_all_dbs = 200",
                    remediation="Configure admin/senha e restrinja a porta 5984.",
                    cwe="CWE-306",
                    owasp="A07:2021 Identification and Authentication Failures",
                )
        return None

    # ---- Memcached (11211) ------------------------------------------------
    def _memcached(self, host):
        porta = 11211
        self.log(f"sondando Memcached em {host}:{porta}")
        try:
            with socket.create_connection((host, porta), timeout=TIMEOUT) as s:
                s.settimeout(TIMEOUT)
                s.sendall(b"stats\r\n")
                resp = _recv(s)
        except OSError:
            return None
        if resp.startswith(b"STAT ") or b"\r\nSTAT " in resp:
            return self.achado(
                title="Memcached exposto SEM autenticacao",
                severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                url=f"{host}:{porta}",
                description="O Memcached respondeu 'stats' sem autenticacao — "
                "cache legivel e usavel em ataques de amplificacao.",
                evidence=f"{host}:{porta} respondeu a 'stats'.",
                remediation="Ligue SASL ou -l 127.0.0.1 e bloqueie a porta 11211.",
                cwe="CWE-306",
                owasp="A05:2021 Security Misconfiguration",
            )
        return None
