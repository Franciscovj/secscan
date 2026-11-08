"""Cliente HTTP compartilhado por todos os checks.

Uma sessao unica (reuso de conexao), User-Agent configuravel, timeout, numero
de tentativas com recuo e um limitador de taxa (rate limit) para nao martelar o
alvo. Todo check recebe uma instancia deste cliente em vez de chamar requests
direto, o que garante comportamento e cortesia consistentes.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field

import requests
from requests.adapters import HTTPAdapter

try:
    from urllib3.util.retry import Retry
except Exception:  # pragma: no cover
    Retry = None


UA_PADRAO = "secscan/0.3 (+https://github.com/Franciscovj/secscan)"


class _RateLimiter:
    """Garante no minimo `intervalo` segundos entre requisicoes (thread-safe)."""

    def __init__(self, req_por_seg: float) -> None:
        self._intervalo = 1.0 / req_por_seg if req_por_seg > 0 else 0.0
        self._lock = threading.Lock()
        self._proximo = 0.0

    def espera(self) -> None:
        if self._intervalo <= 0:
            return
        with self._lock:
            agora = time.monotonic()
            if agora < self._proximo:
                time.sleep(self._proximo - agora)
                agora = time.monotonic()
            self._proximo = agora + self._intervalo


@dataclass
class HttpConfig:
    timeout: float = 10.0
    user_agent: str = UA_PADRAO
    verificar_tls: bool = True
    tentativas: int = 2
    req_por_seg: float = 10.0
    proxy: str | None = None
    headers_extra: dict[str, str] = field(default_factory=dict)
    seguir_redirect: bool = True


class HttpClient:
    """Fachada fina sobre requests.Session com rate limit e contagem de requisicoes."""

    def __init__(self, config: HttpConfig | None = None) -> None:
        self.config = config or HttpConfig()
        self._rate = _RateLimiter(self.config.req_por_seg)
        self._contagem = 0
        self._lock = threading.Lock()
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": self.config.user_agent})
        if self.config.headers_extra:
            self.session.headers.update(self.config.headers_extra)
        if self.config.proxy:
            self.session.proxies.update(
                {"http": self.config.proxy, "https": self.config.proxy}
            )
        if Retry is not None and self.config.tentativas > 0:
            retry = Retry(
                total=self.config.tentativas,
                backoff_factor=0.4,
                status_forcelist=(502, 503, 504),
                allowed_methods=frozenset(["GET", "HEAD", "POST", "OPTIONS"]),
            )
            adapter = HTTPAdapter(max_retries=retry)
            self.session.mount("http://", adapter)
            self.session.mount("https://", adapter)

    @property
    def total_requisicoes(self) -> int:
        return self._contagem

    def request(self, metodo: str, url: str, **kwargs) -> requests.Response:
        self._rate.espera()
        kwargs.setdefault("timeout", self.config.timeout)
        kwargs.setdefault("verify", self.config.verificar_tls)
        kwargs.setdefault("allow_redirects", self.config.seguir_redirect)
        with self._lock:
            self._contagem += 1
        return self.session.request(metodo, url, **kwargs)

    def get(self, url: str, **kwargs) -> requests.Response:
        return self.request("GET", url, **kwargs)

    def head(self, url: str, **kwargs) -> requests.Response:
        return self.request("HEAD", url, **kwargs)

    def post(self, url: str, **kwargs) -> requests.Response:
        return self.request("POST", url, **kwargs)

    def options(self, url: str, **kwargs) -> requests.Response:
        return self.request("OPTIONS", url, **kwargs)

    def fechar(self) -> None:
        try:
            self.session.close()
        except Exception:
            pass
