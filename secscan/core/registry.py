"""Registro central de checks.

Cada check se registra com um id, categoria (passivo/ativo/intrusivo) e um
alvo-tipo. O runner consulta este registro para saber o que rodar, respeitar
--only/--skip e aplicar a trava de autorizacao nos checks intrusivos.
"""

from __future__ import annotations

from enum import Enum
from typing import Callable


class Categoria(str, Enum):
    """Quao invasivo e o check.

    PASSIVO:   so observa (headers, cookies, TLS). Seguro em qualquer alvo.
    ATIVO:     manda requisicoes sondando caminhos/parametros, sem payload de ataque.
    INTRUSIVO: envia payloads de teste (injecao, forca bruta). Exige autorizacao.
    """

    PASSIVO = "passivo"
    ATIVO = "ativo"
    INTRUSIVO = "intrusivo"


class TipoAlvo(str, Enum):
    URL = "url"
    HOST = "host"


_REGISTRO: dict[str, "CheckMeta"] = {}


class CheckMeta:
    def __init__(
        self,
        id: str,
        titulo: str,
        categoria: Categoria,
        fabrica: Callable,
        tipo_alvo: TipoAlvo = TipoAlvo.URL,
    ) -> None:
        self.id = id
        self.titulo = titulo
        self.categoria = categoria
        self.fabrica = fabrica
        self.tipo_alvo = tipo_alvo


def registrar(
    id: str,
    titulo: str,
    categoria: Categoria,
    tipo_alvo: TipoAlvo = TipoAlvo.URL,
):
    """Decorator que registra uma classe de check."""

    def _wrap(cls):
        if id in _REGISTRO:
            raise ValueError(f"Check duplicado: {id}")
        _REGISTRO[id] = CheckMeta(id, titulo, categoria, cls, tipo_alvo)
        cls.id = id
        cls.titulo = titulo
        cls.categoria = categoria
        cls.tipo_alvo = tipo_alvo
        return cls

    return _wrap


def todos() -> dict[str, CheckMeta]:
    return dict(_REGISTRO)


def get(id: str) -> CheckMeta | None:
    return _REGISTRO.get(id)


def selecionar(only: list[str] | None, skip: list[str] | None) -> list[CheckMeta]:
    ids = list(_REGISTRO.keys())
    if only:
        ids = [i for i in ids if i in set(only)]
    if skip:
        ids = [i for i in ids if i not in set(skip)]
    return [_REGISTRO[i] for i in ids]
