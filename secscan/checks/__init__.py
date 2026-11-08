"""Pacote de checks. Importar este modulo registra todos os checks disponiveis.

Para adicionar um check: crie um modulo aqui, decore a classe com @registrar
e acrescente o import abaixo.
"""

from . import (  # noqa: F401
    admin_panel,
    backup_files,
    cookies,
    cors,
    csrf,
    debug_mode,
    directory_listing,
    git_exposure,
    headers,
    open_redirect,
    port_scan,
    sensitive_paths,
    sql_injection,
    ssrf,
    subdomain_enum,
    tls,
    traversal,
    weak_login,
    xss,
    xxe,
)
