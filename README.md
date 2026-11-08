# secscan

[![ci](https://github.com/Franciscovj/secscan/actions/workflows/ci.yml/badge.svg)](https://github.com/Franciscovj/secscan/actions/workflows/ci.yml)
![python](https://img.shields.io/badge/python-3.9%2B-blue)
![license](https://img.shields.io/badge/license-MIT-green)

Ferramenta de auditoria de segurança web em linha de comando — transforma uma
gravação de alvo em um relatório estruturado de achados (severidade, confiança,
evidência, remediação e CWE/OWASP por item).

> ⚠️ **Uso autorizado apenas.** Rode o secscan **somente** em sistemas que você
> possui ou para os quais tem permissão **escrita**. Os checks intrusivos
> (injeção, força bruta) só rodam em alvos locais/privados ou com `--autorizo`.
> Escanear sistema de terceiro sem autorização é ilegal na maioria dos países.

## Por que existe

A saída foi pensada para ser consumida por **outra ferramenta ou por uma IA**:
o `--format json` é estável e descreve cada achado de forma objetiva. Também há
um **auto-teste embutido** (`secscan selftest`) que sobe um alvo de mentira local
e valida os checks sozinho — assim a ferramenta se verifica sem bater em site
real e sem gasto manual.

## Instalação

Instale direto do repositório — não precisa de PyPI:

```bash
pip install git+https://github.com/Franciscovj/secscan.git
```

Isso instala o comando `secscan` na sua máquina. (Requer `git` instalado.)

Ou clone e instale em modo editável, para desenvolver:

```bash
git clone https://github.com/Franciscovj/secscan.git
cd secscan
python -m venv venv
# Windows:  .\venv\Scripts\activate
# Linux/macOS:  source venv/bin/activate
pip install -e ".[dev]"
```

Sem instalar nada, também dá para rodar com `python -m secscan`.

## Uso

```bash
# auditoria padrão (passivo + ativo), saída JSON no stdout
secscan scan https://meusite.com

# relatório HTML numa pasta
secscan scan https://meusite.com --format html -o relatorios/

# só alguns checks
secscan scan meusite.com --only headers,tls,cookies,cors

# auditoria completa, incluindo checks intrusivos (exige autorização)
secscan scan https://meusite.com --perfil completo --autorizo

# listar os checks disponíveis
secscan checks

# auto-teste (não precisa de alvo externo)
secscan selftest
```

### Principais opções do `scan`

| Opção | O que faz |
|---|---|
| `--only a,b` / `--skip a,b` | roda só / pula esses checks |
| `--perfil rapido\|padrao\|completo` | passivo / +ativo / +intrusivo |
| `--format txt\|json\|html\|md\|sarif\|all` | formato do relatório (JSON é o padrão) |
| `-o, --output DIR` | salva em arquivo(s) nessa pasta (senão, imprime no stdout) |
| `--autorizo` | confirma que você tem permissão (libera os intrusivos) |
| `--rate N` | limite de requisições por segundo (padrão 10; 0 = sem limite) |
| `--threads N` / `--timeout S` | paralelismo / timeout por requisição |
| `--proxy URL` | passa por um proxy (ex.: Burp em `http://127.0.0.1:8080`) |
| `--sem-tls` | não verificar certificado |
| `--falhar-se-achar` | sai com código 1 se houver achado alto/crítico (útil em CI) |

## Checks

Organizados por quão invasivos são:

- **passivo** (só observa): `headers`, `cookies`, `cors`, `tls`, `csp_audit`,
  `info_disclosure`
- **ativo** (sonda caminhos/params): `sensitive_paths`, `git_exposure`,
  `directory_listing`, `open_redirect`, `backup_files`, `admin_panel`,
  `debug_mode`, `csrf`, `port_scan`, `subdomain_enum`, `http_methods`
- **intrusivo** (envia payloads — exige autorização): `sql_injection`, `xss`,
  `traversal`, `weak_login`, `ssrf`, `xxe`

`secscan checks` lista todos com a categoria.

## Arquitetura

```
secscan/
  core/        finding (modelo do achado), http_client, target, registry, runner, authorization
  checks/      um módulo por verificação (classe Check → lista de Finding)
  report/      reporters txt/json/html/md/sarif
  selftest/    alvo de mentira + validação (o `secscan selftest`)
  wordlists/   listas usadas pelos checks
tests/         testes (rodam contra o alvo de mentira, sem rede externa)
```

Cada check herda de `Check` e retorna uma lista de `Finding` estruturados —
nada de texto solto reparseado depois. Para adicionar um check: crie um módulo
em `checks/`, decore a classe com `@registrar(id, titulo, Categoria.X)` e
inclua o import em `checks/__init__.py`.

## Testes

```bash
python -m pytest          # ou: python -m unittest
secscan selftest          # auto-teste de ponta a ponta
```

## Licença

MIT.
