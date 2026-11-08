---
name: secscan
description: >
  Opera a CLI `secscan` (ferramenta de auditoria de seguranca web da OrbitFVJ,
  repo publico github.com/Franciscovj/secscan) para escanear um site/host e
  achar vulnerabilidades: headers, cookies, TLS, CORS, CSP, SQL injection, XSS,
  path traversal, SSRF, XXE, redirecionamento aberto, arquivos sensiveis,
  .git exposto, forca bruta de login, portas abertas, subdominios e mais (23
  checks). Use SEMPRE que o usuario pedir para auditar, escanear ou testar a
  seguranca de um site/API/host dele, procurar vulnerabilidades, checar
  headers/SSL/CORS/CSP, fazer um pentest ou varredura de seguranca, rodar o
  secscan, ou gerar um relatorio de seguranca — mesmo que ele nao diga
  "secscan" com todas as letras. So para alvos que o usuario possui ou tem
  permissao escrita para testar.
---

# secscan — auditoria de seguranca web por CLI

`secscan` transforma um alvo (URL ou host) num relatorio estruturado de achados,
com severidade, confianca, evidencia, remediacao e CWE/OWASP por item. A saida
em JSON e estavel e feita para ser lida por outra ferramenta ou por voce (IA).

## Regra de ouro: autorizacao

Rode o secscan **somente** em alvos que o usuario possui ou tem permissao
escrita para testar. Os checks *intrusivos* (que enviam payloads de ataque: SQL
injection, XSS, path traversal, SSRF, XXE, forca bruta) so rodam contra alvos
locais/privados ou quando o usuario passa `--autorizo`. Antes de usar
`--autorizo` ou o perfil `completo` contra um alvo na internet, confirme com o
usuario que ele tem autorizacao. Nunca escaneie alvo de terceiro sem permissao.

## Instalacao (uma vez por maquina)

Precisa de Python 3.9+ e `git`. Instale direto do repositorio (nao ha PyPI):

```bash
pip install git+https://github.com/Franciscovj/secscan.git
```

Isso cria o comando `secscan`. Sem instalar, tambem roda com `python -m secscan`
dentro de um clone do repo. Para checar se esta instalado: `secscan --version`.

## Como rodar

O comando principal e `secscan scan <alvo>`. O alvo e uma URL (`https://site.com`)
ou host (`site.com`). A saida vai para o stdout; o progresso e o resumo colorido
vao para o stderr (entao `... > relatorio.json` guarda so o relatorio limpo).

```bash
# auditoria padrao (checks passivos + ativos), relatorio JSON no stdout
secscan scan https://site-do-usuario.com

# salvar relatorios (txt/json/html/md/sarif) numa pasta
secscan scan https://site-do-usuario.com --format html -o relatorios/

# auditoria COMPLETA, incluindo checks intrusivos (exige autorizacao)
secscan scan https://site-do-usuario.com --perfil completo --autorizo

# so alguns checks
secscan scan site-do-usuario.com --only headers,tls,cookies,cors --format json

# em automacao/CI (nao pergunta nada; sem --autorizo, pula os intrusivos)
secscan scan https://site.com --sem-interacao --silencioso --format json
```

### Perfis (`--perfil`)
- `rapido` — so checks **passivos** (so observam; seguro em qualquer alvo).
- `padrao` — passivos + **ativos** (sondam caminhos/parametros). **Padrao.**
- `completo` — tudo, incluindo **intrusivos** (envia payloads; exige `--autorizo`).

### Opcoes uteis
| Opcao | Para que |
|---|---|
| `--only a,b` / `--skip a,b` | roda so / pula esses checks |
| `--format txt\|json\|html\|md\|sarif\|all` | formato do relatorio (padrao `json`) |
| `-o, --output DIR` | salva arquivo(s) nessa pasta (senao, imprime no stdout) |
| `--autorizo` | confirma permissao; libera os checks intrusivos |
| `--sem-interacao` | nunca pergunta (CI); sem `--autorizo`, pula intrusivos |
| `--rate N` | limite de requisicoes por segundo (padrao 10; 0 = sem limite) |
| `--threads N` / `--timeout S` | paralelismo / timeout por requisicao |
| `--proxy URL` | passa por um proxy (ex.: Burp em `http://127.0.0.1:8080`) |
| `--sem-tls` | nao verificar certificado TLS |
| `--falhar-se-achar` | codigo de saida 1 se houver achado alto/critico (bom p/ CI) |

### Outros comandos
- `secscan checks` — lista os 24 checks, por categoria (passivo/ativo/intrusivo).
- `secscan selftest` — auto-teste: sobe um alvo de mentira local e confirma que
  os checks disparam. Nao bate em site real. Bom para validar a instalacao.
- `secscan` (sem argumento) — abre um menu interativo colorido (use so quando ha
  um humano no terminal; em automacao, prefira os subcomandos).

## Como ler o resultado (JSON)

Prefira `--format json`. A estrutura:

```json
{
  "alvo": "https://site.com",
  "resumo": {"critical": 0, "high": 2, "medium": 5, "low": 3, "info": 4, "total": 14},
  "achados": [
    {
      "check": "sql_injection",
      "title": "SQL Injection baseada em erro no parametro 'id'",
      "severity": "high",
      "confidence": "firm",
      "url": "https://site.com/...",
      "description": "…",
      "evidence": "…",
      "remediation": "…",
      "cwe": "CWE-89",
      "owasp": "A03:2021 Injection"
    }
  ]
}
```

Ao reportar para o usuario:
1. Comece pelo `resumo` (quantos achados, quantos altos/criticos).
2. Liste os achados por **severidade** (critical → high → medium → low → info),
   e dentro de cada um pela `confidence` (`confirmed` > `firm` > `tentative`).
3. Para cada achado relevante, de o `title`, a `evidence` (o que comprova) e a
   `remediation` (como corrigir). Trate `tentative` como suspeita a confirmar,
   nao como certeza.
4. Nao invente achados: reporte so o que esta no JSON.

## Os 24 checks

- **passivo** (so observa): `headers`, `cookies`, `cors`, `tls`, `csp_audit`,
  `info_disclosure`
- **ativo** (sonda caminhos/parametros): `sensitive_paths`, `git_exposure`,
  `directory_listing`, `open_redirect`, `backup_files`, `admin_panel`,
  `debug_mode`, `csrf`, `port_scan`, `subdomain_enum`, `http_methods`,
  `db_exposure` (MongoDB/Redis/Elasticsearch/CouchDB/Memcached sem auth)
- **intrusivo** (envia payloads — exige `--autorizo`): `sql_injection`, `xss`,
  `traversal`, `weak_login`, `ssrf`, `xxe`

## Fluxo recomendado

1. Confirme que o alvo e do usuario (ou ele tem permissao). Se for na internet e
   for usar intrusivos, peca o "ok" explicito.
2. Comece leve: `secscan scan <alvo> --format json` (perfil padrao). Veja o resumo.
3. Se o usuario autorizou e quer fundo: `--perfil completo --autorizo`.
4. Leia o JSON, resuma por severidade, destaque os altos/criticos com evidencia e
   correcao. Ofereca salvar o relatorio (`-o relatorios/ --format html`) se util.
5. Se um check falhar ou o alvo nao responder, diga o que aconteceu — nao fabrique.

## Observacoes

- Erros de rede num check nao derrubam o scan; o check so nao gera achado.
- A ferramenta respeita um limite de requisicoes (`--rate`) para nao martelar o
  alvo; aumente so com cuidado e autorizacao.
- Codigo e documentacao: github.com/Franciscovj/secscan (uso autorizado apenas).
