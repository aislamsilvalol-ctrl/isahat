# Auditoria do projeto IsaHat

Data da leitura: 2026-10-07. Base: `main` em `ad65241` (`security: drop unreachable security@isahat.dev, add Dependabot (#1)`). Versão declarada: `0.1.0` (`src/isahat/__init__.py`, linhas 12; `pyproject.toml`, linhas 6).

Este documento só descreve o que está no repositório. Nenhum código de aplicação foi alterado nesta auditoria.

Escopo pedido em destaque: scans híbridos, jobs duráveis e a UI web local. Resultado curto: o pipeline do motor sempre mistura crawl web e descoberta de API, mas não existe um modo chamado hybrid; os “jobs” da bridge são tarefas `asyncio` na memória do processo, com checkpoints SQLite parciais; a UI local não autentica ninguém.

---

## 1. PROJECT MAP

### O que o projeto é e faz

IsaHat é um auditor de segurança ofensivo-defensivo, local e offline-first, para aplicações web e APIs que o operador declara estar autorizado a testar. O motor em `src/isahat/core/` descobre superfície (crawl + formulários + OpenAPI/GraphQL), roda detectores não destrutivos por padrão e grava achados com severidade e confiança separadas. As cascas são a CLI Typer (`src/isahat/cli/main.py`), a bridge HTTP FastAPI (`src/isahat/api/app.py`, comando `isahat serve`) e o shell desktop Tauri + React (`apps/desktop/`).

Política de uso: `RESPONSIBLE-USE.md`, `SECURITY.md`, `THREAT-MODEL.md`. Licença Apache-2.0 (`LICENSE`, ADR em `docs/adr/0002-license.md`).

O laboratório `labs/vulnerable_apps/simple_app/app.py` é um alvo **intencionalmente vulnerável**, só para teste local. `labs/README.md` (linhas 5–7) pede para não expô-lo na rede. `labs/README.md` (linhas 23–27) ainda lista `mock_apis/` e `sample_targets/` como roadmap; esses diretórios não existem.

### Stack

| Camada | O que o código usa |
| --- | --- |
| Linguagem do motor | Python `>=3.11` (`pyproject.toml`, linha 10). Ambiente desta auditoria: Python 3.12.3. |
| CLI | Typer + Rich (`pyproject.toml`, linhas 36–37; `src/isahat/cli/main.py`). |
| HTTP de saída | `httpx` async (`src/isahat/core/http.py`). |
| Modelos | Pydantic v2 (`src/isahat/core/models.py`, `config.py`, `auth.py`, `state.py`). |
| Config | YAML via PyYAML, `yaml.safe_load` (`src/isahat/core/config.py`, linhas 77–92). |
| Bridge | FastAPI + Uvicorn (`src/isahat/api/app.py`; `serve` em `src/isahat/cli/main.py`, linhas 443–475). |
| UI | React 18, React Router 6, Vite 5, TypeScript 5.5 (`apps/desktop/package.json`). i18n PT/EN em `apps/desktop/src/i18n/`. |
| Shell nativo | Tauri 2, Rust edition 2021 (`apps/desktop/src-tauri/`). O Rust só sobe a janela (`apps/desktop/src-tauri/src/main.rs`, linhas 9–12). |
| Banco | SQLite da stdlib, arquivo único. Sem ORM, sem Alembic, sem Postgres. |
| Filas / workers externos | Ausentes. Sem Celery, RQ, Redis, broker ou tabela de jobs. |
| Telegram, webhooks, painel admin, pagamentos | Ausentes no código. |

Dependências Python diretas: `typer`, `rich`, `httpx`, `pydantic`, `PyYAML`, `fastapi`, `uvicorn` (`pyproject.toml`, linhas 34–42). Dev: `pytest`, `pytest-asyncio`, `pytest-cov`, `ruff`, `mypy`, `types-PyYAML` (linhas 51–57). UI: `@tauri-apps/api`, `react`, `react-dom`, `react-router-dom` (`apps/desktop/package.json`, linhas 14–18).

O monorepo npm (`package.json` na raiz) só declara o workspace `apps/desktop`. O motor não é um pacote Node.

### Frontend

`apps/desktop/` é a única UI. Rotas em `apps/desktop/src/App.tsx` (linhas 89–94):

- `/` dashboard (`screens/Dashboard.tsx`)
- `/new` novo scan (`screens/NewScan.tsx`)
- `/scans/:id` detalhe ao vivo (`screens/ScanDetail.tsx`)
- `/compare` comparação (`screens/Compare.tsx`)

O cliente HTTP está em `apps/desktop/src/api/client.ts`. No webview Tauri a base é `http://127.0.0.1:8741`; no `vite dev` a base é `/api`, proxiada para `127.0.0.1:8741` (`apps/desktop/vite.config.ts`, linhas 10–18). Não há tela de login, sessão, cookie de app nem header de credencial da bridge.

### Backend

Não há servidor multi-usuário. O “backend” é:

1. Biblioteca in-process `isahat.core` + `isahat.storage` + `isahat.reporting`.
2. Bridge loopback `create_app()` em `src/isahat/api/app.py`.

Endpoints reais (também listados em `docs/API.md`, linhas 114–124):

| Método | Caminho | Função |
| --- | --- | --- |
| GET | `/health` | versão (`app.py`, linhas 143–145) |
| POST | `/scans` | enfileira scan, 202 (`app.py`, linhas 147–162) |
| GET | `/scans` | histórico + scans em memória (`app.py`, linhas 164–204) |
| GET | `/checkpoints` | scans interrompidos (`app.py`, linhas 206–219) |
| POST | `/scans/{scan_id}/resume` | retoma checkpoint (`app.py`, linhas 221–243) |
| GET | `/scans/{scan_id}` | `ScanResult` JSON (`app.py`, linhas 245–250) |
| GET | `/scans/{scan_id}/status` | estado do job em memória (`app.py`, linhas 252–262) |
| GET | `/scans/{scan_id}/events` | SSE (`app.py`, linhas 264–283) |
| GET | `/scans/{scan_id}/report` | relatório (`app.py`, linhas 285–299) |
| POST | `/scans/{scan_id}/findings/{finding_id}/annotation` | revisão (`app.py`, linhas 301–315) |
| GET | `/compare` | diff de achados (`app.py`, linhas 317–334) |
| GET | `/severities` | enum (`app.py`, linhas 336–338) |

FastAPI também publica `/docs` e `/openapi.json` (padrão da lib; `serve` anuncia “docs at /docs” em `cli/main.py`, linha 467). Não há middleware de autenticação.

CLI (`src/isahat/cli/main.py`): `scan`, `report`, `compare`, `list`, `plugins list`, `plugins install`, `doctor`, `serve`, `version`. Códigos de saída em `src/isahat/cli/exit_codes.py`: 0 ok, 1 erro, 2 uso, 3 limiar `--fail-on`, 130 cancelado.

### Pipeline do scan (o que existe no lugar de “hybrid”)

`ScanEngine.run` (`src/isahat/core/engine.py`, linhas 85–187) sempre executa, nesta ordem:

1. Crawl BFS dentro do escopo (`Crawler`, `src/isahat/core/crawler.py`).
2. Fingerprint passivo (`src/isahat/core/tech.py`).
3. Descoberta de API (`discover_apis` em `src/isahat/core/api.py`).
4. Pontos de injeção GET (`src/isahat/core/injection.py`).
5. Detectores padrão (`src/isahat/core/detectors/__init__.py`, linhas 41–59), mais `RateLimitingDetector` só se `safety.rate_limit_checks` (`engine.py`, linhas 60–61).

Não há símbolo, flag, classe ou commit com o nome hybrid. `scan_type` (`web` ou `api`) é gravado no resultado (`engine.py`, linhas 49 e 91; `models.py`, linha 223) e **não é comparado em lugar nenhum de `src/`** para escolher estágios ou detectores. O seletor da UI (`apps/desktop/src/screens/NewScan.tsx`, linhas 79–81) e o `--type` da CLI (`cli/main.py`, linha 107) mudam só esse rótulo.

O mesmo vale para `profile`: a UI oferece `safe` e `standard` (`NewScan.tsx`, linhas 73–75). O motor copia a string para `config.scan.profile` (`api/app.py`, linha 112; `cli/main.py`, linhas 58–59) e a persiste. Nenhum `if` em `src/` altera detectores, métodos HTTP ou limites por causa do nome do perfil. O que muda comportamento de segurança é `safety.destructive_tests`, `safety.rate_limit`, `safety.rate_limit_checks` e os caps de crawl (`src/isahat/core/config.py`, linhas 31–59).

Conclusão: o scan atual é um único pipeline web+API. Os modos “web”, “api”, “safe” e “standard” da interface são metadados.

### Banco, ORM, schema, migrações

`ScanStore` (`src/isahat/storage/database.py`) abre SQLite com `check_same_thread=False` e um `RLock` (linhas 112–123). Caminho padrão: `$ISAHAT_HOME/isahat.db` ou `~/.isahat/isahat.db` (`default_db_path`, linhas 70–76).

Schema aplicado com `executescript` a cada abertura (`_SCHEMA`, linhas 36–67). Tabelas:

- `scans` — colunas de resumo + `payload` JSON do `ScanResult`. PK `id`. Upsert em `save` (linhas 136–174).
- `checkpoints` — `scan_id` PK, `target`, `stage`, `payload` JSON, `saved_at`.
- `annotations` — `finding_id` PK, `state`, `comment`, `updated_at`.

Índices: `idx_scans_target`, `idx_scans_started`. Não há tabela de versão de schema, não há migrações, não há ORM. ADR-0003 (`docs/adr/0003-storage.md`) registra essa escolha e deixa SQLAlchemy/Postgres para depois.

Não há `chmod` no diretório nem no arquivo. Não há `PRAGMA busy_timeout` nem `journal_mode=WAL`.

### Auth (dois sentidos diferentes)

**Auth do alvo (credencial que o scanner envia ao sistema testado).** `AuthConfig` (`src/isahat/core/auth.py`) carrega headers e cookies de um JSON. A CLI usa `--auth` (`cli/main.py`, linhas 168–174). A UI cola JSON num `<textarea>` (`NewScan.tsx`, linhas 84–91) e manda no corpo de `POST /scans` (`client.ts`, linhas 150–161). O cliente HTTP anexa isso em todo request (`http.py`, linhas 95–102). O resultado só guarda o booleano `authenticated` (`engine.py`, linha 92). O comentário de `auth.py` (linhas 4–5) diz que segredos não são persistidos; a seção 4 mostra que o checkpoint quebra essa garantia.

**Auth da UI / da bridge (quem pode operar o IsaHat).** Não existe. Não há usuário, senha, sessão, API key, middleware ou checagem de token em `src/isahat/api/app.py`. `serve` escuta em `127.0.0.1:8741` por padrão e aceita outro `--host` com um aviso no terminal (`cli/main.py`, linhas 444–473). CORS permite qualquer origem `http(s)://localhost` ou `127.0.0.1` em qualquer porta, e `tauri://localhost`, com `allow_headers=["*"]` e métodos GET/POST (`app.py`, linhas 100–105).

O único “portão” de scan é o campo `confirmed: bool` (`ScanRequest`, `app.py`, linhas 42–50). `POST /scans` devolve 400 se `confirmed` é falso (linhas 149–156) e, em seguida, **desliga** `require_scope_confirmation` (linhas 113–115). Qualquer cliente HTTP que envie `confirmed: true` inicia um scan. A UI só habilita o botão depois de três checkboxes (`NewScan.tsx`, linhas 23 e 141), mas o servidor não vê esses checkboxes.

`require_scope_confirmation` é lido só pela CLI (`cli/main.py`, linhas 69–80 e 182–185). O motor não consulta essa flag. `docs/ARCHITECTURE.md` (linhas 30–32) e `apps/desktop/README.md` (linhas 30–32) afirmam que a confirmação vive abaixo da bridge e que a UI não consegue contorná-la. O código da bridge aceita o booleano e o motor segue.

`POST /scans/{id}/resume` não pede `confirmed`. O handler monta `ScanRequest(..., confirmed=True)` sozinho (`app.py`, linhas 238–242), com o comentário de que o checkpoint prova a autorização original.

### Jobs duráveis — verificação

Não há fila durável. O estado de execução mora num `dict` local de `create_app`:

```70:88:src/isahat/api/app.py
class _ScanJob:
    """A running (or finished) scan and its progress event buffer."""
    ...
        self.status = "running"
        self.task: asyncio.Task[None] | None = None
        self.condition = asyncio.Condition()
```

`jobs: dict[str, _ScanJob] = {}` (`app.py`, linha 108). `POST /scans` gera `uuid.uuid4().hex[:12]`, publica “queued” e faz `asyncio.create_task` (`app.py`, linhas 157–161). Não existe status `queued` persistido: o job já nasce `running`.

O que é durável é o **checkpoint de progresso do scan**, não o job:

| Pergunta | O que o código faz |
| --- | --- |
| Persistência do job | Nenhuma. Processo morto apaga `jobs`, eventos SSE e o `asyncio.Task`. O comentário em `app.py` (linhas 187–188) diz que o scan em voo não é persistido até o fim. |
| Persistência do progresso | `checkpoints` no SQLite. O motor grava depois do crawl (`engine.py`, linhas 139–140), depois da descoberta de API (linhas 157–160) e depois de cada detector (linhas 227–230). Modelo em `src/isahat/core/state.py` (linhas 59–71). |
| Retries do job | Nenhum. Exceção vira `status=error` (`app.py`, linhas 133–136) e para. Não há contador, backoff nem requeue. |
| Retry HTTP | Um retry, 0,1 s, só em `httpx.TransportError` (`http.py`, linhas 162–176). Não retenta 5xx. O comentário fala em métodos idempotentes; o código retenta qualquer método que tenha passado de `_check_method`. Com `destructive_tests` ligado, um POST também seria reenviado. |
| Idempotência de `POST /scans` | Ausente. Cada POST cria outro `scan_id`. Não há `Idempotency-Key`. |
| Idempotência de gravação | `INSERT ... ON CONFLICT DO UPDATE` em scans, checkpoints e annotations (`database.py`, linhas 144–156, 236–240, 292–295). Teste: `tests/unit/test_reporting_storage.py`, `test_storage_upsert_is_idempotent`. |
| Idempotência de resume | Frágil. O 409 só ocorre se `jobs[scan_id].status == "running"` (`app.py`, linhas 226–228). Dois POSTs simultâneos podem ambos passar. O próprio teste aceita 202 **ou** 409 no segundo resume (`tests/unit/test_api_bridge.py`, linhas 161–162). |
| Crash no meio de um estágio | O último checkpoint commited permanece. CLI em `KeyboardInterrupt` orienta `--resume` (`cli/main.py`, linhas 236–243). SIGKILL no meio do crawl, antes do primeiro `save_checkpoint`, não deixa o que retomar. |
| Crash entre “terminou” e “gravou o resultado” | Janela real. `run()` apaga o checkpoint (`engine.py`, linhas 184–185) **e só então** devolve o resultado. A bridge grava com `store.save` no `else` (`app.py`, linhas 137–139). A CLI grava depois (`cli/main.py`, linhas 254–255). Morrer nesse intervalo apaga o checkpoint e não deixa linha em `scans`. |
| Detector que lança `Exception` | O motor isola o erro (`engine.py`, linhas 223–226) e **mesmo assim** acrescenta o nome em `completed_detectors` (linhas 227–230). No resume esse detector é pulado (linhas 219–221). `KeyboardInterrupt` não cai nesse `except` (é `BaseException`); o teste `test_interrupted_scan_resumes_from_checkpoint` (`tests/integration/test_engine_e2e.py`, linhas 152–198) cobre só esse caso. |
| Contrato do scan no resume da API | `ScanRequest(target=checkpoint.target, confirmed=True)` (`app.py`, linha 241). Perfil volta a `safe`, tipo a `web`, `auth` a `None`, `rate_limit_check` a `False` (defaults em `app.py`, linhas 46–49). O checkpoint não guarda perfil, tipo, auth, rate limit, concorrência nem escopo (`state.py`, linhas 59–71). `requests_made` existe no modelo e nunca é escrito nem lido pelo motor. |
| Lease / heartbeat | Ausente. Dois processos (CLI `--resume` e `POST /resume`, ou duas bridges no mesmo arquivo) podem retomar o mesmo `scan_id`. |
| Limpeza de jobs | O `dict` não remove jobs terminados. O buffer corta em 500 eventos **pelo início da lista** (`app.py`, linhas 39 e 84–85) enquanto o SSE usa índice (`app.py`, linhas 271–276): cortar o prefixo desloca o cursor. |
| SSE e crash de notificação | `publish` notifica depois de anexar o evento, mas o gerador SSE checa o buffer **fora** do `Condition` e só então espera (`app.py`, linhas 270–281). Uma notificação entre a checagem e o `wait()` se perde. A UI mitiga com poll de 1,2 s (`ScanDetail.tsx`, linhas 246–264). |
| Transação resultado+checkpoint | `save`, `save_checkpoint` e `delete_checkpoint` dão `commit` cada um. Não há transação única de “resultado gravado e checkpoint removido”. |

Recuperação que funciona hoje: se o processo morre **depois** de um `save_checkpoint` e **antes** de `delete_checkpoint`, `GET /checkpoints` lista a linha e a UI/CLI conseguem retomar o estágio. Isso é resume de scan, não um job durável com retry e idempotência.

### Workers, filas, webhooks, Telegram, admin, integrações

- Workers: a thread do Uvicorn mais tasks asyncio. O texto “worker threads” em `database.py` (linhas 107–109) e no CHANGELOG descreve esse compartilhamento do SQLite, não um pool de jobs.
- Filas: `deque` do crawler (`crawler.py`, linha 94). Nada externo.
- Webhooks, Telegram, bot, Mini App: nenhuma ocorrência funcional. A busca no código não acha clientes desses serviços.
- Painel admin: a UI desktop é o único painel, sem papéis.
- Integrações externas de produto (Jira, Slack, GitHub App, DefectDojo): só no roadmap (`ROADMAP.md`, linhas 68–74). CI usa Actions, Dependabot e gitleaks.
- IA: `.env.example` (linhas 11–22) documenta `ISAHAT_AI_PROVIDER`, `ISAHAT_OLLAMA_HOST`, `ISAHAT_AI_MODEL`, `ISAHAT_AI_API_KEY`. Nenhum módulo lê essas variáveis. Fase 4 no roadmap está por fazer (`ROADMAP.md`, linhas 60–66).

### Código financeiro

Não há cobrança, saldo, pedido, assinatura, Stripe, PIX ou ledger. A única string relacionada é o exemplo de exclusão de path `/payments/*` em `README.md` (linha 124) e `examples/isahat.yml` (linha 32). Seção 3 fecha isso.

### Storage, cache, cron

- Storage de achados: SQLite local. Relatórios são texto gerado na hora (`isahat.reporting`), não objetos em S3/disco obrigatório. A CLI pode escrever arquivo com `-o` (`cli/main.py`, linhas 83–100).
- Cache de aplicação: só o buffer de eventos em memória e o rate limiter por host (`http.py`, linhas 51–73).
- Cron da aplicação: nenhum. O único agendamento é o workflow `.github/workflows/security.yml` (linhas 8–9), segunda 06:00 UTC.

### Deploy e CI/CD

- Docker: `Dockerfile` (Python 3.12-slim, usuário `isahat` uid 10001, `ISAHAT_HOME=/data`, `ENTRYPOINT ["isahat"]`). `docker-compose.yml` monta `./.isahat:/data` e o comando padrão é `--help`.
- Não há manifesto Kubernetes, systemd ou publicador PyPI no CI. `docs/INSTALLATION.md` cita PyPI como planejado (o README aponta para esse doc).
- CI (`.github/workflows/ci.yml`): em push/PR para `main`.
  - `quality`: ruff, mypy, pytest com coverage XML em Python 3.11 e 3.12.
  - `desktop`: `npm install`, `npm run typecheck`, `npm run build` (Node 20).
  - `build`: wheel e sdist.
  - `docker`: `docker build` e `docker run ... version`.
- Security workflow (`.github/workflows/security.yml`): `pip-audit --strict || true` (não bloqueia, linha 33), CycloneDX `|| true` (linha 36), gitleaks com `fetch-depth: 0`.
- Dependabot semanal para pip, npm e GitHub Actions (`.github/dependabot.yml`).
- Empacotamento Tauri: `tauri.conf.json` lista ícones que não estão no repo. `apps/desktop/src-tauri/icons/` só tem `README.md`. `npm run tauri build` não foi executado e não tem os arquivos que o config exige (linhas 31–37 de `tauri.conf.json`).

### Variáveis de ambiente e segredos

Lidas pelo código:

| Nome | Onde |
| --- | --- |
| `ISAHAT_HOME` | `src/isahat/storage/database.py`, linhas 73–76. Também no Compose (`docker-compose.yml`, linha 12) e na imagem (`Dockerfile`, linha 10). |
| `NO_COLOR` | `src/isahat/cli/console.py`, linha 36. Qualquer valor não vazio desliga cor. |

Documentadas em `.env.example` e **não lidas** por código Python/TS: `ISAHAT_AI_PROVIDER`, `ISAHAT_OLLAMA_HOST`, `ISAHAT_AI_MODEL`, `ISAHAT_AI_API_KEY`.

`.gitignore` ignora `.env` e libera `.env.example` (linhas 36–38). `examples/auth.example.json` tem os literais `REPLACE_WITH_YOUR_TOKEN` e `REPLACE_WITH_YOUR_SESSION_COOKIE`, não credenciais reais. Esta auditoria não imprimiu valores de segredo e não rodou gitleaks localmente. O workflow de gitleaks existe; o resultado dele neste clone não foi consultado.

Mascaramento de evidência: `src/isahat/core/sanitize.py` (Bearer, JWT, `AKIA…`, pares password/token/api_key, headers `authorization`/`cookie`/`set-cookie` e afins). Vários detectores chamam `mask_value` ou `format_headers`; outros guardam trecho cru truncado (ver seção 4).

### Observabilidade

Log do Uvicorn em `warning` (`cli/main.py`, linha 474). Progresso de scan vai para o callback (stdout Rich se `--verbose`, ou eventos SSE). Não há OpenTelemetry, métricas, request id, log estruturado nem audit log de quem confirmou um scan. `doctor` (`cli/main.py`, linhas 397–440) checa httpx, detectores, escrita do SQLite e presença de `isahat.yml`.

### Testes existentes

Ver seção 6. Há unidade offline e uma integração que sobe o lab em `127.0.0.1` numa porta efêmera (`tests/integration/test_engine_e2e.py`). Não há testes de UI (Playwright/Vitest); o roadmap marca isso como pendente (`ROADMAP.md`, linha 58; `apps/desktop/README.md`, linhas 66–72).

### Histórico git (todos os commits; são 11, menos de 30)

| Commit | Data | Assunto |
| --- | --- | --- |
| `1003d80` | 2026-08-05 | feat: initial IsaHat foundation (Phase 1) |
| `14dfa6f` | 2026-08-05 | feat(scanner): detectores de parâmetro e relatórios SARIF/CSV (Phase 2) |
| `402b74e` | 2026-08-05 | feat(scanner): scans autenticados, path traversal, HTML (Phase 2) |
| `9b5e348` | 2026-08-05 | feat(scanner): descoberta de API e detectores de API (Phase 2) |
| `6756b97` | 2026-08-05 | feat(scanner): rate-limit opt-in e resume (Phase 2) |
| `17a5525` | 2026-08-05 | feat(phase3): bridge local, revisão de achados, shell desktop |
| `c56773d` | 2026-08-05 | chore: URLs apontando para `isabellahat` (nome antigo) |
| `2fed0cb` | 2026-08-05 | docs: CLI fora do venv |
| `10e08c0` | 2026-08-05 | fix(desktop): retry do health da bridge |
| `c7af6d4` | 2026-08-06 | chore: rename do repo para `aislamsilvalol-ctrl/isahat` |
| `b046c53` | 2026-08-06 | feat(desktop): redesign, remediação, i18n PT/EN |
| `1386597` | 2026-08-06 | feat(desktop): resume na UI e tema |
| `ad65241` | 2026-09-03 | security: remove `security@isahat.dev`, adiciona Dependabot (#1) |

Não há commit posterior a `1386597` que introduza fila durável ou modo hybrid. O resume e a bridge entram em `6756b97` e `17a5525`.

### Mapa de módulos e dependências

```
apps/desktop (React) --HTTP/SSE--> isahat.api (FastAPI)
isahat.cli (Typer) --chamada direta--> isahat.core.engine
isahat.api --chamada direta--> isahat.core.engine
isahat.core.engine --> scope, http, crawler, tech, api, injection, detectors, risk, state
isahat.core.http --> scope
isahat.cli / isahat.api --> isahat.storage.ScanStore --> sqlite3
isahat.cli / isahat.api --> isahat.reporting (json, markdown, html, sarif, csv, compare)
apps/desktop/src-tauri --> só webview + CSP; não chama o motor
```

Contrato interno estável pretendido: modelos em `src/isahat/core/models.py` (`ScanResult`, `Finding`, `Severity`, `Confidence`, `FindingState`). Fingerprint do achado: SHA-256 truncado, prefixo `ISA-` (`models.py`, linhas 116–123).

---

## 2. Classificação das funcionalidades

| Funcionalidade | Classe | Evidência |
| --- | --- | --- |
| CLI `scan` com perfil safe, crawl, detectores, relatório e `--fail-on` | FUNCIONA | `cli/main.py` `scan`; testes e2e em `tests/integration/test_engine_e2e.py` |
| Escopo por host e path (deny-by-default no pedido inicial) | FUNCIONA | `src/isahat/core/scope.py`; `tests/unit/test_scope.py` |
| Confirmação interativa na CLI (`--yes`, recusa sem TTY) | FUNCIONA | `cli/main.py`, linhas 69–80 e 182–185 |
| Confirmação no motor e na bridge | RISCO | Flag ignorada pelo motor; bridge aceita `confirmed: true` (`api/app.py`, linhas 113–115 e 147–156) |
| Detectores padrão (headers, cookies, arquivos sensíveis, CORS, open redirect, XSS refletido, SQLi por erro, path traversal, GraphQL, dados sensíveis) | FUNCIONA | `detectors/__init__.py`, linhas 48–59; testes em `tests/unit/test_detectors.py` e `test_detectors_phase2.py` |
| Rate-limit check opt-in, cap 30, para no 429, só GET | FUNCIONA | `detectors/rate_limiting.py`, linhas 9–15 e 52–68; `tests/unit/test_resume_ratelimit.py` |
| Scans autenticados pela CLI | FUNCIONA | `core/auth.py`; `test_authenticated_client_attaches_cookies` |
| Descoberta OpenAPI/GraphQL dentro do mesmo scan | FUNCIONA | `core/api.py`; `engine.py`, linhas 147–160 |
| Modo hybrid nomeado | QUEBRADO | Não há implementação. O pipeline único sempre faz crawl e API. |
| Seletor web vs api e safe vs standard | PARCIAL | Só rótulo. `scan_type` e `profile` não ramificam o motor. |
| Relatórios JSON, Markdown, HTML, SARIF, CSV e compare na lib/CLI | FUNCIONA | `src/isahat/reporting/`; `tests/unit/test_reporting_storage.py` |
| HTML com escape e sem script | FUNCIONA | `reporting/html_report.py`, linhas 1–7 e 75–117; teste `test_html_report_escapes_evidence_payloads` |
| SQLite histórico, upsert, anotações por fingerprint | FUNCIONA | `storage/database.py`; anotações globais são de propósito (`ROADMAP.md`, linhas 49–51) e também um efeito colateral (seção 4) |
| Checkpoint + `--resume` na CLI quando o processo morre entre estágios | PARCIAL | `engine.py` + `test_interrupted_scan_resumes_from_checkpoint`. Falha de detector e a janela pós-`delete_checkpoint` ficam de fora. |
| Jobs da bridge (fila, retry, idempotência, sobreviver a crash) | RISCO | `api/app.py`, classe `_ScanJob` e dict `jobs`. Ver seção 1. |
| Resume pela API e pelo dashboard | PARCIAL | `POST /scans/{id}/resume` e `Dashboard.tsx`, linhas 98–105. Perde auth, perfil, tipo e rate-limit check. |
| UI desktop: dashboard, form, detalhe, filtros, revisão, export | PARCIAL | Telas em `apps/desktop/src/screens/`. Typecheck passa. Sem teste de UI. Sem auth. |
| Comparação na UI | PARCIAL | A API devolve `markdown` (`app.py`, linha 333). `Compare.tsx` (linhas 80–112) mostra contagens e não renderiza esse markdown. |
| Health da bridge com retry na UI | FUNCIONA | `App.tsx`, linhas 14–29 |
| `plugins install` | LEGADO | Mensagem de “não disponível” e exit 2 (`cli/main.py`, linhas 385–394) |
| Variáveis de IA e `.env.example` | LEGADO | Documentadas, não lidas |
| `labs/mock_apis` | LEGADO | Citado em `labs/README.md`, diretório ausente |
| Empacotamento nativo assinado | QUEBRADO | Ícones ausentes; CI não roda `tauri build` (`ci.yml` só faz o bundle Vite) |
| `pip-audit` no CI | RISCO | `|| true` em `security.yml`, linha 33, não falha o job |
| Docker `isahat version` | FUNCIONA no workflow | `ci.yml`, linhas 93–102. Não reexecutado nesta auditoria. |
| Threat model T1 (“scope em todo request”) | PARCIAL | Vale para a URL pedida. Redirect seguido pelo httpx não repassa no `Scope` (`http.py`, linhas 138–149). |

---

## 3. Dinheiro

O IsaHat não manipula dinheiro. Não há `float` de saldo, atualização de saldo, idempotência de pagamento, webhook financeiro, conciliação ou corrida de débito/crédito.

A string `/payments/*` é um exemplo de path fora de escopo (`examples/isahat.yml`, linha 32; `README.md`, linha 124).

---

## 4. Segurança

O produto **varre sistemas**. O risco de abuso é o de um agente de scan local sem autenticação, com confirmação forjável e com um furo de escopo em redirect.

### Salvaguardas de autorização e consentimento que existem

- Host do alvo entra no allowlist; outros hosts falham em `Scope.allows` / `Scope.require` (`scope.py`, linhas 37–83). Testes em `tests/unit/test_scope.py`.
- Scheme só `http`/`https` (`scope.py`, linhas 71–74).
- Exclude ganha de include (`scope.py`, linhas 62–69).
- CLI: banner + `typer.confirm` default `False`; sem TTY, recusa se não houver `--yes` (`cli/main.py`, linhas 69–80).
- Métodos fora de GET/HEAD/OPTIONS levantam `PermissionError` salvo `destructive_tests` (`http.py`, linhas 26–27 e 115–120). A bridge não expõe esse flag no `ScanRequest`; um `isahat.yml` com `destructive_tests: true` vale para a bridge, porque ela faz `model_copy` do config carregado (`app.py`, linhas 107–112).
- Rate limit por host, default 3 req/s (`config.py`, linha 53; `http.py`, `_HostRateLimiter`).
- Caps: `max_pages` 100, `max_depth` 3 (`config.py`, linhas 36–37); pontos de injeção têm teto nos detectores (ex.: `_MAX_POINTS = 20` em `sqli_error.py`, linha 17).
- User-Agent identificável (`http.py`, linha 24).
- Rate-limit check desligado por padrão, burst com teto 30, no máximo 3 endpoints, para no HTTP 429, só GET (`rate_limiting.py`, linhas 26–31 e 52–68).
- Lab vulnerável documentado como local-only (`labs/README.md`, linhas 5–7).

### O que não segura o abuso

1. **A UI e a bridge não autenticam o operador.** Qualquer processo local, e qualquer página servida em `localhost` / `127.0.0.1` (CORS libera a origem e `allow_headers=*`, `app.py` linhas 100–105), pode `POST /scans` com `confirmed: true` e varrer a URL que quiser. O allowlist de host é derivado **dessa URL** (`scope.py`, linhas 37–45). Não há registro de quem confirmou, papel, ou artefato de autorização.
2. **`--host` diferente de `127.0.0.1` sobe o mesmo API na rede** (`cli/main.py`, linhas 469–473). Aí o IsaHat vira um scanner remoto sem credencial. O aviso é só texto no terminal.
3. **Resume não reconfirma** (`app.py`, linhas 238–242) e ainda dispara o scan de novo contra `checkpoint.target`.
4. **Redirect sai do escopo.** `SafeHttpClient.request` chama `scope.require` na URL inicial e depois `httpx` com `follow_redirects` default `True` (`http.py`, linhas 85–86, 98–100, 138–149; default de config em `config.py`, linha 35). O httpx segue o `Location` sem nova consulta ao `Scope`. Um alvo autorizado que redirecione faz o IsaHat pedir outro host (incluindo endereço interno). O crawler só filtra links **depois** da resposta (`crawler.py`, linhas 106–107 e 142–146); o request fora de escopo já aconteceu. O detector de open redirect passa `follow_redirects=False` de propósito (`docs` e `http.py`, linhas 133–135); o crawl e o restante dos GETs não.
5. **Segredos no checkpoint.** `ResponseSnapshot` guarda `headers`, `text` e `request_headers` crus (`state.py`, linhas 24–45). O motor serializa as respostas do crawl inteiras (`engine.py`, linhas 189–198). `request_headers` vem de `response.request.headers` (`http.py`, linhas 152–160), onde o httpx coloca `Authorization` e `Cookie` do `AuthConfig`. `save_checkpoint` grava esse JSON no SQLite (`database.py`, linhas 231–249) sem `mask_headers`. Isso contradiz `auth.py` (linhas 4–5), `DEVELOPMENT.md` (linha 58, “Secrets never persisted”) e o threat model T4 (`THREAT-MODEL.md`, linha 38), que marca o mascaramento como implementado.
6. **Evidência incompleta.** `sensitive_files.py` e `sensitive_data.py` chamam `mask_value`. `sqli_error.py` (linha 79), `reflected_xss.py` (linha 61) e `path_traversal.py` (linha 89) truncam o corpo sem mascarar. Headers de resposta no checkpoint também ficam crus, inclusive `Set-Cookie`.
7. **Permissão do arquivo.** `default_db_path` cria o diretório com o umask do processo (`database.py`, linhas 74–76). T10 do threat model está “Partial” (`THREAT-MODEL.md`, linha 44) e continua parcial: não há `0o700`.
8. **`/docs` aberto** no mesmo bind (`cli/main.py`, linha 467).
9. **Erros internos voltam ao cliente** como `str(exc)` (`app.py`, linhas 135–136) e a UI mostra `status.detail` (`ScanDetail.tsx`, linhas 254 e 354–358).
10. **Anotação é global por fingerprint**, não por scan (`database.py`, linhas 287–330). O endpoint confere se o achado está naquele scan (linhas 306–309) e grava só `finding_id`. Outro scan com o mesmo fingerprint herda o estado. É o desenho do roadmap, e também permite que um cliente local altere a revisão de todos os scans que compartilham o id `ISA-…`.
11. **Sem rate limit na API.** O limite é só de saída, por host de alvo. Um cliente pode abrir muitos scans.
12. **SSRF de produto.** O scanner é, por função, um cliente HTTP controlado pelo caller. Sem auth na bridge, o caller pode ser outro programa. Não há bloqueio de link-local, metadata ou IP privado além da regra de host literal.
13. **Injeção de comando.** Não há `subprocess`, `os.system` ou `shell=True` em `src/`.
14. **SQL injection no store.** As queries usam `?` (`database.py`). O payload é JSON. Não há SQL dinâmico com entrada do alvo.
15. **XSS na UI.** As telas imprimem texto React, sem `dangerouslySetInnerHTML`. O relatório HTML escapa (`html_report.py`). Referências de achados são listas escritas nos detectores, não URLs do alvo.
16. **Upload / path traversal no app.** Não há endpoint de upload. O id no `Content-Disposition` do relatório é o `scan_id` cru (`app.py`, linhas 295–298). Ids novos são hex de 12 caracteres; um id vindo de `--resume` / checkpoint é string livre e entra no header.
17. **Mass assignment.** `ScanRequest`, `AnnotationRequest` e `AuthConfig` são modelos Pydantic fechados nos campos declarados. Não há objeto ORM que copie o body inteiro para colunas.
18. **IDOR clássico.** Sem autenticação, todo scan local é legível por `GET /scans` e `GET /scans/{id}`. O id de 12 hex não funciona como segredo.
19. **Segredos hardcoded.** Não foram encontrados tokens reais no tree. O exemplo de auth é placeholder (`examples/auth.example.json`). A chave de IA no exemplo está vazia e o código não a usa.
20. **ReDoS / resposta hostil.** T5 está “Partial” no threat model (`THREAT-MODEL.md`, linha 39). O crawler usa regex em HTML (`crawler.py`, linhas 20–30) sobre `response.text` sem teto de tamanho antes de parsear. O checkpoint persiste o corpo inteiro.

Detectores ativos (CORS, redirect, XSS refletido, SQLi por mensagem de erro, traversal, arquivos sensíveis, introspecção GraphQL) fazem GET dentro do escopo da URL que eles mesmos montam. A descrição de cada um está no docstring do arquivo em `src/isahat/core/detectors/`. Esta auditoria não reproduz payloads.

---

## 5. TODO, FIXME, mock, temporário, placeholder, fake, hardcoded

Não há comentários `TODO` / `FIXME` / `HACK` / `XXX` em `src/` ou `apps/desktop/src/`. O que existe de provisório:

| Onde | O que é |
| --- | --- |
| `src/isahat/cli/main.py`, linhas 385–394 | `plugins install` responde que a instalação não existe e cita a Fase 5. |
| `.env.example`, linhas 11–22 | Bloco “Phase 4” de IA, desligado e não ligado a código. |
| `labs/README.md`, linhas 23–27 | `mock_apis/` e `sample_targets/` anunciados e ausentes. |
| `apps/desktop/src-tauri/icons/README.md` | Ícones ainda por gerar; o `tauri.conf.json` já aponta para arquivos que não estão no git. |
| `ROADMAP.md` | Fases 2 e 3 com itens ⬜ (SQLi booleano/time-based, PDF, multi-target, binários assinados, testes de UI). Fases 4 e 5 inteiras por fazer. |
| `examples/auth.example.json` | Placeholders `REPLACE_WITH_YOUR_TOKEN` e `REPLACE_WITH_YOUR_SESSION_COOKIE`. |
| `tests/unit/helpers.py`, linhas 1–4 | Cliente HTTP fake para teste offline. Não entra no produto. |
| `labs/vulnerable_apps/simple_app/app.py`, linha 137 | Comentário de alvo de laboratório (“fake /etc/passwd”). É o app vulnerável de teste, não o motor. |
| `NewScan.tsx`, linhas 65 e 88 | Atributos HTML `placeholder` de formulário (i18n), não dados falsos de negócio. |
| `.github/workflows/security.yml`, linhas 33 e 36 | `\|\| true` deixa audit e SBOM falharem em silêncio durante o alpha. |
| `src/isahat/core/state.py`, linha 71 | Campo `requests_made` no checkpoint, nunca preenchido pelo motor. |
| Perfil `standard` e tipo `api` | Valores aceitos pela UI e pela CLI sem efeito no pipeline (seção 1). |

`docs/adr/template.md` contém o texto de status “Proposed | Accepted | Superseded”, que é molde de ADR, não decisão pendente.

---

## 6. Testes

### Como rodar

Documentado em `docs/DEVELOPMENT.md` (linhas 18–26) e `scripts/dev.sh`:

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
ruff check src tests
mypy
pytest -q
```

UI (`apps/desktop`, também no job `desktop` do CI):

```bash
npm install
npm run typecheck
npm run build
```

Lab: `python labs/vulnerable_apps/simple_app/app.py --port 8123` e `isahat scan http://127.0.0.1:8123 --yes --verbose` (`scripts/dev.sh`, funções `lab` e `scan_lab`).

Pytest está com `asyncio_mode = auto` e `testpaths = ["tests"]` (`pyproject.toml`, linhas 66–69). Mypy estrito em `src/isahat` (linhas 86–91). Ruff em `src` e `tests` (linhas 71–84).

Cobertura por arquivo de teste (nomes reais):

- `tests/unit/test_scope.py`, `test_config.py`, `test_auth.py`, `test_sanitize.py`, `test_models_risk.py`
- `tests/unit/test_detectors.py`, `test_detectors_phase2.py`, `test_api_discovery.py`, `test_crawler_injection.py`
- `tests/unit/test_resume_ratelimit.py` (checkpoint roundtrip e o detector de rate limit)
- `tests/unit/test_reporting_storage.py`
- `tests/unit/test_api_bridge.py` (fluxo HTTP, SSE, confirmação obrigatória, resume)
- `tests/integration/test_engine_e2e.py` (lab real em loopback, inclusive resume após `KeyboardInterrupt`)

Não há teste que mate o processo entre `delete_checkpoint` e `save`, que falhe um detector com `Exception` e espere reexecução, que confira auth no resume da API, que impeça redirect fora de escopo, ou que exija credencial na bridge.

### O que foi executado nesta auditoria

Ambiente: Python 3.12.3, Node 22.14.0, npm 10.9.7. Pacotes em venv `/tmp/isahat-venv` (`pip install -e ".[dev]"`). UI com `npm install` em `apps/desktop`.

| Comando | Resultado |
| --- | --- |
| `ruff check src tests` | Exit 0. “All checks passed!” |
| `mypy` | Exit 0. “Success: no issues found in 44 source files” |
| `pytest -q` | Exit 0. 100 testes (72 + 28 no progresso). 1 aviso: `StarletteDeprecationWarning` em `fastapi/testclient.py` (“Using httpx with starlette.testclient is deprecated; install httpx2”). |
| `npm run typecheck` em `apps/desktop` | Exit 0 (`tsc --noEmit`). |
| `npm run build` em `apps/desktop` | Exit 0. Vite 5.4.21 gerou `dist/` (gitignored): CSS ~10 kB, JS ~192 kB. |
| `docker build` / `docker run ... version` | Não executado aqui. O workflow `ci.yml` faz isso em `ubuntu-latest`. |
| `npm run tauri build` | Não executado. Faltam os ícones listados em `tauri.conf.json`. Rust não foi usado. |
| `pip-audit`, gitleaks | Não executados localmente. No CI, `pip-audit` está com `\|\| true`. |

Os testes verdes não cobrem os furos das seções 1 e 4. O teste de resume da bridge trata 202 e 409 como ambos aceitáveis (`test_api_bridge.py`, linha 162), então a corrida de resume não falha o CI.

---

## 7. UX e mobile (a partir do código)

A UI é um shell desktop. `tauri.conf.json` (linhas 16–19) fixa mínimo 960×640. `styles.css` não tem `@media`. O layout é `.shell { display: flex }` com sidebar fixa de 238px (`.sidebar`, linhas 60–71) e `.content` com padding 34px 40px (`styles.css`, linhas 184–188).

Consequências visíveis no código:

- Em largura menor que ~960px a sidebar não colapsa; a tabela do dashboard (cinco colunas, `Dashboard.tsx`, linhas 167–206) não tem `overflow-x` no `table` (`styles.css`, linhas 301–304).
- Ações do achado são uma fileira horizontal (`.finding-actions`, `styles.css`, linhas 616–622; quatro botões em `ScanDetail.tsx`, linhas 186–214).
- Scan em andamento que ainda não foi gravado entra na lista com `started_at: ""` (`app.py`, linhas 193–197). O dashboard faz `new Date(row.started_at).toLocaleString()` (`Dashboard.tsx`, linha 182) e mostra data inválida.
- Abrir `/scans/:id` depois que o processo da bridge morreu: não há job nem linha em `scans`, `GET` responde 404 (`app.py`, linhas 245–259). A tela trata isso como falha (`ScanDetail.tsx`, linhas 293–300) e não oferece o resume que o dashboard mostra para o checkpoint.
- O form de novo scan exige `type="url"` (`NewScan.tsx`, linha 69). Alvos sem scheme falham no browser antes de chegar na API, enquanto a CLI aceita a string e o escopo explica o erro (`scope.py`, linhas 46–48).
- Auth do alvo é um textarea de JSON livre (`NewScan.tsx`, linhas 85–91), sem mostrar que o valor vai no corpo HTTP para a bridge e pode parar no SQLite via checkpoint.
- `Compare.tsx` pede dois scans e ignora o markdown que a API já calculou (linhas 80–112 e `client.ts`, linha 108).
- Relatórios na UI são links crus para a bridge (`ScanDetail.tsx`, linhas 340–349; `client.ts`, linhas 189–190), sem header. Funciona enquanto a bridge não tem auth; quebra no dia em que a auth existir, se o `<a href>` continuar sem credencial.
- i18n PT/EN persiste em `localStorage` (`i18n/index.tsx`, linhas 8–18). Textos de severidade na tabela continuam as chaves em inglês (`critical`, `high`, …) porque `SeverityBadge` imprime `value` (`Dashboard.tsx`, linhas 16–18).
- Não há estado vazio de “bridge no ar, porém scan 404 porque ainda não persistiu” distinto de “bridge caída”. O banner de bridge (`App.tsx`, linhas 10–37) só olha `/health`.

Não houve passagem em browser nesta auditoria: a mudança deste PR é só este arquivo. O que está acima é leitura de layout e de fluxo, não uma sessão clicada.

---

## 8. BACKLOG

Tamanho: P = pequeno (um módulo, testes locais), M = dois ou três módulos, G = atravessa motor, bridge e UI.

### P0

1. **Bridge sem autenticação e confirmação forjável**
   - Evidência: `src/isahat/api/app.py`, linhas 100–105 e 147–162; `cli/main.py`, linhas 444–473; `NewScan.tsx`, linhas 41–48.
   - Risco: qualquer cliente que alcance a porta dispara scans contra alvos arbitrários. Com `--host` não loopback, o alcance é a rede. Página em `localhost` passa no CORS.
   - Abordagem: segredo local de 0600 em `$ISAHAT_HOME`, obrigatório em toda rota exceto `GET /health`; a UI legítima envia o header; recusar bind fora de loopback sem esse segredo. Não reescrever o motor.
   - Tamanho: M.

2. **Redirect seguido ignora o escopo**
   - Evidência: `src/isahat/core/http.py`, linhas 138–149; default `follow_redirects=True` em `config.py`, linha 35, e no cliente, linhas 85–100.
   - Risco: um 30x no alvo autorizado gera request a outro host. A fronteira que o threat model chama de implementada (T1) não cobre o hop.
   - Abordagem: desligar o follow automático do httpx e revalidar cada `Location` com `Scope.require` antes do próximo GET, com teto de hops. Manter `follow_redirects=False` nos detectores que precisam ver o `Location`.
   - Tamanho: P.

3. **Checkpoint grava segredo e corpo cru**
   - Evidência: `state.py`, linhas 24–45; `engine.py`, linhas 189–198; `http.py`, linhas 152–160; `database.py`, linhas 231–249.
   - Risco: `Authorization`, `Cookie` e `Set-Cookie` ficam no SQLite do usuário, junto com corpos ilimitados.
   - Abordagem: passar headers e texto por `mask_headers` / `mask_value` e `truncate` antes de `ResponseSnapshot`. Não mudar o contrato do `AuthConfig` em memória.
   - Tamanho: P.

4. **Conclusão do scan não é atômica; detector com erro fica “concluído”**
   - Evidência: `engine.py`, linhas 184–186 e 223–230; `app.py`, linhas 137–139; `cli/main.py`, linhas 254–255.
   - Risco: crash no intervalo perde o resultado e o checkpoint. Resume pula detector que falhou com `Exception` e não repete o teste.
   - Abordagem: uma transação SQLite que grava `scans` e apaga `checkpoints`; só então retornar. Só acrescentar `completed_detectors` quando `run()` não lança. Detalhe na seção 9.
   - Tamanho: P.

### P1

5. **Resume da API descarta o contrato do scan**
   - Evidência: `app.py`, linha 241; `state.py`, linhas 59–71. Defaults em `ScanRequest` (`app.py`, linhas 46–49).
   - Risco: retomar pela UI varre de novo sem cookie/header, sem o rate-limit check, e com perfil/tipo default. O operador acha que continuou o mesmo audit.
   - Abordagem: persistir no checkpoint perfil, tipo, flags de safety e um indicador de auth (o material mascarado ou um ponteiro que não regrave o segredo em claro). Recusar resume se o auth original não puder ser reanexado. Reconfirmar escopo na UI.
   - Tamanho: M.

6. **Corrida e falta de lease no resume**
   - Evidência: `app.py`, linhas 226–242; teste em `test_api_bridge.py`, linhas 161–162.
   - Risco: dois resumes do mesmo id rodam juntos e escrevem o mesmo checkpoint.
   - Abordagem: `BEGIN IMMEDIATE` e uma coluna `lease_until` no checkpoint; 409 se o lease estiver vivo. Apertar o teste para exigir 409.
   - Tamanho: P.

7. **Job em memória: SSE perde evento, buffer desloca índice, dict cresce**
   - Evidência: `app.py`, linhas 82–87 e 264–283.
   - Risco: a tela ao vivo para ou repete estágio; `isahat serve` longo segura todos os scans na RAM.
   - Abordagem: esperar o `Condition` com o predicado dentro do lock; cortar eventos com cursor monotônico, não com `del` no prefixo; descartar jobs terminados depois que o resultado está em `scans`.
   - Tamanho: P.

8. **`pip-audit` não falha o CI**
   - Evidência: `.github/workflows/security.yml`, linha 33.
   - Risco: CVE conhecido em dependência entra na `main`.
   - Abordagem: tirar o `|| true` quando a árvore estiver limpa, ou falhar só em severidade alta.
   - Tamanho: P.

### P2

9. **Perfil e tipo de scan não mudam o motor**
   - Evidência: ausência de ramo em `src/`; seletores em `NewScan.tsx`, linhas 73–81; `--type` em `cli/main.py`, linha 107.
   - Risco: o operador escolhe “api” ou “standard” e recebe o mesmo scan “safe/web”, com outro rótulo no relatório.
   - Abordagem: ou passar a ramificar de verdade (lista de detectores por tipo), ou remover as opções até existirem. Não inventar um modo hybrid nesta correção; o pipeline único já faz as duas superfícies.
   - Tamanho: P para esconder o seletor; M para modos reais.

10. **UI do scan em voo e pós-crash**
    - Evidência: `app.py`, linhas 187–203; `Dashboard.tsx`, linha 182; `ScanDetail.tsx`, linhas 293–300.
    - Risco: data inválida e 404 onde existe checkpoint retomável.
    - Abordagem: não listar `started_at` vazio; no 404 do detalhe, consultar `/checkpoints` e mostrar resume.
    - Tamanho: P.

11. **Compare na UI ignora o markdown**
    - Evidência: `Compare.tsx`, linhas 80–112; payload em `app.py`, linha 333.
    - Risco: a comparação “o que mudou” fica só em contagem de ids.
    - Abordagem: renderizar o markdown como texto pré-formatado (não como HTML cru).
    - Tamanho: P.

12. **SQLite sem `busy_timeout`, sem WAL, sem `0o700`**
    - Evidência: `database.py`, linhas 70–123. T10 em `THREAT-MODEL.md`, linha 44.
    - Risco: `database is locked` com CLI e bridge no mesmo arquivo; outros usuários locais leem achados e cookies do checkpoint.
    - Abordagem: `chmod` na criação, `busy_timeout`, WAL. Um PR pequeno, separado do mascaramento.
    - Tamanho: P.

13. **Ícones e bundle Tauri**
    - Evidência: `apps/desktop/src-tauri/icons/README.md`; `tauri.conf.json`, linhas 31–37.
    - Risco: `tauri build` quebra; não há binário assinado como o roadmap promete.
    - Abordagem: gerar o set de ícones e um job de CI que compile o shell, sem publicar release ainda.
    - Tamanho: M.

### P3

14. **`plugins install` e diretórios de lab anunciados**
    - Evidência: `cli/main.py`, linhas 385–394; `labs/README.md`, linhas 23–27.
    - Risco: comando e doc apontam para capacidade inexistente.
    - Abordagem: manter o comando retornando uso inválido até a Fase 5; alinhar o README do lab ao que existe (`simple_app` já cobre OpenAPI/GraphQL, segundo o CHANGELOG).
    - Tamanho: P.

15. **Campo morto `requests_made` no checkpoint e variáveis de IA não lidas**
    - Evidência: `state.py`, linha 71; `.env.example`, linhas 11–22.
    - Risco: quem ler o modelo acha que o contador e a IA existem.
    - Abordagem: preencher o contador no checkpoint ou removê-lo do modelo; comentar no exemplo que a Fase 4 ainda não lê as variáveis.
    - Tamanho: P.

16. **Aviso do TestClient / httpx**
    - Evidência: pytest desta auditoria, `StarletteDeprecationWarning` em `fastapi/testclient.py`.
    - Risco: o teste da bridge quebra numa atualização futura de Starlette.
    - Abordagem: acompanhar a recomendação da stack (httpx2 ou TestClient novo) quando for compatível com FastAPI pinada. Não bloquear os P0.
    - Tamanho: P.

---

## 9. Primeira tarefa recomendada

A primeira mudança deve ser a do item P0.4. Ela corrige perda silenciosa de audit e resume que pula teste, num único fluxo que o código já tem, sem desenhar autenticação nem reescrever a bridge. A autenticação da UI (P0.1) é o P0 seguinte e não entra neste corte: a UI hoje não tem como ler um arquivo de token sem um comando Tauri, e misturar os dois aumenta o diff.

### TASK

Gravar o `ScanResult` e apagar o checkpoint na mesma transação SQLite, e só marcar um detector como concluído quando `run()` retorna sem exceção.

### CONTEXT

O resume existe (`6756b97`, `engine.py`, `checkpoints`). Ele sobrevive a Ctrl+C entre estágios. Ele não sobrevive ao intervalo em que o checkpoint some antes do `INSERT` em `scans`, e trata falha de detector como estágio pronto. O teste e2e cobre `KeyboardInterrupt`, que não entra no `except Exception`.

### FILES

- `src/isahat/core/engine.py` (fim de `run`, `_run_detectors`)
- `src/isahat/storage/database.py` (`save`, `delete_checkpoint`)
- `src/isahat/core/state.py` (protocolo `CheckpointStore`, só se precisar de um método novo)
- `src/isahat/cli/main.py` e `src/isahat/api/app.py` (quem chama `store.save` depois do `run`)
- `tests/integration/test_engine_e2e.py`
- `tests/unit/test_resume_ratelimit.py` ou `tests/unit/test_reporting_storage.py`

Não abrir `apps/desktop/` neste corte.

### CURRENT BEHAVIOR

- `ScanEngine.run`, no caminho feliz, chama `delete_checkpoint` e retorna (`engine.py`, linhas 184–187).
- A bridge faz `store.save(result)` só no `else`, depois do `await engine.run()` (`app.py`, linhas 132–139).
- A CLI faz `store.save(result)` depois de `engine.scan()` (`cli/main.py`, linhas 225–255).
- Cada método do store dá `commit` próprio (`database.py`, linhas 174, 250, 264).
- Se o detector levanta `Exception`, o nome entra em `completed_detectors` e o checkpoint é salvo (`engine.py`, linhas 223–230). O resume seguinte emite “skipping” (linhas 219–221).

### REQUIRED BEHAVIOR

- No caminho feliz, com store presente, o processo que morre depois do commit final deixa a linha em `scans` **ou** deixa o checkpoint. Não deixa os dois ausentes.
- `delete_checkpoint` e o `INSERT`/`UPDATE` de `scans` compartilham um `BEGIN` e um `COMMIT`.
- Se esse commit falha, o checkpoint permanece e `run()` propaga o erro. A bridge continua marcando o job como `error`.
- Se um detector levanta `Exception`, o scan segue (isolamento atual), o achado desse detector não é acrescentado, e o nome **não** entra em `completed_detectors`. Um resume posterior executa esse detector de novo.
- Detectores que retornaram normalmente continuam sendo pulados no resume, como hoje.
- `KeyboardInterrupt` continua saindo de `run()` sem gravar `scans` e sem apagar o checkpoint.

### DO NOT BREAK

- `--resume` da CLI e `POST /scans/{id}/resume` para checkpoint válido.
- Upsert de `scans` por id (`test_storage_upsert_is_idempotent`).
- Anotações por fingerprint.
- Scan com `--no-store` (store `None`): não cria checkpoint e não tenta finalizar.
- Isolamento: um detector com erro não aborta os seguintes na mesma execução.
- Caps, escopo e métodos HTTP. Esta tarefa não mexe em redirect, token da bridge nem no seletor web/api.
- O teste `test_interrupted_scan_resumes_from_checkpoint` deve continuar passando, incluindo `requests_made == 0` no resume em que todos os detectores restantes já constam do checkpoint, e checkpoint `None` ao terminar.

### IMPLEMENTATION

1. Em `ScanStore`, extrair o SQL de `save` e de `delete_checkpoint` para um método que, debaixo do mesmo `_lock`, execute os dois statements e dê um único `commit`. Em falha, `rollback`.
2. Estender o protocolo `CheckpointStore` com esse finalize **ou** fazer o motor chamar o método só quando o objeto concreto for `ScanStore`, sem um segundo caminho de persistência. A CLI e a bridge devem usar esse método em vez de `delete` dentro do motor seguido de `save` fora. O motor pode chamar o finalize antes do `return` se o store expuser o método; aí a CLI/bridge não gravam uma segunda vez, ou gravam de novo só porque o upsert é idempotente — escolher um dos dois e não os dois com commits separados.
3. Em `_run_detectors`, mover `completed_detectors.append` para o `else` do `try`, junto com a cópia de `findings` e `save_checkpoint`. O `except` continua só emitindo o erro.
4. Não introduzir fila, Redis, nem reescrita de `ScanEngine`.

### TESTS

- Novo teste de store: `finalize` deixa o scan legível e o checkpoint ausente; uma falha injetada antes do commit (por exemplo, fechar a conexão ou monkeypatch de `commit`) não apaga o checkpoint se o scan ainda não estava visível. Usar `tmp_path`.
- Novo teste de motor: detector que levanta `RuntimeError` no meio da lista; checkpoint contém os anteriores e omite o que falhou; um segundo `ScanEngine` com o mesmo `scan_id` executa o detector que falhou (contar chamadas) e não refaz os que terminaram.
- Rodar o e2e de `KeyboardInterrupt` existente sem alterar a expectativa de “checkpoint removido só depois do sucesso”.
- Comandos: `pytest tests/integration/test_engine_e2e.py tests/unit/test_resume_ratelimit.py tests/unit/test_reporting_storage.py tests/unit/test_api_bridge.py -q`, depois `ruff check src tests` e `mypy`.

### ACCEPTANCE CRITERIA

- Matar o processo não é simulável com precisão no pytest; o teste de uma transação única é o critério automático. Leitura do diff mostra um único `commit` cobrindo insert do resultado e delete do checkpoint.
- Não existe mais caminho em que `delete_checkpoint` rode sem o `save` do mesmo resultado já estar no mesmo commit.
- Um detector que lança `Exception` não aparece em `completed_detectors`.
- `pytest` dos arquivos acima, `ruff` e `mypy` ficam verdes.
- CLI `scan` feliz com store ainda aparece em `isahat list` e o checkpoint some.
- Nenhuma tela, rota ou detector novo. Nenhum payload de teste novo contra alvo que não seja o lab já usado.
