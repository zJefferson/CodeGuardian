# CodeGuardian

Ferramenta para analisar repositórios Git públicos: qualidade de código, verificação de
dependências, checagens automatizadas e geração de relatórios técnicos.

> Status: API REST para análise de repositórios (estrutura, Ruff e pip-audit), com
> execução em segundo plano limitada ao ambiente local. Sem autenticação: não exponha
> publicamente.

## Requisitos

- Python 3.12 ou superior (desenvolvido com Python 3.14)
- Git

## Instalação (Windows / PowerShell)

```powershell
git clone https://github.com/zJefferson/codeguardian.git
cd codeguardian
py -3.14 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
```

Em Linux/macOS, ative o ambiente com `source .venv/bin/activate`.

O `requirements.txt` fixa todas as versões, incluindo as transitivas, para instalações
reproduzíveis. As dependências diretas estão declaradas em `pyproject.toml`.

## Executando a API

Com o ambiente virtual ativado:

```powershell
uvicorn app.main:app --reload
```

- API: <http://127.0.0.1:8000>
- Verificação de saúde: <http://127.0.0.1:8000/health> → `{"status": "ok"}`
- Documentação interativa (Swagger): <http://127.0.0.1:8000/docs>

`--reload` é apenas para desenvolvimento. Por padrão o servidor escuta somente em `127.0.0.1`.
Use um único worker: as análises e seus resultados ficam na memória do processo.

### Endpoints

| Método e rota | Descrição |
|---|---|
| `POST /analyses` | inicia uma análise (`{"repository_url": "https://github.com/..."}`) e responde `202` |
| `GET /analyses/{analysis_id}` | status: `queued`, `running`, `completed` ou `failed` |
| `GET /analyses/{analysis_id}/report` | relatório JSON (`409` enquanto não estiver pronto) |

```powershell
$r = Invoke-RestMethod -Method Post http://127.0.0.1:8000/analyses -ContentType "application/json" -Body '{"repository_url": "https://github.com/psf/requests"}'
Invoke-RestMethod "http://127.0.0.1:8000$($r.status_url)"
Invoke-RestMethod "http://127.0.0.1:8000$($r.report_url)"
```

Códigos HTTP, formato de erros, limites e restrições da execução em segundo plano:
[docs/api.md](docs/api.md).

## Testes e verificações

```powershell
pytest                # testes
pytest -v             # testes com saída detalhada
ruff check .          # lint
ruff format --check . # formatação
pip-audit -r requirements.txt  # vulnerabilidades conhecidas nas dependências
```

## Validação de repositórios

`app/repository_url.py` aceita somente URLs no formato
`https://github.com/<usuário>/<repositório>` (opcionalmente com `.git` ou `/` final).
São rejeitados: outros esquemas e hosts, portas diferentes de 443, credenciais
embutidas, endereços IP, `localhost`, query/fragmento, caminhos codificados ou com
segmentos extras e caracteres não ASCII. As mensagens de erro nunca reproduzem a URL
recebida. Passar na validação não torna o repositório confiável.

## Clonagem controlada

`app/repository_clone.py` clona um repositório já validado em um diretório
temporário exclusivo, removido ao final da análise (inclusive em caso de erro):

```python
from app.repository_clone import cloned_repository
from app.repository_url import parse_github_repository_url

repo = parse_github_repository_url("https://github.com/psf/requests")
with cloned_repository(repo) as path:
    ...  # ler arquivos em `path`; nunca executá-los
```

A clonagem é rasa (`--depth=1`), sem submódulos, sem credenciais, sem as
configurações globais do Git e com limites de tempo, tamanho e saída. Nenhum código
do repositório é executado e nenhuma dependência é instalada. Os controles e os
riscos restantes estão em [docs/clonagem.md](docs/clonagem.md). **A clonagem ainda
não roda isolada; não exponha o serviço publicamente sem os controles descritos lá.**

## Análise estrutural

`app/structure_analyzer.py` examina o diretório clonado usando apenas metadados do
sistema de arquivos (nenhum arquivo é aberto ou executado):

```python
from app.structure_analyzer import analyze_structure

report = analyze_structure(path)  # StructureReport (Pydantic)
report.python_files  # arquivos .py
report.config_files  # pyproject.toml, requirements*.txt, setup.cfg, pytest.ini...
report.relevant_directories  # src/, pacotes, tests/, docs/
report.tests, report.documentation
report.complete, report.limitations
```

Diretórios de dependências, caches e controle de versão (`.git`, `.venv`,
`node_modules`, `__pycache__`, `*.egg-info`...) são ignorados. Links simbólicos e
junções nunca são seguidos. A varredura tem limites de profundidade e de número de
arquivos; quando um limite é atingido, `complete` é `False` e o motivo aparece em
`limitations` (análise incompleta não é o mesmo que ausência de achados).

## Análise estática com Ruff

`app/ruff_analyzer.py` executa `ruff check` sobre o repositório clonado e retorna um
`RuffReport` (Pydantic) com arquivo, linha, coluna, regra, mensagem e sugestão de
correção de cada achado:

```python
from app.ruff_analyzer import RuffSettings, analyze_with_ruff

report = analyze_with_ruff(path)  # regras padrão: E4, E7, E9, F, B, S
report.status  # completed | no_python_files | timeout | output_limit | failed
report.findings  # lista de RuffFinding
```

- O Ruff só lê os arquivos; nada é importado nem executado.
- `--isolated`: a configuração do repositório analisado (`pyproject.toml`, `ruff.toml`)
  é ignorada, pois é controlada por terceiros. As regras são definidas pelo CodeGuardian.
- `--no-cache` e `--no-fix`: nada é gravado no repositório.
- Limites de tempo, de bytes de saída e de número de achados; o subprocesso recebe um
  ambiente mínimo, sem segredos.
- `completed` com `findings` vazio significa "nenhum achado"; `timeout` e
  `output_limit` significam análise incompleta; `failed`, falha da ferramenta.

## Análise de dependências

`app/dependency_audit.py` verifica vulnerabilidades conhecidas com pip-audit nas
dependências declaradas em `requirements*.txt`, `pyproject.toml`, `Pipfile.lock`,
`poetry.lock` e `uv.lock`:

```python
from app.dependency_audit import audit_dependencies

report = audit_dependencies(path)
report.status  # no_vulnerabilities | vulnerabilities_found | source_unavailable | failed ...
report.packages  # pacote, versão, origem e vulnerabilidades (PYSEC/GHSA/CVE)
report.unaudited  # o que não pôde ser verificado e por quê
report.tool_version
```

Nada é instalado: apenas dependências com versão exata são enviadas ao pip-audit,
por meio de um arquivo sanitizado, com `--no-deps --disable-pip`, em um subprocesso
com ambiente mínimo. **A análise depende das dependências declaradas e das
informações disponíveis na fonte de vulnerabilidades**; veja o escopo e os limites
em [docs/dependencias.md](docs/dependencias.md).

## Relatório consolidado

`app/analysis_report.py` executa as etapas (validação, clonagem, estrutura, Ruff e
pip-audit) e consolida os resultados em um `AnalysisReport`:

```python
from pathlib import Path

from app.analysis_report import analyze_repository

report = analyze_repository("https://github.com/psf/requests")
report.overall_status  # no_issues_found | issues_found | nothing_to_analyze | incomplete | failed
report.approved  # True somente se tudo foi verificado por completo e sem achados
report.checks  # status de cada verificação: completed | partial | failed | skipped | not_applicable
report.export_json(Path("relatorio.json"))
```

O relatório contém identificador, URL canônica, data, duração, versões das
ferramentas (CodeGuardian, Python, Git, Ruff, pip-audit), status de cada verificação,
contagem de achados, resultados do Ruff e do pip-audit, avisos e erros.

- **Análises incompletas nunca são aprovadas.** Timeout, falha, fonte de
  vulnerabilidades indisponível, limite atingido ou dependências não auditadas
  resultam em `incomplete`.
- **Nada é presumido.** Etapas que não executaram aparecem como `skipped`; contagens
  sem resultado são `null`, não zero.
- **Sem conteúdo sensível.** Sem credenciais (URL canônica), sem saídas brutas das
  ferramentas, sem trechos de código e sem caminhos do servidor; da estrutura entra
  apenas um resumo.

## Pontuação de qualidade

Cada relatório traz `quality`: uma pontuação de 0 a 100 calculada de forma determinística
(sem IA) a partir dos resultados estruturados, com os fatores que a influenciaram.

| Dimensão | Peso | Fonte |
|---|---|---|
| Análise estática | 40 | Ruff (achados ponderados por categoria e por arquivo) |
| Dependências | 30 | pip-audit (pacotes vulneráveis) |
| Práticas do projeto | 20 | testes, README, dependências declaradas e fixadas, docs |
| Testes executados | 10 | pytest isolado, quando habilitado |

Verificações que falharam ou não foram executadas ficam **indisponíveis** (nunca valem 0
ou 100) e, nesse caso, a nota geral também fica indisponível. **A pontuação é um
indicador relativo das verificações automatizadas, não uma medida absoluta da qualidade
do software.** Fórmulas, pesos e exemplos: [docs/pontuacao.md](docs/pontuacao.md).

## Execução isolada de testes (opcional)

`app/test_runner.py` pode executar os testes do repositório analisado com pytest,
**somente** dentro de um container Docker descartável: sem rede, usuário sem
privilégios, sistema de arquivos somente leitura, limites de CPU, memória, processos e
tempo, sem credenciais do host e sem instalar dependências. Desabilitada por padrão:

```powershell
docker build -f docker/pytest-runner.Dockerfile -t codeguardian/pytest-runner:0.1.0 .
$env:CODEGUARDIAN_TEST_EXECUTION = "enabled"
$env:CODEGUARDIAN_TEST_IMAGE = "codeguardian/pytest-runner:0.1.0"
uvicorn app.main:app
```

Sem Docker disponível, a etapa é marcada como ignorada; nunca há execução fora do
container. Arquitetura, controles, resultados e riscos: [docs/testes-isolados.md](docs/testes-isolados.md).

## Estrutura

```
app/      código da aplicação
docker/   imagem do ambiente isolado de testes
docs/     documentação técnica
tests/    testes automatizados
```
