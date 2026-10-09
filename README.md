# CodeGuardian

Ferramenta para analisar repositórios Git públicos: qualidade de código, verificação de
dependências, checagens automatizadas e geração de relatórios técnicos.

> Status: API mínima com verificação de saúde. As análises ainda não foram implementadas.

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

## Estrutura

```
app/      código da aplicação
docs/     documentação técnica
tests/    testes automatizados
```
