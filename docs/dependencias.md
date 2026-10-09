# Análise de dependências: escopo e limites

O CodeGuardian verifica vulnerabilidades conhecidas nas dependências declaradas de
um repositório usando o [pip-audit](https://pypi.org/project/pip-audit/). Este
documento explica como a análise funciona e, principalmente, **o que ela não cobre**.

## Como funciona

1. `app/dependency_files.py` localiza os arquivos suportados (a partir da análise
   estrutural) e os lê **como dados**, sem instalar nem executar nada:

   | Arquivo | O que é lido |
   |---|---|
   | `requirements*.txt` | linhas de requisito (PEP 508) |
   | `pyproject.toml` | `[project] dependencies`, `optional-dependencies` e `[dependency-groups]` |
   | `Pipfile.lock` | seções `default` e `develop` |
   | `poetry.lock`, `uv.lock` | tabelas `[[package]]` vindas do PyPI |

2. Somente dependências com **versão exata** (`==` / `===`) são auditadas. As demais
   ficam em `unaudited`, com o motivo.
3. Um arquivo `requirements` **sanitizado** (apenas `nome==versão`) é gerado em um
   diretório temporário próprio. Os arquivos do repositório nunca são entregues ao
   pip-audit.
4. O pip-audit roda em um subprocesso separado (`python -I -m pip_audit`), com
   `--no-deps --disable-pip`: não instala pacotes, não resolve dependências e,
   portanto, não executa `setup.py` de terceiros. O ambiente do subprocesso é mínimo
   (sem tokens ou variáveis `PIP_*` do servidor), com diretório pessoal e cache
   apontando para o diretório temporário, removido ao final.
5. Para cada versão, o pip-audit consulta a fonte de vulnerabilidades (PyPI por
   padrão, ou OSV) e o CodeGuardian registra pacote, versão, arquivos de origem,
   identificadores (`PYSEC-…`, `GHSA-…`, `CVE-…`) e versões com correção.

## Resultados possíveis

| `status` | Significado |
|---|---|
| `no_vulnerabilities` | análise concluída, nenhuma vulnerabilidade conhecida nas versões auditadas |
| `vulnerabilities_found` | análise concluída, com vulnerabilidades |
| `no_dependency_files` | nenhum arquivo de dependências suportado encontrado |
| `no_auditable_dependencies` | há arquivos, mas nenhuma dependência com versão exata |
| `source_unavailable` | a fonte de vulnerabilidades não respondeu (rede, PyPI/OSV fora do ar) |
| `timeout` / `output_limit` | análise interrompida por limite |
| `failed` | falha de execução do pip-audit |

"Nenhuma vulnerabilidade" **não significa** que o projeto é seguro.

## O que a análise não cobre

A análise depende **das dependências declaradas** e **das informações disponíveis na
fonte de vulnerabilidades**:

- **Versões não fixadas** (`requests>=2`, `django`) não são auditadas: sem instalar o
  projeto não é possível saber qual versão seria usada.
- **Dependências transitivas** só são verificadas se estiverem declaradas com versão
  exata (por exemplo, em um lockfile ou em um `requirements.txt` gerado com
  `pip freeze`/`pip-compile`).
- **Vulnerabilidades não publicadas** ou ainda não cadastradas na fonte não aparecem.
  Resultados podem mudar com o tempo para as mesmas versões.
- **Pacotes fora do PyPI** (git, caminhos locais, URLs, índices privados) não são
  auditados; o nome poderia coincidir com outro pacote no PyPI.
- **Opções de `requirements`** (`-r`, `-c`, `-e`, `--index-url`…) não são seguidas,
  por segurança: poderiam apontar para arquivos fora do repositório ou para serviços
  internos. Arquivos incluídos só são lidos se também estiverem no repositório com
  nome `requirements*.txt`.
- **Marcadores de ambiente** (`; python_version < "3.9"`) não são avaliados: a
  dependência é auditada mesmo que não se aplique a todas as plataformas.
- Formatos não suportados: `setup.py`/`setup.cfg` (exigiriam executar ou interpretar
  código), `[tool.poetry.dependencies]`, `pdm.lock`, `environment.yml`.
- Não há verificação de licenças, pacotes maliciosos ou typosquatting.

## Implantação

- O pip-audit precisa de acesso de saída a `pypi.org` (ou `api.osv.dev`). Proxies do
  ambiente do servidor não são repassados ao subprocesso.
- `AuditSettings.python_executable` permite usar um ambiente virtual dedicado ao
  pip-audit, separado do ambiente da API. Nesse caso a versão da ferramenta não é
  lida automaticamente (`tool_version` fica `null`).
- As mesmas recomendações de isolamento de [clonagem.md](clonagem.md) se aplicam.
