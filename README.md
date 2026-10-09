# CodeGuardian

Ferramenta para analisar repositórios Git públicos: qualidade de código, verificação de
dependências, checagens automatizadas e geração de relatórios técnicos.

> Status: configuração inicial. A API e as análises ainda não foram implementadas.

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

## Verificações

```powershell
ruff check .          # lint
ruff format --check . # formatação
pytest                # testes
pip-audit -r requirements.txt  # vulnerabilidades conhecidas nas dependências
```

## Estrutura

```
app/      código da aplicação
tests/    testes automatizados
```
