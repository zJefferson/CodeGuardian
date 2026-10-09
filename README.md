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

## Estrutura

```
app/      código da aplicação
tests/    testes automatizados
```
