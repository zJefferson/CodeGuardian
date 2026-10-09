# Pontuação de qualidade (fórmula 1.0)

> **Indicador relativo, baseado apenas nas verificações automatizadas executadas. Não é
> uma medida absoluta da qualidade do software.** Uma nota alta não garante ausência de
> defeitos, vulnerabilidades ou problemas de projeto; uma nota baixa não significa que o
> software seja inutilizável. A nota não usa IA e não lê o código: é calculada de forma
> determinística a partir dos resultados estruturados do relatório.

Implementação: `app/quality_score.py`. O resultado fica em `report.quality` e, de forma
resumida, em `quality_score` no endpoint de status.

## Estados

Cada dimensão termina em um de três estados:

| Estado | Significado | Efeito |
|---|---|---|
| `available` | verificação concluída, nota de 0 a 100 | entra na média |
| `not_applicable` | nada a avaliar (ex.: sem dependências declaradas) | fica fora da média; pesos são renormalizados |
| `unavailable` | verificação falhou, não executou ou faltam dados | **nunca vale 0 nem 100**; a nota geral fica indisponível |

A **nota geral** é a média ponderada das dimensões aplicáveis. Ela fica **indisponível**
quando qualquer dimensão aplicável está indisponível, quando o repositório não foi
analisado (URL inválida, falha de clonagem) ou quando não há código Python nem
dependências. As notas das dimensões disponíveis continuam visíveis.

A nota é independente do campo `approved`.

## Dimensões e pesos

| Dimensão | Peso | Fonte |
|---|---|---|
| `static_analysis` | 40 | Ruff |
| `dependencies` | 30 | pip-audit |
| `practices` | 20 | análise estrutural |
| `tests` | 10 | execução isolada com pytest (opcional) |

Peso efetivo = peso ÷ soma dos pesos das dimensões aplicáveis. Sem execução de testes,
por exemplo: 40/90, 30/90 e 20/90.

### Análise estática (Ruff)

Peso de cada achado por regra:

| Categoria | Regras | Peso |
|---|---|---|
| Código não analisável | `invalid-syntax`, `E9*` | 10 |
| Segurança | `S*` | 5 |
| Erros prováveis | `F*`, `B*` | 3 |
| Estilo e legibilidade | demais (`E4*`, `E7*`...) | 1 |

`S101` (uso de `assert`) em arquivos de teste tem peso 0: é o mecanismo normal do pytest.
São considerados de teste arquivos em diretórios `tests/`, `test/` ou `testing/`, e
arquivos `test_*.py`, `*_test.py` ou `conftest.py`.

```
D    = soma dos pesos ÷ número de arquivos Python
nota = 100 ÷ (1 + D ÷ 10)
```

D = 10 reduz a nota à metade; a curva nunca fica negativa. Os pontos perdidos são
atribuídos às categorias proporcionalmente aos seus pesos (fatores exibidos).

- **Indisponível**: Ruff com timeout, falha ou limite de saída; ou lista de achados
  truncada (sem o detalhe por regra não há como ponderar). O limite padrão de achados
  detalhados é 5000.
- **Não aplicável**: sem arquivos Python.

### Dependências (pip-audit)

```
nota = 100 − 25 × pacotes vulneráveis − 5 × vulnerabilidades adicionais no mesmo pacote
       (mínimo 0)
```

O pip-audit não informa gravidade (CVSS); todas as vulnerabilidades pesam igual.

**Cobertura** = pacotes auditados ÷ (auditados + não auditados), contando por nome: uma
faixa de versão no `pyproject.toml` não conta como "não auditada" se o mesmo pacote foi
auditado por um lockfile. Linhas sem nome (como `-r`) contam como não auditadas.

- **Indisponível**: auditoria com falha, fonte indisponível, timeout; nenhuma dependência
  auditável; ou **cobertura abaixo de 50%**.
- **Não aplicável**: sem arquivos de dependências.

### Práticas do projeto (estrutura)

| Item | Pontos |
|---|---|
| Testes presentes | 40 |
| README na raiz | 25 |
| Dependências declaradas (`pyproject.toml`, `requirements*.txt`, `Pipfile`) | 15 |
| Versões fixadas (lockfile, ou dependências com `==` auditadas) | 10 |
| Diretório de documentação | 10 |

- **Indisponível**: análise estrutural incompleta (não é possível afirmar ausências) ou,
  sem lockfile, quando a auditoria não terminou e não há como saber se há versões fixadas.

### Testes executados

```
nota = 100 × aprovados ÷ (aprovados + reprovados + erros)
```

- **Não aplicável**: execução desabilitada ou nenhum teste encontrado.
- **Indisponível**: ambiente isolado indisponível, erro de coleta, timeout, limite de
  recursos, falha de infraestrutura ou contagens ausentes.

## Exemplo

Projeto com 20 arquivos Python, 4 × `F401`, 2 × `S603`, 1 × `E711`; um pacote com 3
vulnerabilidades; testes e README presentes, lockfile, sem diretório de docs; execução de
testes desabilitada:

| Dimensão | Cálculo | Nota | Peso efetivo |
|---|---|---|---|
| Análise estática | D = (4×3 + 2×5 + 1×1) ÷ 20 = 1,15 → 100 ÷ 1,115 | 89,7 | 0,444 |
| Dependências | 100 − 25 − 2×5 | 65,0 | 0,333 |
| Práticas | 100 − 10 (sem docs) | 90,0 | 0,222 |
| Testes | desabilitado | — | — |

Nota geral = (40 × 89,7 + 30 × 65 + 20 × 90) ÷ 90 = **81,5**.

## Limitações

- As ferramentas detectam apenas o que suas regras cobrem; arquitetura, desempenho,
  legibilidade geral e correção funcional não são avaliados.
- A densidade usa número de arquivos, não de linhas: arquivos muito grandes ou muito
  pequenos distorcem a métrica.
- Sem CVSS, uma vulnerabilidade crítica e uma de baixo impacto pesam igual.
- Projetos com dependências em faixas de versão e sem lockfile tendem a ficar com a
  dimensão de dependências indisponível (cobertura baixa).
- Pesos e constantes são escolhas documentadas, não padrões da indústria; mudanças na
  fórmula devem alterar `formula_version`.
