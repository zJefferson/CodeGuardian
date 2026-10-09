# Exemplos de relatório

## `relatorio-codeguardian.json` — resultado real

Relatório **real, não editado**, produzido pelo próprio CodeGuardian ao analisar o seu
repositório público:

| Campo | Valor |
|---|---|
| Repositório | <https://github.com/zJefferson/CodeGuardian> (commit `eb21194`) |
| Gerado em | 2026-10-09 (UTC), com `analyze_repository()` |
| Ferramentas | CodeGuardian 0.1.0, Python 3.14.6, Git 2.52.0, Ruff 0.16.10, pip-audit 2.10.1 |
| Execução de testes | desabilitada (configuração padrão) |
| IA | não utilizada |

Como ler o resultado:

- **706 achados do Ruff**, todos `S101` (uso de `assert`) em `tests/`. O CodeGuardian
  aplica as mesmas regras a qualquer repositório; na pontuação, `S101` em arquivos de
  teste tem peso 0 (ver [pontuacao.md](../pontuacao.md)), por isso a análise estática
  recebe 100.
- **Dependências `partial`**: os 47 pacotes do `requirements.txt` foram auditados sem
  vulnerabilidades conhecidas, mas as 8 faixas de versão do `pyproject.toml` contam como
  declarações não auditadas.
- Por isso o resultado geral é **`incomplete`** e `approved` é `false`, embora a
  pontuação seja 100: a pontuação considera a cobertura por nome de pacote (100%), enquanto
  `approved` exige que nenhuma declaração fique sem auditoria. Os dois critérios são
  documentados e intencionais.

Resultados de vulnerabilidades dependem da data: uma nova análise das mesmas versões pode
trazer achados diferentes.

## Exemplos ilustrativos

Os valores do exemplo de cálculo em [pontuacao.md](../pontuacao.md#exemplo-ilustrativo)
são **hipotéticos**, criados para demonstrar a fórmula; não correspondem a nenhum
repositório real. Os relatórios usados nos testes automatizados (`tests/`) também são
dados de teste, não resultados reais.
