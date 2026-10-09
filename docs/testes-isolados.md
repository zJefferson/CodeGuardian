# Execução isolada de testes

O CodeGuardian pode, **opcionalmente**, executar os testes dos repositórios analisados
com pytest. Como isso significa executar código de terceiros, a execução só acontece
dentro de um container descartável e só quando configurada explicitamente.

## Ativação

Desabilitada por padrão. Para ativar, defina **ambas** as variáveis no ambiente em que
a API é iniciada (o arquivo `.env` não é carregado automaticamente):

```powershell
$env:CODEGUARDIAN_TEST_EXECUTION = "enabled"
$env:CODEGUARDIAN_TEST_IMAGE = "codeguardian/pytest-runner:0.1.0"
uvicorn app.main:app
```

Somente o valor exato `enabled` ativa a execução. Uma referência de imagem inválida
(por exemplo, contendo espaços ou começando com `-`) impede a API de iniciar.

Construa a imagem antes (único momento em que há acesso à rede, com conteúdo confiável):

```powershell
docker build -f docker/pytest-runner.Dockerfile -t codeguardian/pytest-runner:0.1.0 .
```

## Arquitetura

```
API (processo principal)                       Docker (VM Linux / host)
  └─ app/test_runner.py                          ┌──────────────────────────────┐
       ├─ docker version / image inspect  ─────► │ container descartável (--rm) │
       └─ docker run (sem shell, timeout) ─────► │  python -m pytest            │
            ▲ código de saída + resumo           │  /workspace  (repo, readonly)│
            └──────────────────────────────────  │  /tmp        (tmpfs 64 MB)   │
                                                 │  sem rede, usuário nobody    │
                                                 └──────────────────────────────┘
```

O processo da API nunca importa nem executa código do repositório; ele apenas chama a
CLI `docker` com uma lista de argumentos fixa.

### Controles do container

| Controle | Opção |
|---|---|
| Descartável | `--rm`, nome único, `docker rm --force` sempre ao final |
| Sem rede | `--network none` |
| Usuário sem privilégios | `--user 65534:65534`, `--cap-drop ALL`, `--security-opt no-new-privileges` |
| CPU / memória / processos | `--cpus 1`, `--memory 512m --memory-swap 512m`, `--pids-limit 128`, `--ulimit nofile=256` |
| Tempo | timeout de 300 s; ao exceder, `docker kill` (encerrar só o cliente deixaria o container vivo) |
| Sistema de arquivos | `--read-only`; repositório montado `readonly`; `/tmp` em tmpfs `noexec,nosuid,nodev` de 64 MB |
| Sem credenciais do host | apenas `--env` com valores fixos (`HOME=/tmp` etc.); nenhum `--env-file`, nenhuma variável herdada |
| Sem socket do Docker | nenhum volume além do repositório |
| Sem instalação de dependências | imagem própria com Python + pytest; `--pull never`; nada é instalado na execução |
| Saída | limitada em bytes; o relatório guarda apenas status e contagens, nunca a saída bruta |

Ajustes do pytest: `-p no:cacheprovider` (sistema somente leitura),
`-o addopts=` (ignora opções do repositório que exigiriam plugins ausentes),
`PYTEST_DISABLE_PLUGIN_AUTOLOAD=1` e `--basetemp=/tmp/pytest`.

Os limites são configuráveis em `TestExecutionSettings` (`cpus`, `memory_mb`,
`pids_limit`, `tmpfs_mb`, `timeout_seconds`).

## Resultados

| `status` | Significado | Efeito no relatório |
|---|---|---|
| `disabled` | execução não configurada | verificação `skipped`, **não altera** o resultado geral |
| `skipped_unavailable` | sem ambiente isolado (Docker ausente/parado, modo Windows, imagem não construída) | `incomplete` |
| `no_tests` | nenhum teste encontrado/coletado | `not_applicable` |
| `passed` | todos os testes passaram | sem achados |
| `failed` | testes reprovados | achados (`issues_found`) |
| `collection_error` | erro ao coletar (geralmente dependências ausentes) | `incomplete` |
| `pytest_error` | erro de uso/interno do pytest (configuração do repositório) | `incomplete` |
| `timeout` | tempo excedido | `incomplete` |
| `resource_limit` | container encerrado (ex.: memória, código 137) | `incomplete` |
| `infrastructure_error` | falha do Docker ou do ambiente | `incomplete` |

Se não houver ambiente isolado disponível, a etapa é **ignorada**. Não existe
alternativa de execução fora do container.

## Riscos restantes

1. **Container não é uma fronteira perfeita.** Ele compartilha o kernel com o host (no
   Windows, com a VM WSL2 do Docker Desktop). Uma vulnerabilidade de kernel ou do
   runtime permitiria escapar. Em produção, use runtimes com isolamento mais forte
   (gVisor, Kata Containers, microVMs) em hosts dedicados.
2. **Acesso ao Docker equivale a root.** A API precisa falar com o daemon; se a própria
   API for comprometida, o atacante controla o Docker. Em produção, mova a execução
   para um serviço runner separado, com Docker rootless e sem outros segredos.
3. **A maioria dos projetos reais terá `collection_error`.** Sem instalar dependências,
   testes que importam bibliotecas de terceiros não são coletados. É uma limitação
   funcional, registrada como tal (não como "testes reprovados").
4. **Abuso de recursos é limitado, não impedido.** Um teste pode consumir CPU/memória
   até os limites e o tempo máximo.
5. **Containers órfãos.** Se o processo da API cair durante a execução, o container
   pode continuar até o fim; ele tem `--rm` e a label `codeguardian.role=test-runner`,
   que permite limpeza manual: `docker ps -q --filter label=codeguardian.role=test-runner`.
6. **Windows.** O bind mount usa o diretório temporário do usuário, que precisa estar
   compartilhado com o Docker Desktop (padrão para `C:\Users`).

## Validação

A orquestração é testada com comandos Docker simulados (`tests/test_test_runner.py`).
A execução real ainda não foi validada neste ambiente porque o daemon do Docker não
estava disponível; nessa condição, o comportamento verificado foi o esperado: etapa
`skipped_unavailable`, sem executar nada localmente.
