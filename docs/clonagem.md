# Clonagem de repositórios: controles e riscos

Este documento descreve como `app/repository_clone.py` clona repositórios não
confiáveis, quais riscos permanecem e quais controles são necessários antes de
expor o CodeGuardian publicamente.

## Controles implementados

| Controle | Como |
|---|---|
| Somente repositórios validados | Aceita apenas `GitHubRepository` e revalida a URL antes de clonar (impede objetos montados manualmente com `owner`/`name` maliciosos). |
| Sem shell e sem injeção de opções | `subprocess.Popen` com lista de argumentos, `shell=False`, caminho absoluto do Git e `--` antes da URL e do destino. |
| Configuração do Git isolada | `GIT_CONFIG_NOSYSTEM=1` e `GIT_CONFIG_GLOBAL` apontando para o dispositivo nulo: helpers de credenciais, aliases, hooks globais e filtros do servidor não são carregados. |
| Sem credenciais | `credential.helper=` vazio, `GIT_TERMINAL_PROMPT=0`, `GCM_INTERACTIVE=never`, askpass vazio. Repositórios privados ou inexistentes falham sem pedir senha. |
| Ambiente mínimo | O Git recebe apenas `PATH`, `SYSTEMROOT` e variáveis próprias; tokens e segredos do processo da API não são repassados. |
| Somente HTTPS | `protocol.allow=never`, `protocol.https.allow=always`, `GIT_ALLOW_PROTOCOL=https`. |
| Sem redirecionamentos | `http.followRedirects=false`: o Git não segue o servidor para outros endereços. |
| Clone mínimo | `--depth=1 --single-branch --no-tags --no-recurse-submodules --template=`. Submódulos (que poderiam apontar para outros hosts) não são buscados. |
| Nenhum código do repositório executado | Hooks não são clonados; `--template=` evita copiar hooks locais; nenhum filtro (`smudge`/LFS) está configurado; `core.fsmonitor=false`. |
| Integridade dos objetos | `transfer.fsckObjects=true` rejeita objetos malformados. |
| Proteção do sistema de arquivos | `core.symlinks=false` (links viram arquivos comuns), `core.protectNTFS` e `core.protectHFS` bloqueiam nomes perigosos como `.git` disfarçado. |
| Diretório exclusivo | `tempfile.mkdtemp` (permissões restritas) por clonagem. |
| Limpeza garantida | Context manager remove o diretório após a análise, em erro e em timeout, inclusive arquivos somente leitura de `.git/objects`. |
| Tempo limite | Processo interrompido (`kill`) ao exceder `timeout_seconds`. |
| Tamanho limite | Tamanho do diretório monitorado durante a clonagem e verificado ao final. |
| Saída limitada | No máximo `max_output_bytes` da saída de erro são guardados; o restante é descartado. A saída fica em `detail` (para logs) e nunca na mensagem ao usuário. |

## Riscos restantes

1. **O Git roda no mesmo host da API.** Uma vulnerabilidade no Git (no protocolo,
   no parser de pacotes ou no checkout) explorada por um repositório malicioso
   comprometeria o servidor. Os controles acima reduzem a superfície, mas **não
   são isolamento**.
2. **Processos filhos após timeout.** `kill` encerra o `git` principal; processos
   auxiliares (`git-remote-https`) podem continuar por alguns instantes até
   perceberem o pipe fechado. No Windows isso pode atrasar a remoção dos arquivos;
   a limpeza tenta novamente e registra um aviso se falhar.
3. **Limite de tamanho por amostragem.** O tamanho é medido a cada
   `poll_interval_seconds`; entre duas medições o repositório pode ultrapassar o
   limite. Não há limite de número de arquivos nem de profundidade de diretórios.
4. **Consumo de rede e CPU.** Não há limite de banda nem de CPU/memória do Git.
   Repositórios com histórico raso mas árvore gigante ainda consomem recursos.
5. **Disco compartilhado.** Os clones usam o diretório temporário do sistema; muitas
   clonagens simultâneas podem esgotar o disco.
6. **Conteúdo hostil nos arquivos.** Nomes de arquivos estranhos, arquivos enormes,
   binários e textos com instruções (prompt injection) chegam às etapas seguintes.
   Esses dados devem ser tratados como não confiáveis por todos os analisadores.
7. **Repositórios renomeados.** Com redirecionamentos desativados, URLs antigas
   falham em vez de seguir para o novo endereço.
8. **Disponibilidade do GitHub.** Rate limiting e falhas de rede aparecem como
   falhas de clonagem genéricas.

## Controles necessários para implantação pública

- **Isolamento:** executar a clonagem (e toda análise posterior) em contêiner ou
  VM descartável, sem privilégios, com usuário não root, sistema de arquivos
  raiz somente leitura e volume de trabalho dedicado.
- **Rede de saída restrita:** permitir apenas `github.com:443` a partir do
  ambiente de clonagem; bloquear redes privadas e endereços de metadados de nuvem
  (`169.254.169.254` etc.) no nível de rede, não só na aplicação.
- **Limites do sistema operacional:** cgroups/limites do contêiner para CPU,
  memória, número de processos e tamanho do disco (quota ou tmpfs com tamanho
  fixo), garantindo também a morte de toda a árvore de processos no timeout.
- **Fila e concorrência:** limitar clonagens simultâneas por instância e por
  usuário; aplicar rate limiting e autenticação na API.
- **Git atualizado:** manter o Git na versão mais recente com correções de
  segurança e registrar a versão usada em cada análise.
- **Observabilidade:** registrar falhas, timeouts e limites atingidos (com
  `detail`), sem registrar segredos nem expor esses detalhes ao usuário.
- **Limpeza periódica:** rotina que remove diretórios `codeguardian-*` órfãos
  deixados por quedas do processo.
