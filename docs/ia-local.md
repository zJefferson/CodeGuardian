# Explicações com IA local (Ollama)

Funcionalidade **opcional**: explica, em linguagem simples, um achado do relatório (do
Ruff ou do pip-audit) e sugere possíveis correções, usando um modelo executado
localmente com o [Ollama](https://ollama.com). Todas as análises funcionam sem IA; a
pontuação e o relatório não são alterados.

## Configuração

1. Instale o Ollama pelo site oficial (<https://ollama.com/download>) e inicie-o
   (por padrão ele escuta em `http://127.0.0.1:11434`).
2. Baixe o modelo (cerca de 4,7 GB; requer ~8 GB de RAM livre):

   ```powershell
   ollama pull qwen2.5-coder:7b
   ```

   Máquinas com menos memória podem usar um modelo menor, por exemplo
   `ollama pull llama3.2:3b`, e configurar `CODEGUARDIAN_OLLAMA_MODEL`.
3. Habilite as explicações no ambiente em que a API é iniciada:

   ```powershell
   $env:CODEGUARDIAN_AI_EXPLANATIONS = "enabled"
   # opcionais:
   $env:CODEGUARDIAN_OLLAMA_URL = "http://127.0.0.1:11434"
   $env:CODEGUARDIAN_OLLAMA_MODEL = "qwen2.5-coder:7b"
   uvicorn app.main:app
   ```

   Somente o valor exato `enabled` habilita. `CODEGUARDIAN_OLLAMA_URL` aceita apenas
   `http://` em endereço de loopback (`127.0.0.1`, `localhost`, `::1`); qualquer outro
   valor impede a API de iniciar.

Com a IA habilitada, a interface web mostra o botão **Explicar com IA** em cada achado do
Ruff e em cada vulnerabilidade.

## API

| Rota | Descrição |
|---|---|
| `GET /ai/status` | `{"enabled": bool, "model": str \| null, "local_only": true}` |
| `POST /analyses/{id}/explanations` | explica um achado de um relatório concluído |

Corpo da requisição:

```json
{"kind": "ruff_finding", "finding_index": 5}
{"kind": "vulnerability", "package": "jinja2", "vulnerability_id": "PYSEC-2019-217"}
```

`finding_index` é a posição do achado em `report.ruff.findings`. A resposta traz
`status`, a cópia **exata** do achado original (`finding`), a explicação (`summary`,
`explanation`, `suggested_fix`), o modelo usado e um aviso.

| `status` | Significado |
|---|---|
| `completed` | explicação gerada e validada |
| `disabled` | funcionalidade desabilitada (o modelo não é chamado) |
| `unavailable` | Ollama inacessível ou modelo não baixado |
| `timeout` | o modelo não respondeu em 60 s |
| `invalid_response` | resposta fora do esquema, grande demais ou citando dados que não constam no achado |
| `busy` | limite de 2 explicações simultâneas atingido |
| `failed` | erro inesperado |

Esses estados são retornados com HTTP `200`. Erros da requisição seguem o formato padrão
da API: `404` (análise ou achado inexistente), `409` (relatório não disponível) e `422`
(corpo inválido).

## Privacidade e segurança

- **Somente local.** O cliente aceita apenas endereços de loopback, não segue
  redirecionamentos e ignora proxies do ambiente. Nada é enviado a serviços externos e
  não há APIs pagas.
- **Mínimo necessário.** Para cada pedido é enviado apenas **um** achado, com seus campos
  estruturados: regra, mensagem, sugestão da ferramenta, arquivo e linha; ou pacote,
  versão, identificador, aliases e versões com correção. Nenhum código-fonte é enviado
  (o clone já foi removido quando a explicação é pedida).
- **Dados não confiáveis.** Mensagens e caminhos podem conter texto controlado pelo
  repositório analisado (tentativas de *prompt injection*). O achado é enviado como JSON
  entre `<achado>` e `</achado>`, os caracteres `<` e `>` dos dados são neutralizados,
  cada campo é limitado a 300 caracteres e o prompt de sistema instrui o modelo a nunca
  seguir instruções contidas nos dados.
- **Sem invenções.** O modelo precisa responder em um esquema JSON fixo (`format` do
  Ollama), validado com Pydantic (resumo até 300 caracteres; explicação e correção até
  2000). Respostas que citem números de linha diferentes do achado ou identificadores de
  vulnerabilidade (CVE, GHSA, PYSEC) ausentes do achado são descartadas.
- **Resultados originais preservados.** A explicação é exibida separadamente, marcada como
  gerada por IA; arquivo, linha, regra, mensagem e vulnerabilidades continuam vindo das
  ferramentas. Relatório e pontuação não mudam.
- **Limites.** Timeout de 60 s, resposta HTTP até 32 KiB, até 700 tokens gerados e no
  máximo 2 explicações simultâneas.

## Limitações

- A explicação é genérica sobre a regra ou vulnerabilidade: o modelo não vê o código.
- Modelos locais podem errar ou simplificar demais; a checagem de "invenções" é
  heurística (linhas e identificadores) e não garante correção do texto.
- O tempo de resposta depende do hardware; sem GPU, modelos de 7B podem levar dezenas
  de segundos.
- A geração ocorre no processo da API (thread do servidor), limitada pelo timeout.
- Nesta máquina de desenvolvimento o Ollama não estava instalado: a integração foi
  validada com um cliente simulado nos testes e com um servidor falso local que imita a
  API do Ollama.
