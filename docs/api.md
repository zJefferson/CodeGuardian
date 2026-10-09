# API REST

A API é assíncrona: iniciar uma análise apenas a enfileira, e o andamento é
consultado depois. Nenhuma requisição aguarda a análise terminar.

## Endpoints

| Método e rota | Sucesso | Erros |
|---|---|---|
| `POST /analyses` | `202` + cabeçalho `Location` | `422` entrada inválida, `413` corpo grande demais, `503` capacidade esgotada (com `Retry-After`) |
| `GET /analyses/{analysis_id}` | `200` status | `404` não encontrada/expirada, `422` id inválido |
| `GET /analyses/{analysis_id}/report` | `200` relatório JSON | `404`, `409` ainda em execução ou falhou sem relatório, `422` |
| `GET /health` | `200` | — |

Documentação interativa: `/docs` (Swagger) e `/openapi.json`.

### Exemplo

```bash
curl -X POST http://127.0.0.1:8000/analyses \
  -H "content-type: application/json" \
  -d '{"repository_url": "https://github.com/psf/requests"}'
```

```json
{
  "analysis_id": "b48380fa-9e59-4783-b4a1-ba68f41c209f",
  "status": "queued",
  "repository_url": "https://github.com/psf/requests",
  "status_url": "/analyses/b48380fa-9e59-4783-b4a1-ba68f41c209f",
  "report_url": "/analyses/b48380fa-9e59-4783-b4a1-ba68f41c209f/report"
}
```

`GET /analyses/{id}` retorna `status` (`queued`, `running`, `completed`, `failed`) e,
quando concluída, `overall_status` e `approved` do relatório. `completed` significa
que há relatório — o relatório em si pode indicar falha (por exemplo, repositório
inexistente). `failed` significa que nenhum relatório foi produzido.

### Erros

Todos os erros têm o mesmo formato e nunca reproduzem os valores enviados:

```json
{
  "error": {
    "code": "validation_error",
    "message": "A requisição contém dados inválidos.",
    "details": [{"field": "repository_url", "message": "A URL não pode conter credenciais."}]
  }
}
```

Códigos: `validation_error`, `payload_too_large`, `not_found`, `method_not_allowed`,
`analysis_not_ready`, `analysis_failed`, `capacity_exceeded`, `internal_error`.

## Execução em segundo plano: restrições

O projeto **não possui infraestrutura persistente de tarefas** (fila, worker separado
ou banco de dados). Por isso a execução usa um fluxo limitado, em memória
(`app/jobs.py`), adequado **apenas ao ambiente local**:

| Limite | Padrão | Comportamento |
|---|---|---|
| Análises simultâneas | 2 threads | as demais aguardam na fila |
| Fila | 10 pendentes | acima disso, `503` com `Retry-After` |
| Duração máxima de um job | 900 s | após o limite, o job vira `failed`; cada etapa também tem timeout próprio |
| Retenção de resultados | 1 h, até 200 análises | depois, `404` |
| Corpo da requisição | 8 KiB | acima disso, `413` |

Consequências:

- **Resultados são perdidos** quando o processo reinicia; análises em andamento são
  abandonadas e seus diretórios temporários podem ficar órfãos (veja
  [clonagem.md](clonagem.md)).
- **Um único processo.** Com vários workers (`uvicorn --workers N`) ou várias
  instâncias, cada uma teria sua própria fila e memória: um id criado em uma não
  seria encontrado em outra. Rode com um único worker.
- **As análises disputam CPU e memória com a API**, no mesmo processo.
- Um job que excede a duração máxima é marcado como `failed`, mas a thread só termina
  quando a etapa em andamento atinge o próprio timeout.
- **Não há autenticação nem limite por cliente.** Não exponha a API publicamente.

Para produção seriam necessários: fila persistente e workers separados (isolados
conforme [clonagem.md](clonagem.md)), armazenamento persistente dos relatórios,
autenticação, limites por cliente e limpeza periódica de diretórios órfãos.
