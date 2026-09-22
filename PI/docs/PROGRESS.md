# Progresso por blocos

## Estado atual

`CURRENT_BLOCK: B0`

Status geral: **planejamento concluído; implementação ainda não iniciada**.

## Regras de atualização

Ao terminar um bloco:

1. altere `CURRENT_BLOCK` para o próximo bloco;
2. atualize o status do bloco concluído;
3. acrescente uma entrada curta no histórico;
4. não implemente o próximo bloco na mesma tarefa sem pedido explícito.

Não transforme este arquivo em diário detalhado. O objetivo é permitir handoff rápido entre sessões/agentes.

## Status

| Bloco | Estado | Resumo |
| --- | --- | --- |
| B0 | READY | Scaffold, modelos e contrato de snapshot |
| B1 | BLOCKED | Processos e rede; depende de B0 |
| B2 | BLOCKED | Serviços systemd; depende de B0/B1 |
| B3 | BLOCKED | Permissões contextuais; depende de B1/B2 |
| B4 | BLOCKED | Correlações/findings; depende de B1-B3 |
| B5 | BLOCKED | CLI/relatórios/offline; depende de B4 |
| B6 | BLOCKED | Cenários, docs e demo; depende de B5 |
| B7 | OPTIONAL | Extensões somente após B0-B6 |

## Formato do resumo de conclusão

Use no máximo este formato:

```md
### YYYY-MM-DD — Bx concluído

- Entregue: ...
- Validação: ...
- Decisões: ...
- Limitações/pendências: ...
- Próximo bloco: By
```

Se uma decisão alterar a arquitetura, atualize `ARCHITECTURE.md` no mesmo bloco.

## Histórico

Nenhum bloco implementado ainda.
