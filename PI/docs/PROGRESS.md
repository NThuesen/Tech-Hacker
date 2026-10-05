# Progresso por blocos

## Estado atual

`CURRENT_BLOCK: NONE`

Status geral: **B0-B8 concluídos e validados; integração offline com o dataset do professor disponível. Nenhum próximo bloco aprovado**.

## Regras de atualização

Ao terminar um bloco:

1. altere `CURRENT_BLOCK` para o próximo bloco;
2. atualize o status do bloco concluído;
3. acrescente uma entrada curta no histórico;
4. não implemente o próximo bloco na mesma tarefa sem pedido explícito; se o bloco concluído for o último aprovado, defina `CURRENT_BLOCK: NONE`.

Não transforme este arquivo em diário detalhado. O objetivo é permitir handoff rápido entre sessões/agentes.

## Status

| Bloco | Estado | Resumo |
| --- | --- | --- |
| B0 | DONE | Scaffold, modelos e contrato JSON v1 validados; 21 testes passam |
| B1 | DONE | Processos e sockets normalizados, falhas parciais e snapshot; suíte com 36 testes passa |
| B2 | DONE | Serviços systemd, wrapper read-only e vínculo MainPID; suíte com 55 testes passa |
| B3 | DONE | Permissões contextuais e indicação POSIX separada; suíte com 81 testes passa |
| B4 | DONE | C1/C2/C3 e findings rastreáveis; suíte com 109 testes passa |
| B5 | DONE | CLI live/offline e relatórios; suíte com 116 testes passa |
| B6 | DONE | Quatro cenários integrados, README, roteiro e base técnica; 124 testes passam |
| B7 | DONE | C2 direta/descendente com proveniência e cadeia PPID, travessia segura e demo de filho; suíte com 139 testes passa |
| B8 | DONE | Importador offline e analyze-dataset; generator preservado, núcleo/schema inalterados; suíte com 174 testes passa |

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

### 2026-09-22 — B0 concluído

- Entregue: pacote com layout src/tests, modelos, JSON v1, CLI de ajuda e comandos canônicos no README/AGENTS.md.
- Validação: instalação editable com .[dev] em PI/.venv; import e --help funcionam; 21 testes passam com Python 3.13.12 e pytest 9.1.1.
- Decisões: dataclasses, campos desconhecidos como null, issues estruturados, validação de tipos/versão JSON e contrato documentado em ARCHITECTURE.md.
- Limitações/pendências: sem coleta, correlação ou scan/analyze; compatibilidade mínima declarada Python 3.11, execução validada apenas em 3.13.12.
- Próximo bloco: B1.

### 2026-09-22 — B1 concluído

- Entregue: coletores psutil de processos e sockets, composição de snapshot parcial na API Python e testes com mocks.
- Validação: 36 testes passam em Python 3.13.12; ajuda CLI validada; coleta local read-only com 180 processos, 1 socket e 90 issues preservada em round-trip JSON; git diff --check sem erros.
- Decisões: UID/GID efetivos; falha por campo preserva dados disponíveis; corrida detectada mantém apenas PID; TCP LISTEN e UDP vinculado sem peer; documentação atualizada.
- Limitações/pendências: visibilidade parcial sem privilégios, snapshot não atômico e UDP sem prova de função servidor; serviços/permissões e comandos CLI ainda não implementados.
- Próximo bloco: B2.

### 2026-09-22 — B2 concluído

- Entregue: wrapper central read-only, collector systemd, parser com fixtures, associação MainPID -> ProcessRecord e integração no snapshot.
- Validação: 55 testes passam em Python 3.13.12; coleta local observou 21 serviços e 1 aviso de serviços, com round-trip JSON válido; casos sem systemd, sem MainPID e falhas por unit cobertos.
- Decisões: timeout por comando, sem shell/autenticação interativa; configuração vazia preservada; MainPID zero como null; vínculos resolvidos sem duplicar processos no JSON.
- Limitações/pendências: coleta não atômica, ExecStart ainda bruto, permissões e análise ainda ausentes; próximo bloco não iniciado.
- Próximo bloco: B3.

### 2026-09-22 — B3 concluído

- Entregue: seleção deduplicada, stat de recursos/pais imediatos, resolução de identidades e indicação POSIX separada dos fatos, sem findings.
- Validação: 81 testes passam em Python 3.13.12; coleta local com 109 registros de permissões e 5 avisos da fonte preservada em round-trip JSON; ajuda CLI funciona.
- Decisões: group-writable inconclusivo sem membros; substituição considera travessia/sticky bit; ExecStart ambíguo gera aviso; sem varredura global ou alteração do host.
- Limitações/pendências: ACLs, capabilities, mounts, namespaces, ancestrais e symlinks não verificados; correlações ainda não implementadas.
- Próximo bloco: B4.

### 2026-09-22 — B4 concluído

- Entregue: analyze_snapshot puro, C1/C2/C3 com evidência, interpretação, hipótese, lacunas e disposition; documentação da API.
- Validação: 109 testes passam em Python 3.13.12, incluindo positivos, negativos, inconclusivos, round-trip de findings, determinismo e preservação do snapshot.
- Decisões: C1 exige privilégio observado e recurso modificável para needs_review; C2/C3 são contexto; avisos pertinentes preservados; nomes não determinam risco.
- Limitações/pendências: análise limitada às evidências do snapshot e aos bits POSIX; CLI, relatórios e fluxo de arquivos offline pertencem a B5, ainda não iniciado.
- Próximo bloco: B5.

### 2026-09-22 — B5 concluído

- Entregue: scan/analyze, texto com quatro camadas, relatório JSON v1, save-snapshot e resumo de coleta parcial.
- Validação: 116 testes passam; fluxo real scan -> snapshot temporário -> analyze produziu JSON idêntico (185 processos, 21 serviços, 1 socket e 111 permissões); needs_review mantém exit 0.
- Decisões: arquivo novo com modo 0600 sem sobrescrita; relatório separado do snapshot; códigos 0/1/2 e stdout/stderr documentados.
- Limitações/pendências: coleta parcial segue as limitações já registradas; cenários integrados e material de demonstração reservados a B6, ainda não iniciado.
- Próximo bloco: B6.

### 2026-09-22 — B6 concluído

- Entregue: fixtures normal/unsafe_service/listener/partial, testes end-to-end, README final, DEMO.md com matriz da rubrica e TECHNICAL_REPORT.md como base de até quatro páginas.
- Validação: 124 testes passam em Python 3.13.12; quatro cenários em texto/JSON com resultados exatos, normal sem C1, inseguro com needs_review e parcial inconclusivo; offline testado sem coleta/comandos/sockets.
- Decisões: demonstração sintética reproduzível após setup, sem criar incidente no host; coleta live como complemento; nenhum item de B7 adicionado.
- Limitações/pendências: grupo deve revisar autoria, diagramar e conferir quatro páginas do documento técnico e realizar apresentação; limitações de coleta/análise documentadas no README.
- Próximo bloco: B7 — robustez da associação processo ↔ serviço por ancestralidade PPID (aprovado, não iniciado).

### 2026-09-22 — B7 concluído

- Entregue: resolução pura de associação C2 direta/descendente, proveniência e cadeia PPID em evidência; cenário listener com filho e README/ARCHITECTURE/DEMO/TECHNICAL_REPORT atualizados.
- Validação: 139 testes passam em Python 3.13.12; direto, filho, neto, não relacionado, dados ausentes, self-parent e ciclo cobertos; CLI end-to-end texto/JSON e offline sem coleta; import/--help e scan local → snapshot temporário → analyze com JSON idêntico; git diff --check sem erros.
- Decisões: todas as units alcançadas preservadas; descendência exige processos observados até o MainPID; C1, collectors, dependências e schema v1 preservados.
- Limitações/pendências: PPID é contexto, não membership autoritativo; snapshot não atômico, cgroups/socket activation/namespaces fora do escopo; documento técnico final de quatro páginas versionado; apresentação continua com o grupo.
- Próximo bloco: B8 — integração com o dataset generator fornecido pela disciplina (aprovado, não iniciado).

### 2026-10-05 — B8 concluído

- Entregue: importador puro de textos e leitura dos quatro arquivos do generator, CLI analyze-dataset texto/JSON, proveniência de MainPID e limitações por fonte; README/ARCHITECTURE/DEMO/TECHNICAL_REPORT atualizados.
- Validação: 174 testes passam em Python 3.13.12; generator real com seeds 5/1/2 em temporários, casos positivos/negativos/ambíguos, entradas ausentes/malformadas, round-trip v1 e bloqueio de consultas ao host; comando canônico seed 5 executado em training-generated/professor-correlation, texto/JSON e import/--help válidos; git diff --check sem erros.
- Decisões: somente root literal recebe ID 0; MainPID por igualdade textual única com aviso; pais somente do CSV; falhas estruturais retornam 1, lacunas preservam resultado parcial; generator, fixtures, C1/C2/C3, schema e dependências preservados.
- Limitações/pendências: sem sockets/logs ou cronologia; generated_at varia e não representa coleta; permissões ausentes mantêm inconclusivos; documento técnico final atualizado com B8 e validado em quatro páginas; apresentação continua com o grupo.
- Próximo bloco: NONE — nenhuma nova extensão iniciada.
