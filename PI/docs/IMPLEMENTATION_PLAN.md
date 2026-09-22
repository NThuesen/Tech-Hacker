# Plano de implementação por blocos

## Objetivo

Permitir que um agente de código trabalhe em partes pequenas, verificáveis e fáceis de revisar.

**Regra:** trabalhe somente no bloco indicado como `CURRENT_BLOCK` em `docs/PROGRESS.md`. Não comece o bloco seguinte no mesmo trabalho sem pedido explícito.

Antes de implementar um bloco:

1. leia `AGENTS.md`;
2. confira `docs/PROGRESS.md`;
3. leia apenas esta seção do bloco e as partes relevantes de `docs/ARCHITECTURE.md`;
4. inspecione o código existente.

Ao concluir:

1. rode as validações do bloco;
2. atualize documentação afetada;
3. acrescente um resumo curto em `docs/PROGRESS.md`;
4. marque o próximo bloco como `CURRENT_BLOCK`, mas não o implemente sem nova solicitação.

## B0 — Scaffold, modelos e contrato de snapshot

### Objetivo

Criar a base mínima do projeto sem implementar lógica de detecção.

### Escopo

- layout `src/` e `tests/`;
- configuração de pacote Python;
- dependências mínimas;
- dataclasses/modelos descritos na arquitetura;
- serialização/deserialização JSON;
- `python -m endpoint_investigator --help`;
- infraestrutura mínima de testes.

### Não fazer

- collectors reais;
- correlações;
- UI;
- LLM.

### Aceite

- import do pacote funciona;
- `--help` funciona;
- round-trip Snapshot -> JSON -> Snapshot preserva dados;
- testes do bloco passam;
- comandos canônicos de setup/teste são registrados em `AGENTS.md` e README.

## B1 — Processos e rede

### Objetivo

Coletar processo/identidade e listeners do endpoint.

### Escopo

- collector psutil de processos;
- tratamento de `NoSuchProcess`, `AccessDenied` e corrida;
- collector de sockets de escuta;
- ligação socket -> PID quando fornecida pelo SO;
- testes com mocks/fixtures.

### Aceite

- snapshot contém processos normalizados;
- listeners aparecem sem port scan;
- falha em um processo não derruba a coleta;
- nenhum nome de processo é interpretado como malicioso;
- testes positivos e de falha parcial passam.

## B2 — Serviços systemd

### Objetivo

Coletar serviços em execução e associá-los a processos.

### Escopo

- wrapper central de comandos read-only;
- listagem de services em execução;
- parsing de propriedades via `systemctl show`;
- MainPID -> ProcessRecord;
- indisponibilidade de systemd vira aviso estruturado.

### Aceite

- services possuem os campos mínimos da arquitetura;
- parser tem fixtures próprias;
- serviço sem MainPID é representado sem crash;
- ambiente sem systemd produz snapshot parcial válido.

## B3 — Permissões contextuais

### Objetivo

Analisar somente recursos usados por processos/serviços já observados.

### Escopo

- seleção deduplicada de caminhos relevantes;
- `os.stat` para arquivo e pai imediato;
- resolução owner/group;
- classificação de escrita por owner/group/others;
- indicação conservadora de modificação por identidade não-root;
- limitações explícitas para ACL/capabilities/mount/namespaces.

### Aceite

- não existe varredura global do filesystem;
- arquivos ausentes/inacessíveis não causam crash;
- testes cobrem root-only, owner não-root, group-writable e world-writable;
- resultado preserva fatos observados separados da interpretação.

## B4 — Correlações e findings

### Objetivo

Implementar o núcleo que vale a maior parte da rubrica.

### Escopo

Implementar C1, C2 e C3 conforme `ARCHITECTURE.md`.

Todo finding deve usar:

- evidência;
- interpretação;
- hipótese;
- evidência ausente;
- disposition.

### Aceite

- C1 não dispara apenas porque o serviço roda como root;
- C1 dispara no cenário privilegiado + recurso modificável;
- C2 descreve listener sem chamá-lo automaticamente de vulnerabilidade;
- C3 adiciona contexto de PPID/identidade apenas a processos relevantes;
- há casos positivos, negativos e inconclusivos;
- nenhum finding depende apenas de nome de processo/arquivo.

## B5 — CLI, relatórios e modo offline

### Objetivo

Transformar o núcleo em produto demonstrável.

### Escopo

- `scan`;
- `analyze SNAPSHOT`;
- texto humano;
- JSON estável;
- `--save-snapshot`;
- resumo de coleta parcial;
- códigos de saída coerentes.

### Aceite

- live scan executa sem modificar o host;
- um snapshot salvo pode ser reanalisado;
- formato textual mostra claramente as quatro camadas do finding;
- JSON é adequado para auditoria/testes;
- finding não altera exit code para erro de execução.

## B6 — Cenários integrados, qualidade e demo

### Objetivo

Fechar a rubrica com evidência reproduzível e documentação.

### Escopo

- fixtures integradas: normal, unsafe_service, listener, partial;
- testes end-to-end das fixtures;
- README final;
- roteiro de demonstração;
- seção de limitações;
- conferir cobertura da rubrica;
- preparar material-base para o documento técnico de até 4 páginas.

### Aceite

- todos os testes passam;
- demo não depende de internet nem incidente real;
- cenário normal prova ausência de falso positivo óbvio;
- cenário unsafe prova C1;
- cenário partial prova resultado inconclusivo;
- README cobre todos os itens pedidos no enunciado;
- cada critério da rubrica está demonstrável.

## B7 — Extensões somente se houver ganho claro

Este bloco começa vazio e é opcional.

Exemplos aceitáveis após B0-B6:

- journal do systemd para enriquecer C1/C2;
- hash local para registrar integridade observada;
- export Markdown.

Não adicionar uma extensão apenas para aumentar o número de features. Qualquer proposta deve explicar qual critério da rubrica melhora e qual complexidade adiciona.
