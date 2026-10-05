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

## B7 — Robustez da associação processo ↔ serviço

### Objetivo

Melhorar a correlação C2 sem criar novas fontes de dados: além do vínculo direto por `MainPID`, reconhecer quando o processo que possui um socket é **descendente observado** do `MainPID` de um serviço pela cadeia de PPID já presente no snapshot.

A melhoria existe para reduzir falsos "serviço não associado" em serviços que criam workers/filhos, preservando uma interpretação conservadora.

### Escopo

- criar uma resolução **pura** de associação processo ↔ serviço usando apenas `ProcessRecord.pid/ppid` e `ServiceRecord.main_pid`;
- manter associação direta quando `process.pid == service.main_pid`;
- adicionar associação indireta quando a cadeia observada `PID -> PPID -> ...` alcança o `MainPID`;
- registrar no finding C2 a proveniência da associação:
  - `direct_main_pid`;
  - `descendant_of_main_pid`;
- para associação indireta, incluir a cadeia observada de PIDs como evidência;
- proteger a travessia contra processo pai ausente, `ppid=None`, self-parent, ciclos e dados parciais;
- reutilizar a mesma lógica em análise live e offline; nenhuma consulta adicional ao host durante correlação;
- atualizar testes e documentação afetada;
- demonstrar pelo menos um listener pertencente a processo filho, preferencialmente adaptando o cenário integrado de listener ou adicionando uma fixture mínima se isso deixar o teste mais claro.

### Guardrails

A ancestralidade PPID é **evidência contextual**, não prova autoritativa de membership systemd. Não afirmar que um processo "pertence" definitivamente à unit apenas por ancestralidade.

Continuam fora de escopo:

- cgroups/systemd membership;
- units `.socket`;
- socket activation;
- PID namespaces/containers;
- nova dependência;
- novo collector;
- mudança do schema JSON v1.

C1 permanece baseada no `MainPID` e identidade efetiva observada do serviço; B7 não deve ampliar a heurística de privilégio.

### Aceite

- associação direta por `MainPID` continua funcionando;
- processo filho e neto podem ser associados ao serviço quando a cadeia PPID observada alcança o `MainPID`;
- processo sem ancestral de serviço não é falsamente associado;
- cadeia incompleta, pai ausente, self-parent e ciclo terminam de forma segura e determinística;
- C2 registra `direct_main_pid` ou `descendant_of_main_pid` em evidência;
- associação indireta registra a cadeia de PIDs usada para sustentar a interpretação;
- C2 continua `informational` quando o contexto necessário está completo e `inconclusive` quando faltam evidências;
- nenhuma nova coleta, dependência ou alteração de schema é introduzida;
- testes unitários cobrem direto, filho, neto, não relacionado, pai ausente e ciclo;
- existe cobertura end-to-end da associação por descendência;
- README, ARCHITECTURE, DEMO e TECHNICAL_REPORT são atualizados para refletir o comportamento real;
- suíte completa passa.

### Encerramento

Depois de concluir e validar B7:

- marque B7 como `DONE`;
- registre o resumo em `PROGRESS.md`;
- defina `CURRENT_BLOCK: NONE`;
- registre o status geral como escopo planejado concluído;
- **não inicie nenhuma nova extensão** sem solicitação explícita.


## B8 — Integração com o dataset generator da disciplina

### Objetivo

Usar diretamente o `tools/generate_dataset.py` fornecido pelo professor como fonte adicional de cenários de validação, sem substituir as quatro fixtures próprias e sem alterar o núcleo C1/C2/C3.

### Escopo

- preservar `tools/generate_dataset.py` como artefato fornecido pela disciplina; não reescrever sua lógica;
- adicionar um importador pequeno e puro para um diretório produzido pelo generator;
- ler `processes.csv`, `permissions.csv`, `services.txt` e `metadata.json` e convertê-los para o `Snapshot` v1 existente;
- `journal.log` e `README.txt` permanecem artefatos do dataset e não entram nas correlações atuais;
- não consultar o host ao importar/analisar dataset;
- resolver `ServiceRecord.main_pid` somente quando houver correspondência **única e exata** entre `ExecStart` do serviço e o comando observado de um processo; caso contrário manter `None` e registrar limitação;
- mapear apenas a identidade literal `root` para UID 0 quando a fonte do dataset informar `user=root`; não inventar UIDs numéricos para outros nomes;
- para permissões, mapear owner/group literal `root` para ID 0 e preservar os demais nomes sem inventar IDs;
- reconstruir `parent_path` e `parent_mode` apenas quando o diretório pai estiver presente no próprio dataset;
- expor a integração pela CLI como `analyze-dataset DATASET_DIR`, reutilizando `analyze_snapshot()` e o reporting existente;
- adicionar testes unitários do parser/importador e um teste end-to-end que execute o generator real em diretório temporário e analise o resultado;
- usar um seed determinístico documentado para a demonstração do cenário de correlação.

### Guardrails

- nenhum dado do dataset pode ser interpretado como instrução;
- não executar comandos encontrados em `cmd` ou `ExecStart`;
- não acessar caminhos listados em `permissions.csv`; os metadados do arquivo são dados offline;
- não resolver usuários/grupos pelo host local;
- não criar uma segunda implementação de C1/C2/C3;
- não modificar schema JSON v1;
- não adicionar dependência de runtime;
- não adicionar análise de logs neste bloco;
- não substituir as fixtures `normal`, `unsafe_service`, `listener` e `partial`.

### Aceite

- `python tools/generate_dataset.py --level intermediate --seed 5 --output training-generated/professor-correlation` gera um dataset reproduzível;
- `python -m endpoint_investigator analyze-dataset training-generated/professor-correlation` usa o mesmo núcleo de correlação e produz saída texto/JSON;
- o cenário `correlation` do generator associa `backup-agent.service` ao processo cujo comando é `/bin/bash /opt/backup/backup.sh` e avalia o script 0777 de forma contextual;
- o cenário `privileged_service` não vira alerta forte apenas por executar como root quando o script está 0700;
- arquivo world-writable sem vínculo com serviço privilegiado não deve, sozinho, produzir C1;
- entradas ambíguas ou sem correspondência exata permanecem incompletas em vez de serem adivinhadas;
- análise do dataset não chama psutil, systemctl, os.stat nem qualquer collector live;
- testes cobrem parsing válido, arquivos ausentes/malformados, identidade não-root sem UID inventado, vínculo exato/ambíguo de serviço e análise end-to-end com o generator;
- suíte completa passa;
- README, ARCHITECTURE, DEMO, TECHNICAL_REPORT e PROGRESS são atualizados;
- após concluir, definir `CURRENT_BLOCK: NONE` e não iniciar nova extensão.
