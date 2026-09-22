# Arquitetura — Endpoint Investigator

## 1. Objetivo de engenharia

Construir a solução mais simples que cubra integralmente a rubrica da PI.

O Endpoint Investigator será uma ferramenta **local, read-only e executada sob demanda** em GNU/Linux. Ela coleta um snapshot do endpoint, normaliza os dados, correlaciona entidades e gera findings explicáveis.

A arquitetura evita componentes que não aumentam diretamente a nota: sem banco de dados, sem API web, sem daemon, sem dashboard e sem LLM no núcleo.

## 2. Decisões principais

### Stack

- Python 3.11+; ambiente-alvo principal: Kali Linux da disciplina.
- Dependência de produção prevista: **psutil**, para processos e sockets.
- Biblioteca padrão para permissões, usuários/grupos, JSON, CLI e execução de comandos.
- **systemctl/systemd** como fonte primária de serviços quando disponível.
- pytest como dependência de desenvolvimento.

A dependência em psutil é intencional: reduz parsing manual de `/proc` e mantém o código pequeno. Serviços continuam separados porque systemd possui semântica própria que psutil não modela.

### Sem IA no MVP

A PI permite IA, mas não a exige. O núcleo não usará LLM.

Motivos:

1. a rubrica premia evidência estruturada e correlação;
2. as regras principais podem ser determinísticas e explicáveis;
3. remover LLM elimina chave/API, latência, custo, indisponibilidade e variabilidade;
4. uma camada de IA pode ser adicionada depois apenas como explicação opcional, sem alterar a análise.

### Read-only por padrão

A ferramenta observa o endpoint e não modifica serviços, arquivos, permissões, usuários ou processos.

Nenhum collector deve precisar de `sudo` para o fluxo normal. Falta de permissão vira **evidência ausente / limitação de coleta**, e não erro fatal.

## 3. Fluxo

```text
           +----------------------+
           | live Linux endpoint  |
           +----------+-----------+
                      |
                      v
               +-------------+
               | collectors  |
               +-------------+
          process | service | network
                      |
                      v
               +-------------+
               | normalize   |
               +-------------+
                      |
          recursos relevantes
                      |
                      v
               +-------------+
               | permissions |
               +-------------+
                      |
                      v
               +-------------+
               | correlation |
               +-------------+
                      |
                      v
               +-------------+
               | findings    |
               +-------------+
                      |
               +------+------+
               |             |
               v             v
             text           JSON
```

Também deve existir um caminho offline:

```text
snapshot JSON -> correlation -> findings -> text/JSON
```

Isso permite testes determinísticos e uma demonstração reproduzível usando datasets/fixtures, além da execução real na Kali.

## 4. Estrutura alvo do código

```text
PI/
├── src/
│   └── endpoint_investigator/
│       ├── __init__.py
│       ├── __main__.py
│       ├── cli.py
│       ├── models.py
│       ├── system.py
│       ├── scan.py
│       ├── collectors/
│       │   ├── processes.py
│       │   ├── services.py
│       │   ├── network.py
│       │   └── permissions.py
│       ├── correlations.py
│       └── reporting.py
├── tests/
│   ├── fixtures/
│   └── ...
├── docs/
└── README.md
```

Não crie mais camadas sem uma necessidade concreta. Um módulo pode ser dividido apenas quando ficar grande ou misturar responsabilidades.

## 5. Modelo de dados mínimo

Use dataclasses ou estruturas equivalentes simples e serializáveis.

### ProcessRecord

Campos mínimos:

- `pid`
- `ppid`
- `name`
- `username`
- `uid`
- `gid`
- `status`
- `cmdline`
- `exe`

Campos inacessíveis devem aceitar `null` e registrar a limitação correspondente; o collector não deve abortar o scan por `AccessDenied` ou processo que desapareceu durante a coleta.

### ServiceRecord

Campos mínimos:

- `unit`
- `active_state`
- `sub_state`
- `main_pid`
- `configured_user`
- `configured_group`
- `fragment_path`
- `exec_start`

O collector deve usar propriedades estruturadas de `systemctl show`, não parsing da tabela visual de `systemctl status`.

### NetworkRecord

Somente sockets de escuta são necessários para o escopo inicial:

- `pid`
- `protocol`
- `local_address`
- `local_port`
- `status`

### PermissionRecord

Analisar apenas recursos selecionados pelas relações encontradas:

- executável do processo;
- executável/script referenciado pelo serviço quando resolvido;
- arquivo da unit systemd;
- diretório pai imediato desses recursos quando relevante para substituição do arquivo.

Campos mínimos:

- `path`
- `exists`
- `file_type`
- `owner_uid` / `owner_name`
- `group_gid` / `group_name`
- `mode`
- `owner_writable`
- `group_writable`
- `other_writable`
- `parent_path`
- `parent_mode`

A normalização deve conseguir indicar se um recurso aparenta ser modificável por uma identidade não-root usando permissões POSIX observáveis. ACLs, capabilities, mount flags e namespaces podem limitar a conclusão e devem aparecer como evidência ausente quando relevantes.

### Snapshot

Agrupa:

- metadata de coleta;
- processos;
- serviços;
- sockets;
- permissões;
- avisos/erros parciais de collectors.

O snapshot deve ser serializável em JSON para testes e análise offline.

### Finding

Todo finding usa a mesma forma:

- `id`
- `title`
- `correlation`
- `entities`
- `evidence[]`
- `interpretation`
- `hypothesis`
- `missing_evidence[]`
- `disposition`: `informational`, `needs_review` ou `inconclusive`

Evite uma escala numérica artificial de risco. O objetivo é investigação, não scoring.

## 6. Coletores

### Processos

Fonte: psutil.

Coletar todos os processos visíveis e tolerar corrida de processo encerrado durante o snapshot.

A árvore PID/PPID deve poder ser consultada pela etapa de correlação, mas não é necessário construir uma visualização completa da árvore.

### Serviços

Fonte principal: systemd.

Fluxo sugerido:

1. listar units do tipo service em execução;
2. para cada unit relevante, obter propriedades com `systemctl show`;
3. relacionar `MainPID` com `ProcessRecord`.

Se systemd não estiver disponível, o resultado deve registrar a fonte como indisponível e continuar. Isso é importante para containers/WSL e também torna a limitação explícita.

### Rede

Fonte: psutil.

Coletar apenas listeners TCP/UDP com PID quando disponível. Não fazer port scan. A ferramenta observa o próprio host.

### Permissões

Fonte: `os.stat`, `pwd`, `grp`.

O collector recebe uma lista de caminhos relevantes; não percorre o filesystem indiscriminadamente.

A análise deve considerar tanto a permissão do arquivo quanto a do diretório pai imediato quando a substituição do arquivo for tecnicamente possível.

## 7. Correlações obrigatórias do produto

Implementaremos três correlações. Apenas a primeira tenta identificar uma relação de privilégio insegura; as outras mostram contexto investigativo sem transformar sinais isolados em vulnerabilidade.

### C1 — Serviço privilegiado + recurso modificável

```text
serviço ativo
-> processo/identidade privilegiada
-> recurso executado ou unit relacionada
-> permissão indica modificação por identidade não-root
-> finding needs_review
```

Fontes: serviço + processo + permissões.

Evidência típica:

- unit e MainPID;
- UID do processo;
- caminho do executável/script/unit;
- owner/group/mode;
- diretório pai quando relevante.

Interpretação: um recurso usado para iniciar ou executar um serviço privilegiado aparenta poder ser alterado fora da identidade privilegiada.

Hipótese: pode existir uma relação de privilégio insegura e possibilidade de execução com privilégios elevados após alteração/reinício.

Evidência ausente: não há prova de alteração ou exploração; logs, integridade histórica e ACLs podem ser necessários para confirmar contexto adicional.

**Guardrail:** serviço root sozinho nunca gera esse finding.

### C2 — Processo + serviço + socket de escuta

```text
socket LISTEN
-> PID
-> processo
-> serviço associado
-> identidade
-> contexto de exposição
```

Fontes: rede + processo + serviço.

Gera um finding `informational` ou `inconclusive`, não uma vulnerabilidade.

Objetivo: responder quem está escutando, sob qual identidade, por qual serviço e em qual endereço/porta.

Interpretação: o processo está aceitando conexões naquele endpoint.

Hipótese: se a exposição for inesperada, o serviço merece investigação.

Evidência ausente: intenção da configuração, firewall, origem permitida, autenticação e necessidade de negócio.

Isso demonstra explicitamente que **root + porta aberta não significa vulnerabilidade**.

### C3 — Processo + PPID + usuário

```text
processo relevante
-> PPID
-> processo pai
-> identidades de ambos
-> contexto de origem
```

Fontes: processos relacionados entre si e identidade.

A correlação deve ser usada principalmente para processos já relacionados a serviço/listener/finding, evitando gerar milhares de entradas.

Gera contexto `informational` e, quando o pai não puder ser observado, `inconclusive`.

Objetivo: mostrar que PID/nome isolado é insuficiente e preservar genealogia útil para investigação.

## 8. Seleção de recursos para permissões

Para manter a solução simples e contextual:

1. obtenha processos e serviços;
2. relacione serviço -> MainPID -> processo;
3. monte um conjunto deduplicado de caminhos relevantes;
4. analise permissões apenas nesses caminhos.

Prioridade:

1. `ProcessRecord.exe`;
2. executável/script de `ServiceRecord.exec_start` quando extraível com segurança;
3. `ServiceRecord.fragment_path`;
4. diretório pai imediato desses caminhos.

Não adicionar busca global por SUID, arquivos world-writable ou cron no escopo mínimo.

## 9. CLI alvo

Interface mínima prevista:

```bash
python -m endpoint_investigator scan
python -m endpoint_investigator scan --format json
python -m endpoint_investigator scan --save-snapshot snapshot.json
python -m endpoint_investigator analyze tests/fixtures/scenario_unsafe_service.json
python -m endpoint_investigator analyze tests/fixtures/scenario_unsafe_service.json --format json
```

O comando `scan` coleta e analisa o host atual.

O comando `analyze` executa as mesmas correlações sobre snapshot salvo. Ele existe para reproduzir cenários e facilitar a demonstração/testes; não deve criar uma segunda implementação da análise.

## 10. Tratamento de falhas

Um endpoint real muda enquanto é observado. Portanto:

- processo desapareceu: registrar e continuar;
- acesso negado: campo `null` + aviso estruturado;
- systemd indisponível: serviço collector indisponível + análise parcial;
- caminho removido entre coleta e stat: registrar `exists=false`;
- saída inesperada de comando: erro do collector, nunca inventar valor.

O relatório deve indicar quando a investigação ficou parcial.

## 11. Testes necessários

### Unitários

- parsing de `systemctl show`;
- normalização de processos;
- classificação de permissões POSIX;
- serialização de snapshot/finding.

### Correlações

Para cada C1/C2/C3:

- caso positivo/contextual esperado;
- caso legítimo que não deve virar alerta;
- caso com evidência insuficiente.

### Cenários integrados

Manter fixtures determinísticas:

1. `scenario_normal.json`: serviço legítimo, permissões seguras;
2. `scenario_unsafe_service.json`: serviço privilegiado + recurso modificável por não-root;
3. `scenario_listener.json`: listener associado a serviço, sem afirmar vulnerabilidade;
4. `scenario_partial.json`: dados incompletos -> conclusão inconclusiva.

O teste mais importante para qualidade é provar que sinais isolados não geram conclusão forte.

## 12. Demonstração prevista

A demonstração deve ser curta e reproduzível:

1. rodar `scan` na Kali e mostrar o snapshot real;
2. mostrar um serviço/processo/sua identidade;
3. mostrar listener associado quando existir;
4. analisar fixture insegura e explicar C1;
5. apontar no output os quatro elementos: evidência, interpretação, hipótese e evidência ausente;
6. analisar fixture normal/partial e mostrar que a ferramenta não força uma conclusão.

Isso demonstra domínio técnico sem depender de criar um incidente real.

## 13. Cobertura da rubrica

| Critério | Como a arquitetura cobre |
| --- | --- |
| Funcionamento — 3,0 | CLI live + análise offline, tolerância a coleta parcial, JSON/texto, testes determinísticos |
| Processos/permissões/serviços — 2,0 | collectors dedicados e modelo explícito para cada dimensão |
| Correlação — 2,0 | C1, C2 e C3; C1 cruza as três dimensões obrigatórias |
| Evidência/interpretação/hipótese — 1,5 | schema único de Finding + missing_evidence + inconclusivos |
| Arquitetura/código/docs — 1,0 | módulos pequenos, uma dependência de runtime, documentação e testes |
| Demonstração/domínio — 0,5 | roteiro live + fixtures normal, insegura e parcial |

## 14. Fora do escopo mínimo

Não implementar antes de todos os blocos obrigatórios estarem concluídos:

- LLM;
- Streamlit/web UI;
- FastAPI;
- banco de dados;
- agente residente/monitoramento contínuo;
- scanner remoto/Nmap;
- consulta de CVEs;
- reputação/hash em serviços externos;
- captura de pacotes;
- varredura global do filesystem;
- detecção genérica de malware;
- auto-remediação.

Esses itens adicionam complexidade sem necessidade para atingir a rubrica.

## 15. Critério para extensões

Uma extensão só entra se:

1. um requisito obrigatório já estiver estável;
2. ela melhorar diretamente uma correlação, explicabilidade ou demonstração;
3. vier acompanhada de teste;
4. não duplicar capacidade existente.

A prioridade é uma ferramenta pequena, defensável e bem demonstrada.
